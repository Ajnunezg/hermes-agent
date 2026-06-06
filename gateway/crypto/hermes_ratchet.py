"""Double Ratchet message crypto for the Hermes gateway (forward secrecy + PCS).

A faithful Double Ratchet (Signal, Perrin & Marlinspike) over P-256 / HKDF-SHA256
/ AES-256-GCM, providing per-message **forward secrecy** and **post-compromise
security** for the relay chat lane. It is the Python side of the Swift
``HermesRatchetCrypto`` reference; both share this exact state machine and the
length-prefixed AAD byte format:

    b"OpenBurnBar-HermesRatchet-v1-AAD"
    || u64be(len(associated_data)) || associated_data
    || u64be(len(header.algorithm)) || header.algorithm
    || u64be(len(header.sessionID)) || header.sessionID
    || u64be(len(header.senderDeviceID)) || header.senderDeviceID
    || u64be(len(header.receiverDeviceID)) || header.receiverDeviceID
    || u64be(len(header.ratchetPublicKeyBase64)) || header.ratchetPublicKeyBase64
    || u64be(header.version)
    || u64be(header.previousChainLength)
    || u64be(header.messageNumber)
    || u64be(header.epoch)

Mapping to the Signal Double Ratchet spec (§3): ``KDF_RK`` = HKDF-SHA256 keyed by
the root key over the DH output; ``KDF_CK`` = two HMAC-SHA256 calls under distinct
domain-separated labels; the DH ratchet derives a receiving chain then a fresh
sending chain. Skipped message keys are bounded both per chain and in total to
fail closed against a relay that forces large gaps.

**Session bootstrap (provenance of the initial shared secret).** This module takes
the initial 32-byte ``shared_secret`` as input; it does NOT establish it. The
integration MUST exchange the initial ratchet public keys and seed or derive the
``shared_secret`` over an *authenticated* channel — v4 signed init
(:mod:`gateway.crypto.relay_e2ee_v4`) or v5 signed PQ init
(:mod:`gateway.crypto.relay_e2ee_v5`) — so the first ratchet public keys inherit
the pairing safety-code pin. A ``shared_secret`` learned from a relay-controlled
payload would let the relay seed the session and defeat the ratchet; callers must
never fall back to plaintext.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256

ALGORITHM = "OpenBurnBar-HermesRatchet-v1-P256-HKDFSHA256-AESGCM"
VERSION = 1
RATCHET_INIT_VERSION_V2 = 2
RATCHET_INIT_ALGORITHM_V2 = "OpenBurnBar-HermesRatchet-v2-XWing-P256-HKDFSHA256-AESGCM"
# Per-chain skip distance: how far ahead of the expected message number a single
# header may jump before the sender is rejected.
DEFAULT_MAX_SKIP = 64
# Total bound on the retained skipped-message-key store across all chains. Kept
# separate from DEFAULT_MAX_SKIP (Signal separates per-chain MAX_SKIP from the
# total store) so a long-lived session with occasional out-of-order delivery is
# not rejected, while an untrusted relay still cannot force unbounded allocation.
DEFAULT_MAX_SKIPPED_KEYS = 2000

_ROOT_INFO = b"OpenBurnBar-HermesRatchet-v1-root"
_CHAIN_LABEL = b"OpenBurnBar-HermesRatchet-v1-chain"
_MESSAGE_LABEL = b"OpenBurnBar-HermesRatchet-v1-message"
_AAD_DOMAIN = b"OpenBurnBar-HermesRatchet-v1-AAD"
_SYMMETRIC_KEY_BYTES = 32
_P256_PRIVATE_BYTES = 32
_P256_PUBLIC_X963_BYTES = 65
_AES_GCM_NONCE_BYTES = 12


class HermesRatchetError(Exception):
    """Base class for Hermes ratchet failures."""


class InvalidBase64Error(HermesRatchetError):
    """A base64 field is malformed."""


class InvalidKeyLengthError(HermesRatchetError):
    """A symmetric/private/public key has the wrong byte length."""


class InvalidPublicKeyError(HermesRatchetError):
    """A public key is not a valid X9.63 P-256 point."""


class InvalidPrivateKeyError(HermesRatchetError):
    """A private key is not a valid raw P-256 scalar."""


class MissingRemoteRatchetKeyError(HermesRatchetError):
    """The session has no remote ratchet key where one is required."""


class MissingSendingChainError(HermesRatchetError):
    """The session has no sending chain yet."""


class MissingReceivingChainError(HermesRatchetError):
    """The session has no receiving chain yet."""


class TooManySkippedKeysError(HermesRatchetError):
    """The sender skipped farther than the configured per-chain bound."""


class SkippedKeyLimitExceededError(HermesRatchetError):
    """The bounded skipped-message key store is full."""


class InvalidEnvelopeError(HermesRatchetError):
    """The envelope/header shape is invalid for this session."""


class AuthenticationFailedError(HermesRatchetError):
    """AES-GCM authentication failed."""


class HermesRatchetRole(str, Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


@dataclass(frozen=True)
class HermesRatchetKeyPair:
    private_key_base64: str
    public_key_base64: str

    def to_wire(self) -> dict[str, str]:
        return {
            "privateKeyBase64": self.private_key_base64,
            "publicKeyBase64": self.public_key_base64,
        }

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> "HermesRatchetKeyPair":
        return cls(
            private_key_base64=str(value["privateKeyBase64"]),
            public_key_base64=str(value["publicKeyBase64"]),
        )


@dataclass(frozen=True)
class HermesRatchetHeader:
    session_id: str
    sender_device_id: str
    receiver_device_id: str
    ratchet_public_key_base64: str
    previous_chain_length: int
    message_number: int
    epoch: int
    version: int = VERSION
    algorithm: str = ALGORITHM

    def to_wire(self) -> dict[str, object]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "sessionID": self.session_id,
            "senderDeviceID": self.sender_device_id,
            "receiverDeviceID": self.receiver_device_id,
            "ratchetPublicKeyBase64": self.ratchet_public_key_base64,
            "previousChainLength": self.previous_chain_length,
            "messageNumber": self.message_number,
            "epoch": self.epoch,
        }

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> "HermesRatchetHeader":
        return cls(
            version=int(value["version"]),
            algorithm=str(value["algorithm"]),
            session_id=str(value["sessionID"]),
            sender_device_id=str(value["senderDeviceID"]),
            receiver_device_id=str(value["receiverDeviceID"]),
            ratchet_public_key_base64=str(value["ratchetPublicKeyBase64"]),
            previous_chain_length=int(value["previousChainLength"]),
            message_number=int(value["messageNumber"]),
            epoch=int(value["epoch"]),
        )


@dataclass(frozen=True)
class HermesRatchetEnvelope:
    header: HermesRatchetHeader
    ciphertext_base64: str

    def to_wire(self) -> dict[str, object]:
        return {
            "header": self.header.to_wire(),
            "ciphertextBase64": self.ciphertext_base64,
        }

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> "HermesRatchetEnvelope":
        header = value.get("header")
        if not isinstance(header, dict):
            raise InvalidEnvelopeError("envelope header is missing")
        return cls(
            header=HermesRatchetHeader.from_wire(header),
            ciphertext_base64=str(value["ciphertextBase64"]),
        )


@dataclass
class HermesRatchetSessionState:
    role: HermesRatchetRole
    session_id: str
    local_device_id: str
    remote_device_id: str
    root_key_base64: str
    sending_ratchet_private_key_base64: str
    sending_chain_key_base64: str | None = None
    receiving_chain_key_base64: str | None = None
    remote_ratchet_public_key_base64: str | None = None
    send_message_number: int = 0
    receive_message_number: int = 0
    previous_sending_chain_length: int = 0
    epoch: int = 0
    max_skip: int = DEFAULT_MAX_SKIP
    max_skipped_keys: int = DEFAULT_MAX_SKIPPED_KEYS
    skipped_message_keys: dict[str, str] = field(default_factory=dict)

    def to_wire(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "sessionID": self.session_id,
            "localDeviceID": self.local_device_id,
            "remoteDeviceID": self.remote_device_id,
            "rootKeyBase64": self.root_key_base64,
            "sendingChainKeyBase64": self.sending_chain_key_base64,
            "receivingChainKeyBase64": self.receiving_chain_key_base64,
            "sendingRatchetPrivateKeyBase64": self.sending_ratchet_private_key_base64,
            "remoteRatchetPublicKeyBase64": self.remote_ratchet_public_key_base64,
            "sendMessageNumber": self.send_message_number,
            "receiveMessageNumber": self.receive_message_number,
            "previousSendingChainLength": self.previous_sending_chain_length,
            "epoch": self.epoch,
            "maxSkip": self.max_skip,
            "maxSkippedKeys": self.max_skipped_keys,
            "skippedMessageKeys": dict(self.skipped_message_keys),
        }

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> "HermesRatchetSessionState":
        skipped = value.get("skippedMessageKeys") or {}
        if not isinstance(skipped, dict):
            raise InvalidEnvelopeError("skippedMessageKeys must be an object")
        return cls(
            role=HermesRatchetRole(str(value["role"])),
            session_id=str(value["sessionID"]),
            local_device_id=str(value["localDeviceID"]),
            remote_device_id=str(value["remoteDeviceID"]),
            root_key_base64=str(value["rootKeyBase64"]),
            sending_chain_key_base64=_optional_str(value.get("sendingChainKeyBase64")),
            receiving_chain_key_base64=_optional_str(value.get("receivingChainKeyBase64")),
            sending_ratchet_private_key_base64=str(value["sendingRatchetPrivateKeyBase64"]),
            remote_ratchet_public_key_base64=_optional_str(value.get("remoteRatchetPublicKeyBase64")),
            send_message_number=int(value.get("sendMessageNumber", 0)),
            receive_message_number=int(value.get("receiveMessageNumber", 0)),
            previous_sending_chain_length=int(value.get("previousSendingChainLength", 0)),
            epoch=int(value.get("epoch", 0)),
            max_skip=int(value.get("maxSkip", DEFAULT_MAX_SKIP)),
            max_skipped_keys=int(value.get("maxSkippedKeys", DEFAULT_MAX_SKIPPED_KEYS)),
            skipped_message_keys={str(key): str(raw) for key, raw in skipped.items()},
        )


def generate_key_pair() -> HermesRatchetKeyPair:
    """Generate a P-256 ratchet keypair using Swift-compatible raw encodings."""
    private_key = _generate_private_key()
    return HermesRatchetKeyPair(
        private_key_base64=_b64(_private_key_raw(private_key)),
        public_key_base64=_b64(_public_key_x963(private_key.public_key())),
    )


def key_pair_from_private_base64(private_key_base64: str) -> HermesRatchetKeyPair:
    """Reconstruct a canonical ratchet keypair from a raw P-256 private scalar."""
    private_key = _private_key_from_base64(private_key_base64)
    return HermesRatchetKeyPair(
        private_key_base64=private_key_base64,
        public_key_base64=_b64(_public_key_x963(private_key.public_key())),
    )


def validate_key_pair(key_pair: HermesRatchetKeyPair) -> None:
    """Validate that a wire keypair is canonical and internally consistent."""
    derived = key_pair_from_private_base64(key_pair.private_key_base64)
    if not hmac.compare_digest(derived.public_key_base64, key_pair.public_key_base64):
        raise InvalidPublicKeyError("ratchet public key does not match private key")
    _public_key_from_base64(key_pair.public_key_base64)


def validate_public_key_base64(public_key_base64: str) -> None:
    """Validate a canonical X9.63 P-256 public key encoded as base64."""
    _public_key_from_base64(public_key_base64)


def random_root_key() -> bytes:
    """Generate the 32-byte initial root key material."""
    return _random_bytes(_SYMMETRIC_KEY_BYTES)


def initiator_state(
    *,
    session_id: str,
    local_device_id: str,
    remote_device_id: str,
    shared_secret: bytes,
    remote_initial_ratchet_public_key_base64: str,
    local_initial_ratchet_key_pair: HermesRatchetKeyPair | None = None,
    max_skip: int = DEFAULT_MAX_SKIP,
    max_skipped_keys: int = DEFAULT_MAX_SKIPPED_KEYS,
) -> HermesRatchetSessionState:
    """Create the first sender state, mirroring Signal ``RatchetInitAlice``."""
    _validate_symmetric_key(shared_secret, "sharedSecret")
    local_pair = local_initial_ratchet_key_pair or generate_key_pair()
    local_private_key = _private_key_from_base64(local_pair.private_key_base64)
    remote_public_key = _public_key_from_base64(remote_initial_ratchet_public_key_base64)
    root_key, chain_key = _root_kdf(
        shared_secret, _shared_secret_bytes(local_private_key, remote_public_key)
    )
    return HermesRatchetSessionState(
        role=HermesRatchetRole.INITIATOR,
        session_id=session_id,
        local_device_id=local_device_id,
        remote_device_id=remote_device_id,
        root_key_base64=_b64(root_key),
        sending_chain_key_base64=_b64(chain_key),
        sending_ratchet_private_key_base64=local_pair.private_key_base64,
        remote_ratchet_public_key_base64=remote_initial_ratchet_public_key_base64,
        max_skip=max_skip,
        max_skipped_keys=max_skipped_keys,
    )


def responder_state(
    *,
    session_id: str,
    local_device_id: str,
    remote_device_id: str,
    shared_secret: bytes,
    local_initial_ratchet_key_pair: HermesRatchetKeyPair,
    max_skip: int = DEFAULT_MAX_SKIP,
    max_skipped_keys: int = DEFAULT_MAX_SKIPPED_KEYS,
) -> HermesRatchetSessionState:
    """Create the first receiver state, mirroring Signal ``RatchetInitBob``."""
    _validate_symmetric_key(shared_secret, "sharedSecret")
    _private_key_from_base64(local_initial_ratchet_key_pair.private_key_base64)
    return HermesRatchetSessionState(
        role=HermesRatchetRole.RESPONDER,
        session_id=session_id,
        local_device_id=local_device_id,
        remote_device_id=remote_device_id,
        root_key_base64=_b64(shared_secret),
        sending_ratchet_private_key_base64=local_initial_ratchet_key_pair.private_key_base64,
        max_skip=max_skip,
        max_skipped_keys=max_skipped_keys,
    )


_SESSION_ID_DOMAIN = b"OpenBurnBar-HermesRatchet-v1-session"
_DEVICE_ID_DOMAIN = b"OpenBurnBar-HermesRatchet-v1-device"
_BOOTSTRAP_INFO = b"OpenBurnBar-HermesRatchet-v1-root-bootstrap"
_RATCHET_INIT_V2_TRANSCRIPT_DOMAIN = b"OpenBurnBar-HermesRatchet-v2-init-transcript"
_RATCHET_INIT_V2_ROOT_INFO = b"OpenBurnBar-HermesRatchet-v2-root-pq"
_RATCHET_INIT_V2_CONFIRM_LABEL = b"OpenBurnBar-HermesRatchet-v2-root-confirm"


def derive_session_id(
    *, uid: str, client_id: str, agent_ratchet_public_key_base64: str, peer_ratchet_public_key_base64: str
) -> str:
    """A deterministic, role-free session id from the routing ids + both pinned
    ratchet identity keys (sorted), so both sides derive the IDENTICAL id."""
    low, high = sorted(
        (_b64decode(agent_ratchet_public_key_base64, "agentRatchet"),
         _b64decode(peer_ratchet_public_key_base64, "peerRatchet"))
    )
    return sha256(
        _SESSION_ID_DOMAIN + b"|" + uid.encode("utf-8") + b"|" + client_id.encode("utf-8") + b"|" + low + high
    ).hexdigest()


def derive_device_id(ratchet_public_key_base64: str) -> str:
    return sha256(_DEVICE_ID_DOMAIN + b"|" + _b64decode(ratchet_public_key_base64, "ratchetPub")).hexdigest()[:32]


def ratchet_init_v2_transcript(
    *,
    uid: str,
    client_id: str,
    destination_id: str,
    session_id: str,
    initiator_ratchet_public_key_base64: str,
    responder_ratchet_public_key_base64: str,
    initiator_device_id: str,
    responder_device_id: str,
    responder_kem_public_key_base64: str,
    responder_kem_key_id: str,
    kem_ciphertext_base64: str,
    replay_counter: int,
) -> bytes:
    """Canonical transcript for ratchet_init v2 root derivation and confirmation."""
    parts = [
        b"ratchet_init",
        str(RATCHET_INIT_VERSION_V2).encode("ascii"),
        RATCHET_INIT_ALGORITHM_V2.encode("utf-8"),
        str(uid).encode("utf-8"),
        str(client_id).encode("utf-8"),
        str(destination_id).encode("utf-8"),
        str(session_id).encode("ascii"),
        str(initiator_ratchet_public_key_base64).encode("ascii"),
        str(responder_ratchet_public_key_base64).encode("ascii"),
        str(initiator_device_id).encode("ascii"),
        str(responder_device_id).encode("ascii"),
        str(responder_kem_public_key_base64).encode("ascii"),
        str(responder_kem_key_id).encode("ascii"),
        str(kem_ciphertext_base64).encode("ascii"),
        int(replay_counter).to_bytes(8, "big"),
    ]
    out = bytearray(_RATCHET_INIT_V2_TRANSCRIPT_DOMAIN)
    for part in parts:
        _append_part(out, part)
    return bytes(out)


def derive_ratchet_init_v2_root(kem_shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive the 32-byte initial ratchet root from the PQ KEM secret.

    The transcript hash binds routing ids, both P-256 ratchet keys, both device
    ids, the responder KEM key id/public key, the KEM ciphertext, and the signed
    replay counter. A relay cannot move a KEM ciphertext across sessions or keys.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _validate_symmetric_key(kem_shared_secret, "kemSharedSecret")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_SYMMETRIC_KEY_BYTES,
        salt=b"\x00" * 32,
        info=_RATCHET_INIT_V2_ROOT_INFO + b"|" + hashlib.sha256(transcript).digest(),
    ).derive(kem_shared_secret)


def ratchet_init_v2_root_confirm_mac(root_key: bytes, transcript: bytes) -> bytes:
    _validate_symmetric_key(root_key, "rootKey")
    return hmac.new(root_key, _RATCHET_INIT_V2_CONFIRM_LABEL + transcript, sha256).digest()


def verify_ratchet_init_v2_root_confirm_mac(
    *,
    root_key: bytes,
    transcript: bytes,
    mac: bytes,
) -> None:
    if not hmac.compare_digest(ratchet_init_v2_root_confirm_mac(root_key, transcript), mac):
        raise AuthenticationFailedError("ratchet_init v2 root confirmation failed")


def bootstrap_session(
    *,
    role: HermesRatchetRole,
    uid: str,
    client_id: str,
    local_ratchet_key_pair: HermesRatchetKeyPair,
    peer_ratchet_public_key_base64: str,
    max_skip: int = DEFAULT_MAX_SKIP,
    max_skipped_keys: int = DEFAULT_MAX_SKIPPED_KEYS,
) -> HermesRatchetSessionState:
    """Deterministically establish a session from the PINNED ratchet identity keys
    — no stateful handshake round-trip.

    The initial root key is ``HKDF(ECDH(local_ratchet, peer_ratchet))`` (symmetric,
    so both sides derive it identically) and the session/device ids are
    deterministic functions of the pinned keys + routing ids. ``role`` is the
    caller's fixed role: the agent is the **responder** (it replies to the user)
    and the user's device is the **initiator** (it sends first). The Double Ratchet
    then provides forward secrecy (from the first message) and post-compromise
    security (after the first DH-ratchet round-trip). The bootstrap DH is static-
    static, so the ROOT key has no forward secrecy on its own; the ratchet heals
    this on the first round-trip. The RESPONDER has no sending chain until it
    receives the initiator's first message — callers (e.g. an agent that wants to
    send first) fall back to the v4 signed wrap until then. The pinned ratchet
    identity keys are authenticated at pairing (bound into the all-key safety
    code), so a relay cannot seed the session.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    local_pub = local_ratchet_key_pair.public_key_base64
    peer_pub = peer_ratchet_public_key_base64
    if _b64decode(local_pub, "localRatchet") == _b64decode(peer_pub, "peerRatchet"):
        raise InvalidPublicKeyError("ratchet identity keys must differ between peers")
    session_id = derive_session_id(
        uid=uid, client_id=client_id,
        agent_ratchet_public_key_base64=local_pub, peer_ratchet_public_key_base64=peer_pub,
    )
    local_device = derive_device_id(local_pub)
    peer_device = derive_device_id(peer_pub)
    local_private = _private_key_from_base64(local_ratchet_key_pair.private_key_base64)
    peer_public = _public_key_from_base64(peer_pub)
    dh = _shared_secret_bytes(local_private, peer_public)
    shared_secret = HKDF(
        algorithm=hashes.SHA256(), length=_SYMMETRIC_KEY_BYTES, salt=b"\x00" * 32,
        info=_BOOTSTRAP_INFO + b"|" + session_id.encode("ascii"),
    ).derive(dh)

    if role == HermesRatchetRole.INITIATOR:
        # Initiator: ratchet against the RESPONDER's ratchet identity key (the peer).
        return initiator_state(
            session_id=session_id, local_device_id=local_device, remote_device_id=peer_device,
            shared_secret=shared_secret, remote_initial_ratchet_public_key_base64=peer_pub,
            max_skip=max_skip, max_skipped_keys=max_skipped_keys,
        )
    # Responder: use OUR ratchet identity keypair as the initial ratchet key.
    return responder_state(
        session_id=session_id, local_device_id=local_device, remote_device_id=peer_device,
        shared_secret=shared_secret, local_initial_ratchet_key_pair=local_ratchet_key_pair,
        max_skip=max_skip, max_skipped_keys=max_skipped_keys,
    )


def encrypt(
    plaintext: bytes,
    state: HermesRatchetSessionState,
    *,
    associated_data: bytes = b"",
) -> HermesRatchetEnvelope:
    """Encrypt and advance ``state`` in place."""
    if state.sending_chain_key_base64 is None:
        raise MissingSendingChainError("sending chain is missing")
    sending_chain_key = _symmetric_key_from_base64(
        state.sending_chain_key_base64, "sendingChainKey"
    )
    next_chain_key, message_key = _chain_kdf(sending_chain_key)
    private_key = _private_key_from_base64(state.sending_ratchet_private_key_base64)
    header = HermesRatchetHeader(
        session_id=state.session_id,
        sender_device_id=state.local_device_id,
        receiver_device_id=state.remote_device_id,
        ratchet_public_key_base64=_b64(_public_key_x963(private_key.public_key())),
        previous_chain_length=state.previous_sending_chain_length,
        message_number=state.send_message_number,
        epoch=state.epoch,
    )
    ciphertext = _aes_gcm_seal(
        plaintext,
        message_key,
        envelope_aad(header, associated_data),
    )
    state.sending_chain_key_base64 = _b64(next_chain_key)
    state.send_message_number += 1
    return HermesRatchetEnvelope(header=header, ciphertext_base64=_b64(ciphertext))


def decrypt(
    envelope: HermesRatchetEnvelope,
    state: HermesRatchetSessionState,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt and advance ``state``, TRANSACTIONALLY.

    All ratchet mutations (the skipped-key pop, ``_skip_message_keys``,
    ``_dh_ratchet``, the receiving-chain advance) run against a working COPY and
    are committed to the caller's ``state`` ONLY after the AEAD authenticates. So
    a forged or tampered frame from the untrusted relay leaves ``state`` byte-for-
    byte unchanged: it cannot irreversibly advance the ratchet (permanent session
    DoS), pop a skipped key, or fill the skipped-key store before authentication.
    Mirror this trial-decrypt-then-commit shape in the Swift/Kotlin clients.
    """
    working = copy.deepcopy(state)
    plaintext = _decrypt_into(envelope, working, associated_data)
    _commit_session_state(state, working)
    return plaintext


def _decrypt_into(
    envelope: HermesRatchetEnvelope,
    state: HermesRatchetSessionState,
    associated_data: bytes,
) -> bytes:
    """Decrypt against ``state`` (a working copy), mutating it; raise before any
    commit on failure. The caller (:func:`decrypt`) commits only on success."""
    _validate_header(envelope.header, state)
    skipped_key = _skipped_key_id(
        envelope.header.ratchet_public_key_base64,
        envelope.header.message_number,
    )
    skipped_key_base64 = state.skipped_message_keys.pop(skipped_key, None)
    if skipped_key_base64 is not None:
        message_key = _symmetric_key_from_base64(skipped_key_base64, "skippedMessageKey")
        return _open(envelope, message_key, associated_data)

    if state.remote_ratchet_public_key_base64 != envelope.header.ratchet_public_key_base64:
        if state.remote_ratchet_public_key_base64 is not None:
            _skip_message_keys(
                until=envelope.header.previous_chain_length,
                remote_ratchet_public_key_base64=state.remote_ratchet_public_key_base64,
                state=state,
            )
        _dh_ratchet(envelope.header.ratchet_public_key_base64, state)

    _skip_message_keys(
        until=envelope.header.message_number,
        remote_ratchet_public_key_base64=envelope.header.ratchet_public_key_base64,
        state=state,
    )
    if state.receiving_chain_key_base64 is None:
        raise MissingReceivingChainError("receiving chain is missing")
    receiving_chain_key = _symmetric_key_from_base64(
        state.receiving_chain_key_base64, "receivingChainKey"
    )
    next_chain_key, message_key = _chain_kdf(receiving_chain_key)
    plaintext = _open(envelope, message_key, associated_data)
    state.receiving_chain_key_base64 = _b64(next_chain_key)
    state.receive_message_number += 1
    return plaintext


def _commit_session_state(
    target: HermesRatchetSessionState, source: HermesRatchetSessionState
) -> None:
    """Copy the mutable ratchet fields from a successful working copy back into the
    caller's state (the transaction commit)."""
    target.root_key_base64 = source.root_key_base64
    target.sending_ratchet_private_key_base64 = source.sending_ratchet_private_key_base64
    target.sending_chain_key_base64 = source.sending_chain_key_base64
    target.receiving_chain_key_base64 = source.receiving_chain_key_base64
    target.remote_ratchet_public_key_base64 = source.remote_ratchet_public_key_base64
    target.send_message_number = source.send_message_number
    target.receive_message_number = source.receive_message_number
    target.previous_sending_chain_length = source.previous_sending_chain_length
    target.epoch = source.epoch
    target.skipped_message_keys = dict(source.skipped_message_keys)


def envelope_aad(header: HermesRatchetHeader, associated_data: bytes = b"") -> bytes:
    """Build the Swift-compatible AEAD associated data for one header."""
    data = bytearray(_AAD_DOMAIN)
    _append_part(data, associated_data)
    _append_part(data, header.algorithm.encode("utf-8"))
    _append_part(data, header.session_id.encode("utf-8"))
    _append_part(data, header.sender_device_id.encode("utf-8"))
    _append_part(data, header.receiver_device_id.encode("utf-8"))
    _append_part(data, header.ratchet_public_key_base64.encode("utf-8"))
    _append_u64(data, header.version)
    _append_u64(data, header.previous_chain_length)
    _append_u64(data, header.message_number)
    _append_u64(data, header.epoch)
    return bytes(data)


def _dh_ratchet(
    remote_ratchet_public_key_base64: str,
    state: HermesRatchetSessionState,
) -> None:
    current_private_key = _private_key_from_base64(
        state.sending_ratchet_private_key_base64
    )
    remote_public_key = _public_key_from_base64(remote_ratchet_public_key_base64)
    root_key = _symmetric_key_from_base64(state.root_key_base64, "rootKey")
    receive_root_key, receiving_chain_key = _root_kdf(
        root_key, _shared_secret_bytes(current_private_key, remote_public_key)
    )
    next_private_key = _generate_private_key()
    send_root_key, sending_chain_key = _root_kdf(
        receive_root_key, _shared_secret_bytes(next_private_key, remote_public_key)
    )
    state.previous_sending_chain_length = state.send_message_number
    state.send_message_number = 0
    state.receive_message_number = 0
    state.epoch += 1
    state.remote_ratchet_public_key_base64 = remote_ratchet_public_key_base64
    state.root_key_base64 = _b64(send_root_key)
    state.receiving_chain_key_base64 = _b64(receiving_chain_key)
    state.sending_chain_key_base64 = _b64(sending_chain_key)
    state.sending_ratchet_private_key_base64 = _b64(_private_key_raw(next_private_key))


def _skip_message_keys(
    *,
    until: int,
    remote_ratchet_public_key_base64: str,
    state: HermesRatchetSessionState,
) -> None:
    if until < state.receive_message_number:
        return
    if until - state.receive_message_number > state.max_skip:
        raise TooManySkippedKeysError("skipped message bound exceeded")
    if state.receiving_chain_key_base64 is None:
        if until == state.receive_message_number:
            return
        raise MissingReceivingChainError("receiving chain is missing")
    receiving_chain_key = _symmetric_key_from_base64(
        state.receiving_chain_key_base64, "receivingChainKey"
    )
    while state.receive_message_number < until:
        next_chain_key, message_key = _chain_kdf(receiving_chain_key)
        key = _skipped_key_id(
            remote_ratchet_public_key_base64,
            state.receive_message_number,
        )
        if len(state.skipped_message_keys) >= state.max_skipped_keys:
            raise SkippedKeyLimitExceededError("skipped-message key store is full")
        state.skipped_message_keys[key] = _b64(message_key)
        receiving_chain_key = next_chain_key
        state.receive_message_number += 1
    state.receiving_chain_key_base64 = _b64(receiving_chain_key)


def _open(
    envelope: HermesRatchetEnvelope,
    message_key: bytes,
    associated_data: bytes,
) -> bytes:
    try:
        combined = _b64decode(envelope.ciphertext_base64, "ciphertext")
        return _aes_gcm_open(
            combined,
            message_key,
            envelope_aad(envelope.header, associated_data),
        )
    except HermesRatchetError:
        raise
    except Exception as exc:
        raise AuthenticationFailedError("ratchet envelope authentication failed") from exc


def _validate_header(
    header: HermesRatchetHeader,
    state: HermesRatchetSessionState,
) -> None:
    if (
        header.version != VERSION
        or header.algorithm != ALGORITHM
        or header.session_id != state.session_id
        or header.receiver_device_id != state.local_device_id
        or header.sender_device_id != state.remote_device_id
        or header.message_number < 0
        or header.previous_chain_length < 0
        or header.epoch < 0
    ):
        raise InvalidEnvelopeError("ratchet header does not match this session")
    _public_key_from_base64(header.ratchet_public_key_base64)


def _root_kdf(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=_ROOT_INFO,
    ).derive(dh_output)
    return derived[:32], derived[32:]


def _chain_kdf(chain_key: bytes) -> tuple[bytes, bytes]:
    next_chain_key = hmac.new(chain_key, _CHAIN_LABEL, sha256).digest()
    message_key = hmac.new(chain_key, _MESSAGE_LABEL, sha256).digest()
    return next_chain_key, message_key


def _aes_gcm_seal(plaintext: bytes, key: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _validate_symmetric_key(key, "messageKey")
    nonce = _random_bytes(_AES_GCM_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _aes_gcm_open(combined: bytes, key: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _validate_symmetric_key(key, "messageKey")
    if len(combined) <= _AES_GCM_NONCE_BYTES:
        raise InvalidEnvelopeError("ciphertext is too short")
    try:
        return AESGCM(key).decrypt(
            combined[:_AES_GCM_NONCE_BYTES],
            combined[_AES_GCM_NONCE_BYTES:],
            aad,
        )
    except Exception as exc:
        raise AuthenticationFailedError("ratchet envelope authentication failed") from exc


def _private_key_from_base64(raw_base64: str):
    raw = _b64decode(raw_base64, "privateKey")
    if len(raw) != _P256_PRIVATE_BYTES:
        raise InvalidKeyLengthError("privateKey must be 32 bytes")
    return _private_key_from_raw(raw)


def _private_key_from_raw(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
    except ValueError as exc:
        raise InvalidPrivateKeyError("privateKey is not a valid P-256 scalar") from exc


def _public_key_from_base64(raw_base64: str):
    raw = _b64decode(raw_base64, "publicKey")
    if len(raw) != _P256_PUBLIC_X963_BYTES:
        raise InvalidKeyLengthError("publicKey must be 65 bytes")
    return _public_key_from_x963(raw)


def _public_key_from_x963(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise InvalidPublicKeyError("publicKey is not a valid P-256 point") from exc


def _generate_private_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def _private_key_raw(private_key) -> bytes:
    return private_key.private_numbers().private_value.to_bytes(_P256_PRIVATE_BYTES, "big")


def _public_key_x963(public_key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _shared_secret_bytes(private_key, public_key) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec

    return private_key.exchange(ec.ECDH(), public_key)


def _symmetric_key_from_base64(raw_base64: str, label: str) -> bytes:
    data = _b64decode(raw_base64, label)
    _validate_symmetric_key(data, label)
    return data


def _validate_symmetric_key(data: bytes, label: str) -> None:
    if len(data) != _SYMMETRIC_KEY_BYTES:
        raise InvalidKeyLengthError(f"{label} must be 32 bytes")


def _skipped_key_id(ratchet_public_key_base64: str, message_number: int) -> str:
    return f"{ratchet_public_key_base64}:{message_number}"


def _append_part(data: bytearray, part: bytes) -> None:
    _append_u64(data, len(part))
    data.extend(part)


def _append_u64(data: bytearray, value: int) -> None:
    if value < 0:
        raise InvalidEnvelopeError("negative UInt64 field")
    data.extend(int(value).to_bytes(8, "big"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvalidBase64Error(f"{label} is not valid base64") from exc


def _random_bytes(count: int) -> bytes:
    return os.urandom(count)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "ALGORITHM",
    "VERSION",
    "RATCHET_INIT_VERSION_V2",
    "RATCHET_INIT_ALGORITHM_V2",
    "DEFAULT_MAX_SKIP",
    "DEFAULT_MAX_SKIPPED_KEYS",
    "HermesRatchetError",
    "InvalidBase64Error",
    "InvalidKeyLengthError",
    "InvalidPublicKeyError",
    "InvalidPrivateKeyError",
    "MissingRemoteRatchetKeyError",
    "MissingSendingChainError",
    "MissingReceivingChainError",
    "TooManySkippedKeysError",
    "SkippedKeyLimitExceededError",
    "InvalidEnvelopeError",
    "AuthenticationFailedError",
    "HermesRatchetRole",
    "HermesRatchetKeyPair",
    "HermesRatchetHeader",
    "HermesRatchetEnvelope",
    "HermesRatchetSessionState",
    "generate_key_pair",
    "key_pair_from_private_base64",
    "validate_key_pair",
    "validate_public_key_base64",
    "random_root_key",
    "initiator_state",
    "responder_state",
    "bootstrap_session",
    "derive_session_id",
    "derive_device_id",
    "ratchet_init_v2_transcript",
    "derive_ratchet_init_v2_root",
    "ratchet_init_v2_root_confirm_mac",
    "verify_ratchet_init_v2_root_confirm_mac",
    "encrypt",
    "decrypt",
    "envelope_aad",
]
