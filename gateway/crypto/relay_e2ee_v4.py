"""v4 relay hardening: explicit sender authentication, length padding, all-key
pairing safety code, key-id selectors, and authenticated key rotation.

This module is additive over :mod:`gateway.crypto.relay_e2ee`. It does NOT change
the v1/v2/v3 wire formats; it layers state-of-the-art remediations on top of the
v3 RFC 9180 HPKE content-key wrap, each independently testable and anchored to an
authoritative known-answer vector where one exists:

* **Explicit sender authentication (KCI resistance).** HPKE ``mode_auth`` (v3)
  gives only *implicit* sender authentication: if the recipient static private
  key leaks, a holder of it can forge messages from any sender (RFC 9180 §9.1).
  Per RFC 9180 §9.1.1's own recommendation, v4 adds a detached **Ed25519**
  (RFC 8032) signature by the sender over an *encrypt-then-sign* transcript that
  binds the version, both peers' identity keys, the recipient's encryption key,
  the AADs, and the raw ciphertext bytes. The recipient verifies against the
  **pinned** sender verification key (never a wire-supplied one), and both the
  AEAD open AND the signature verify must pass. A leaked recipient key can no
  longer forge senders; forgery now requires the sender's *separate* signing key.

* **Length padding (size-metadata minimization).** :func:`padme_pad` applies the
  Padmé scheme (Nikitin et al., PoPETs 2019) to the plaintext before sealing,
  hiding the exact length within a deterministic ``<= ~12%`` bound. Integer
  bit-length is used (never floating ``log2``) so the padded length is identical
  across languages.

* **All-key pairing safety code.** :func:`relay_safety_code_v4` commits to the
  full *set* of a peer's pinned public keys (encryption + signing + ratchet),
  length-prefixed and domain-separated, so adding a new key class can never leave
  the human-compared code matching while a relay substitutes the new key.

* **Key-id selectors + authenticated rotation.** :func:`relay_key_id` is a
  128-bit selector over an encryption key (a selector ONLY — never authoritative).
  :func:`build_rotation_signed_body` / :func:`verify_rotation_event` implement a
  "sign-the-successor" rotation event: the new encryption key is signed by the
  current pinned Ed25519 identity key, with a monotonic epoch and validity window.

All primitives are pyca/cryptography + stdlib; no new dependency. Cross-language
parity with the Swift/Kotlin clients is maintained in those repositories.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from gateway.crypto import relay_e2ee

# ---------------------------------------------------------------------------
# Constants / domain separation
# ---------------------------------------------------------------------------

RELAY_KEY_VERSION_V4 = 4
RELAY_ENCRYPTION_V4 = "hpke-auth-p256-ed25519sig-aes256gcm"

_NS = relay_e2ee.HERMES_NAMESPACE  # "OpenBurnBar-HermesRelay"

_SIG_LABEL = f"{_NS}-Sig-v4".encode("ascii")
_CHUNK_SIG_LABEL = f"{_NS}-ChunkSig-v4".encode("ascii")
_ROTATION_LABEL = f"{_NS}-Rotation-v4".encode("ascii")
_KEY_ID_LABEL = f"{_NS}-KeyId-v1|".encode("ascii")
_PAIRING_LABEL = f"{_NS}-Pair-v4".encode("ascii")

_ED25519_PUBLIC_BYTES = 32
_ED25519_PRIVATE_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64
_KEY_ID_BYTES = 16
_X963_PUBLIC_KEY_BYTE_COUNT = relay_e2ee._X963_PUBLIC_KEY_BYTE_COUNT  # 65

# Pairing key purpose tags (stable wire contract for the all-key safety code).
PAIRING_TAG_ENCRYPTION = 0x01  # P-256 X9.63 (65B)
PAIRING_TAG_SIGNING = 0x02     # Ed25519 raw (32B)
PAIRING_TAG_RATCHET = 0x03     # ratchet identity public (P-256 X9.63 65B)


class RelayV4SignatureError(relay_e2ee.RelayCryptoError):
    """An Ed25519 explicit-authentication signature failed to verify."""


class RelayV4RotationError(relay_e2ee.RelayCryptoError):
    """A key-rotation event failed validation (signature, epoch, or window)."""


# ---------------------------------------------------------------------------
# Ed25519 identity keys (raw 32-byte, matching CryptoKit rawRepresentation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelaySigningKey:
    """A sender's long-term Ed25519 signing key (raw 32-byte seed).

    Separate from the P-256 relay encryption key on purpose: one key leak must
    not yield both decryption and signing power (RFC 9180 §9.1.1 key separation).
    """

    raw_representation: bytes

    def __post_init__(self) -> None:
        if len(self.raw_representation) != _ED25519_PRIVATE_BYTES:
            raise relay_e2ee.InvalidPublicKeyError(
                "Ed25519 signing key must be the raw 32-byte seed"
            )

    @classmethod
    def from_base64(cls, raw_base64: str) -> "RelaySigningKey":
        try:
            return cls(base64.b64decode(raw_base64, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise relay_e2ee.InvalidPublicKeyError("Ed25519 signing key is invalid") from exc

    def _private_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(self.raw_representation)

    def public_key_raw(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self._private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key_raw()).decode("ascii")

    def raw_base64(self) -> str:
        return base64.b64encode(self.raw_representation).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        return self._private_key().sign(message)


@dataclass(frozen=True)
class RelayVerifyKey:
    """A peer's long-term Ed25519 verification key (raw 32-byte)."""

    raw_representation: bytes

    def __post_init__(self) -> None:
        if len(self.raw_representation) != _ED25519_PUBLIC_BYTES:
            raise relay_e2ee.InvalidPublicKeyError(
                "Ed25519 verification key must be 32 raw bytes"
            )

    @classmethod
    def from_base64(cls, raw_base64: str) -> "RelayVerifyKey":
        try:
            return cls(base64.b64decode(raw_base64, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise relay_e2ee.InvalidPublicKeyError("Ed25519 verification key is invalid") from exc

    def public_key_raw(self) -> bytes:
        return self.raw_representation

    def public_key_base64(self) -> str:
        return base64.b64encode(self.raw_representation).decode("ascii")

    def _public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        return Ed25519PublicKey.from_public_bytes(self.raw_representation)

    def verify(self, signature: bytes, message: bytes) -> None:
        """Raise :class:`RelayV4SignatureError` if ``signature`` is invalid."""
        from cryptography.exceptions import InvalidSignature

        if len(signature) != _ED25519_SIGNATURE_BYTES:
            raise RelayV4SignatureError("Ed25519 signature must be 64 bytes")
        try:
            self._public_key().verify(signature, message)
        except InvalidSignature as exc:
            raise RelayV4SignatureError("Ed25519 signature did not verify") from exc


def generate_signing_key() -> RelaySigningKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return RelaySigningKey(raw)


def _coerce_verify_key(value: "RelayVerifyKey | str | bytes") -> RelayVerifyKey:
    if isinstance(value, RelayVerifyKey):
        return value
    if isinstance(value, str):
        return RelayVerifyKey.from_base64(value)
    if isinstance(value, (bytes, bytearray)):
        return RelayVerifyKey(bytes(value))
    raise relay_e2ee.InvalidPublicKeyError(
        "verification key must be a RelayVerifyKey, base64 str, or 32 raw bytes"
    )


# ---------------------------------------------------------------------------
# Canonical length-prefixed transcript (no delimiter ambiguity)
# ---------------------------------------------------------------------------


def _lp(value: bytes) -> bytes:
    """Length-prefix a field: 4-byte big-endian length || value.

    Used instead of the v1/v2 ``"|"``-joined AAD so a relay cannot re-segment
    fields (the delimiter-collision hazard flagged in ``relay_e2ee.RelayNamespace.aad``).
    """
    return len(value).to_bytes(4, "big") + value


def relay_signing_transcript(
    *,
    sender_verify_key: bytes,
    recipient_verify_key: bytes,
    recipient_enc_x963: bytes,
    key_aad: bytes,
    raw_enc: bytes,
    raw_wrapped_key: bytes,
    payload_aad: bytes,
    raw_payload_seal: bytes,
    label: bytes = _SIG_LABEL,
    version: int = RELAY_KEY_VERSION_V4,
) -> bytes:
    """The exact bytes an Ed25519 sender signs for a v4 payload envelope.

    Binds (in order, each length-prefixed): the domain label, the version byte,
    both peers' Ed25519 identity keys, the recipient's P-256 encryption key, the
    key-wrap AAD, the HPKE encapsulated key ``enc``, the wrapped content key, the
    payload AAD, and the raw sealed-payload bytes (``nonce || ct || tag``). ``enc``
    and ``wrappedKey`` are SEPARATE length-prefixed fields so their internal
    boundary cannot be shifted. Recipient binding makes a signature valid ONLY for
    the intended recipient (closes the Davis surreptitious-forwarding class).
    """
    return (
        label
        + _lp(bytes([version & 0xFF]))
        + _lp(sender_verify_key)
        + _lp(recipient_verify_key)
        + _lp(recipient_enc_x963)
        + _lp(key_aad)
        + _lp(raw_enc)
        + _lp(raw_wrapped_key)
        + _lp(payload_aad)
        + _lp(raw_payload_seal)
    )


def relay_chunk_signing_transcript(
    *,
    sender_verify_key: bytes,
    recipient_verify_key: bytes,
    chunk_aad: bytes,
    raw_chunk_seal: bytes,
    version: int = RELAY_KEY_VERSION_V4,
) -> bytes:
    """The bytes a sender signs for one streamed chunk (sequence + kind are inside
    ``chunk_aad``). A distinct label from the payload transcript so a payload
    signature can never be replayed as a chunk signature."""
    return (
        _CHUNK_SIG_LABEL
        + _lp(bytes([version & 0xFF]))
        + _lp(sender_verify_key)
        + _lp(recipient_verify_key)
        + _lp(chunk_aad)
        + _lp(raw_chunk_seal)
    )


# ---------------------------------------------------------------------------
# v4 signed seal / open (HPKE v3 wrap + Ed25519 explicit authentication)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelaySignedEnvelopeV4:
    """A v4 signed envelope: the v3 HPKE wrap fields plus the Ed25519 signature."""

    enc: str
    wrapped_key: str
    payload_ciphertext: str
    sender_sig: str
    relay_encryption: str = RELAY_ENCRYPTION_V4
    relay_key_version: int = RELAY_KEY_VERSION_V4


def seal_signed_v4(
    payload_plaintext: bytes,
    *,
    recipient_enc_public: "relay_e2ee.RelayPublicKey | str | bytes",
    recipient_verify_key: "RelayVerifyKey | str | bytes",
    sender_enc_private: "relay_e2ee.RelayPrivateKey | str | bytes",
    sender_signing_key: RelaySigningKey,
    key_aad: bytes,
    payload_aad: bytes,
    content_key: bytes | None = None,
    _ephemeral_private=None,
) -> RelaySignedEnvelopeV4:
    """Seal ``payload_plaintext`` with the v3 HPKE content-key wrap, then sign the
    envelope with the sender's Ed25519 key (encrypt-then-sign).

    The HPKE wrap (``wrap_symmetric_key_v3``) supplies confidentiality + implicit
    auth + ephemeral forward secrecy exactly as v3; the Ed25519 signature supplies
    the explicit, KCI-resistant sender authentication HPKE alone cannot.
    """
    recipient_enc = relay_e2ee._coerce_relay_public_key(recipient_enc_public)
    recipient_vk = _coerce_verify_key(recipient_verify_key)
    if content_key is None:
        content_key = relay_e2ee.generate_symmetric_key()
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        content_key,
        recipient_enc,
        key_aad,
        sender_private=relay_e2ee._coerce_relay_private_key(sender_enc_private),
        _ephemeral_private=_ephemeral_private,
    )
    # Pad the plaintext (Padmé) BEFORE sealing so the relay sees only a
    # length-hidden ciphertext; the padding rides inside the AEAD and is bound by
    # the signature via raw_payload_seal.
    payload_ct = relay_e2ee.seal_to_base64(padme_pad(payload_plaintext), content_key, payload_aad)
    transcript = relay_signing_transcript(
        sender_verify_key=sender_signing_key.public_key_raw(),
        recipient_verify_key=recipient_vk.public_key_raw(),
        recipient_enc_x963=recipient_enc.public_key_x963(),
        key_aad=key_aad,
        raw_enc=base64.b64decode(wrap.enc),
        raw_wrapped_key=base64.b64decode(wrap.wrapped_key),
        payload_aad=payload_aad,
        raw_payload_seal=base64.b64decode(payload_ct),
    )
    signature = sender_signing_key.sign(transcript)
    return RelaySignedEnvelopeV4(
        enc=wrap.enc,
        wrapped_key=wrap.wrapped_key,
        payload_ciphertext=payload_ct,
        sender_sig=base64.b64encode(signature).decode("ascii"),
    )


def open_signed_v4(
    envelope: "RelaySignedEnvelopeV4 | dict",
    *,
    recipient_enc_private: "relay_e2ee.RelayPrivateKey | str | bytes",
    recipient_verify_key: "RelayVerifyKey | str | bytes",
    pinned_sender_enc_public: "relay_e2ee.RelayPublicKey | str | bytes",
    pinned_sender_verify_key: "RelayVerifyKey | str | bytes",
    key_aad: bytes,
    payload_aad: bytes,
) -> bytes:
    """Open a v4 signed envelope -> the payload plaintext, fail-closed.

    Requires BOTH (AND, never OR): (1) the Ed25519 signature verifies against the
    **pinned** sender verification key over the reconstructed transcript, and
    (2) the HPKE v3 unwrap + AES-256-GCM payload open succeed against the pinned
    sender encryption key. The signature is checked FIRST so a forged frame is
    rejected before the AEAD layer and before any caller side effect / replay-cache
    write. ``pinned_*`` keys come from the caller's pin — never a wire field.
    """
    if isinstance(envelope, RelaySignedEnvelopeV4):
        enc = envelope.enc
        wrapped_key = envelope.wrapped_key
        payload_ct = envelope.payload_ciphertext
        sender_sig = envelope.sender_sig
    else:
        enc = str(envelope.get("enc") or "")
        wrapped_key = str(envelope.get("wrappedKey") or "")
        payload_ct = str(envelope.get("payloadCiphertext") or "")
        sender_sig = str(envelope.get("senderSig") or "")
    if not (enc and wrapped_key and payload_ct and sender_sig):
        raise RelayV4SignatureError("v4 envelope missing enc/wrappedKey/payload/senderSig")

    recipient_enc = relay_e2ee._coerce_relay_private_key(recipient_enc_private)
    recipient_vk = _coerce_verify_key(recipient_verify_key)
    sender_enc = relay_e2ee._coerce_relay_public_key(pinned_sender_enc_public)
    sender_vk = _coerce_verify_key(pinned_sender_verify_key)

    try:
        enc_bytes = base64.b64decode(enc, validate=True)
        wrapped_bytes = base64.b64decode(wrapped_key, validate=True)
        payload_bytes = base64.b64decode(payload_ct, validate=True)
        signature = base64.b64decode(sender_sig, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayV4SignatureError("v4 envelope field is not valid base64") from exc

    transcript = relay_signing_transcript(
        sender_verify_key=sender_vk.public_key_raw(),
        recipient_verify_key=recipient_vk.public_key_raw(),
        recipient_enc_x963=recipient_enc.public_key_x963(),
        key_aad=key_aad,
        raw_enc=enc_bytes,
        raw_wrapped_key=wrapped_bytes,
        payload_aad=payload_aad,
        raw_payload_seal=payload_bytes,
    )
    # (1) explicit authentication FIRST — fail closed before touching the AEAD.
    sender_vk.verify(signature, transcript)
    # (2) confidentiality + implicit auth via the HPKE v3 path, bound to the pin.
    content_key = relay_e2ee.unwrap_symmetric_key_v3(
        enc, wrapped_key, recipient_enc, key_aad, pinned_sender_public=sender_enc
    )
    # (3) strip the Padmé padding (fail-closed on a non-zero/over-long pad).
    return padme_unpad(relay_e2ee.open_base64(payload_ct, content_key, payload_aad))


# ---------------------------------------------------------------------------
# Padmé length padding (size-metadata minimization)
# ---------------------------------------------------------------------------


def padme_padded_len(length: int) -> int:
    """Padmé target length (Nikitin et al., PoPETs 2019) using integer bit-length.

    Rounds ``length`` up so the low ``floor(log2(E)) ... `` bits are zero, hiding
    the exact size within a ``<= ~12%`` overhead bound. Integer bit-length (never
    floating ``log2``) keeps the result identical across languages at powers of 2.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if length <= 1:
        return 1
    e = length.bit_length() - 1          # floor(log2(length))
    s = e.bit_length()                   # floor(log2(e)) + 1
    last_bits = e - s
    if last_bits <= 0:
        return length
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


_PADME_TRUE_LEN_HEADER = 4  # 4-byte big-endian true content length, inside the plaintext


def padme_pad(content: bytes) -> bytes:
    """Prepend a 4-byte true-length header and zero-pad to the Padmé length.

    The padded buffer is what gets AEAD-sealed; the exact content length is hidden
    from the relay (which sees only the padded ciphertext size).
    """
    if len(content) >= (1 << 32):
        raise ValueError("content too large to pad")
    body = len(content).to_bytes(_PADME_TRUE_LEN_HEADER, "big") + content
    target = padme_padded_len(len(body))
    return body + b"\x00" * (target - len(body))


def padme_unpad(padded: bytes) -> bytes:
    """Recover the content from a :func:`padme_pad` buffer, fail-closed.

    Verifies every trailing pad byte is zero (rejects a pad-oracle / smuggled-data
    covert channel) and that the declared length fits.
    """
    if len(padded) < _PADME_TRUE_LEN_HEADER:
        raise relay_e2ee.InvalidCiphertextError("padded buffer too short")
    true_len = int.from_bytes(padded[:_PADME_TRUE_LEN_HEADER], "big")
    end = _PADME_TRUE_LEN_HEADER + true_len
    if end > len(padded):
        raise relay_e2ee.InvalidCiphertextError("padded buffer declares more content than present")
    # Canonical-length check: the buffer must be EXACTLY the Padmé length for its
    # declared content, so the encoding is bijective and a sender cannot overstate
    # ``true_len`` to absorb trailing zero pad bytes as content.
    if len(padded) != padme_padded_len(end):
        raise relay_e2ee.InvalidCiphertextError("non-canonical padded length")
    if any(b != 0 for b in padded[end:]):
        raise relay_e2ee.InvalidCiphertextError("non-zero padding byte (fail-closed)")
    return padded[_PADME_TRUE_LEN_HEADER:end]


# ---------------------------------------------------------------------------
# All-key pairing safety code
# ---------------------------------------------------------------------------


def _canonical_key_set(entries: list[tuple[int, bytes]]) -> bytes:
    """Serialize one party's pinned key set: ``u8(count) || for each: u8(tag) ||
    u16be(len) || key``, entries sorted by ``(tag, key)``. Length-prefixed so no
    field boundary is ambiguous."""
    if len(entries) > 0xFF:
        raise relay_e2ee.InvalidPublicKeyError("too many key-set entries (max 255)")
    ordered = sorted(entries, key=lambda e: (e[0], e[1]))
    out = bytearray([len(ordered)])
    for tag, key in ordered:
        if len(key) > 0xFFFF:
            raise relay_e2ee.InvalidPublicKeyError("key-set entry too long")
        out.append(tag & 0xFF)
        out += len(key).to_bytes(2, "big")
        out += key
    return bytes(out)


def relay_safety_code_v4(
    *,
    self_keys: list[tuple[int, bytes]],
    peer_keys: list[tuple[int, bytes]],
    groups: int = 8,
) -> str:
    """A role-free, 128-bit pairing safety code binding the FULL key set of both
    peers (encryption + signing + ratchet) with a domain-separated label.

    Each ``*_keys`` entry is ``(purpose_tag, raw_key_bytes)`` (see ``PAIRING_TAG_*``).
    Both sides compute the identical code regardless of who is "self"/"peer" (the
    two canonical key-set blobs are sorted). Adding a new key class changes the
    code, so a relay cannot substitute a new key while the human code still matches.
    """
    self_blob = _canonical_key_set(self_keys)
    peer_blob = _canonical_key_set(peer_keys)
    low, high = sorted([self_blob, peer_blob])
    digest = hashlib.sha256(_PAIRING_LABEL + b"|" + low + high).digest()[:groups * 2]
    return " ".join(
        digest[i : i + 2].hex().upper() for i in range(0, len(digest), 2)
    )


# ---------------------------------------------------------------------------
# Key-id selectors (selector ONLY — never authoritative)
# ---------------------------------------------------------------------------


def relay_key_id(enc_x963: bytes) -> str:
    """128-bit hex selector for a P-256 encryption key. Used to pick WHICH pinned
    key to verify against during rotation overlap; the key bytes themselves still
    come from the pinned set and the frame must still authenticate under them."""
    if len(enc_x963) != _X963_PUBLIC_KEY_BYTE_COUNT or enc_x963[0] != 0x04:
        raise relay_e2ee.InvalidPublicKeyError("key id requires a 65-byte X9.63 P-256 point")
    return hashlib.sha256(_KEY_ID_LABEL + enc_x963).hexdigest()[: _KEY_ID_BYTES * 2]


# ---------------------------------------------------------------------------
# Authenticated key rotation ("sign-the-successor")
# ---------------------------------------------------------------------------


def build_rotation_signed_body(
    *,
    uid: str,
    client_id: str,
    from_epoch: int,
    to_epoch: int,
    old_enc_x963: bytes,
    new_enc_x963: bytes,
    not_before_ms: int,
    not_after_ms: int,
    rotation_nonce: bytes,
) -> bytes:
    """The canonical length-prefixed bytes signed by the CURRENT identity key to
    authorize replacing the encryption key with ``new_enc_x963``.

    ``to_epoch`` MUST equal ``from_epoch + 1`` (callers enforce monotonicity); the
    successor key id is bound so a recipient swaps the pin atomically. The domain
    label + nonce prevent the signed body being reinterpreted cross-context."""
    if to_epoch != from_epoch + 1:
        raise RelayV4RotationError("rotation epoch must advance by exactly 1")
    if len(rotation_nonce) != 32:
        raise RelayV4RotationError("rotation nonce must be 32 bytes")
    return (
        _ROTATION_LABEL
        + _lp(uid.encode("utf-8"))
        + _lp(client_id.encode("utf-8"))
        + from_epoch.to_bytes(8, "big")
        + to_epoch.to_bytes(8, "big")
        + _lp(relay_key_id(old_enc_x963).encode("ascii"))
        + _lp(relay_key_id(new_enc_x963).encode("ascii"))
        + _lp(new_enc_x963)
        + not_before_ms.to_bytes(8, "big")
        + not_after_ms.to_bytes(8, "big")
        + _lp(rotation_nonce)
    )


def verify_rotation_event(
    signed_body: bytes,
    signature: bytes,
    *,
    pinned_identity_verify_key: "RelayVerifyKey | str | bytes",
    expected_uid: str,
    expected_client_id: str,
    current_epoch: int,
    now_ms: int,
) -> bytes:
    """Verify a rotation event and return the successor encryption key (X9.63).

    Fail-closed on: a bad signature against the **pinned** identity key, a wrong
    channel (uid/clientId), a non-``current_epoch+1`` transition (replay/skip), or
    a validity window that does not contain ``now_ms``. The caller still swaps the
    pin atomically and carries the replay high-water forward.
    """
    vk = _coerce_verify_key(pinned_identity_verify_key)
    vk.verify(signature, signed_body)  # raises RelayV4SignatureError on mismatch

    if not signed_body.startswith(_ROTATION_LABEL):
        raise RelayV4RotationError("rotation body has the wrong domain label")
    pos = len(_ROTATION_LABEL)

    def take_lp() -> bytes:
        nonlocal pos
        n = int.from_bytes(signed_body[pos : pos + 4], "big")
        pos += 4
        value = signed_body[pos : pos + n]
        pos += n
        return value

    def take_u64() -> int:
        nonlocal pos
        value = int.from_bytes(signed_body[pos : pos + 8], "big")
        pos += 8
        return value

    uid = take_lp().decode("utf-8")
    client_id = take_lp().decode("utf-8")
    from_epoch = take_u64()
    to_epoch = take_u64()
    _old_id = take_lp()
    new_id = take_lp().decode("ascii")
    new_enc = take_lp()
    not_before = take_u64()
    not_after = take_u64()
    _nonce = take_lp()

    if uid != expected_uid or client_id != expected_client_id:
        raise RelayV4RotationError("rotation event is for a different channel")
    if from_epoch != current_epoch or to_epoch != current_epoch + 1:
        raise RelayV4RotationError("rotation epoch is not the next monotonic step")
    if not (not_before <= now_ms <= not_after):
        raise RelayV4RotationError("rotation event is outside its validity window")
    if relay_key_id(new_enc) != new_id:
        raise RelayV4RotationError("successor key id does not match the carried key")
    return new_enc
