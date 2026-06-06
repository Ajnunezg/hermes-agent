"""Relay E2EE v5: hybrid ML-KEM-768/X25519 HPKE + Ed25519 signatures.

v5 is additive to the v1-v4 relay formats. It keeps the v4 encrypt-then-sign
shape, but replaces the P-256 HPKE content-key recipient with the Python
``cryptography`` hybrid HPKE KEM ``MLKEM768_X25519``. The explicit Ed25519
signature remains the sender-authentication primitive; the hybrid KEM is used
only for recipient confidentiality.

The module also exposes a small X-Wing-compatible KEM primitive for ratchet-init
root derivation because pyca's HPKE API intentionally does not expose the raw KEM
shared secret. Production content-key wrapping uses pyca HPKE rather than a
hand-rolled HPKE schedule.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass

from gateway.crypto import relay_e2ee
from gateway.crypto import relay_e2ee_v4


RELAY_KEY_VERSION_V5 = 5
RELAY_ENCRYPTION_V5 = "hpke-base-mlkem768-x25519-hkdfsha256-aes256gcm-ed25519sig"

RELAY_KEM_PRIVATE_KEY_ENV = "BURNBAR_RELAY_KEM_PRIVATE_KEY"

KEM_PUBLIC_KEY_BYTES = 1184 + 32
KEM_PRIVATE_SEED_BYTES = 32
KEM_CIPHERTEXT_BYTES = 1088 + 32
MLKEM768_PUBLIC_KEY_BYTES = 1184
MLKEM768_CIPHERTEXT_BYTES = 1088
X25519_PUBLIC_KEY_BYTES = 32

_NS = "OpenBurnBar-HermesRelay"
_SIG_LABEL_V5 = f"{_NS}-Sig-v5".encode("ascii")
_HPKE_INFO_PREFIX_V5 = b"OpenBurnBar-HermesRelay-HPKE-v5|"
_XWING_LABEL = b"\\.//^\\"
_KEY_ID_LABEL = b"OpenBurnBar-HermesRelay-v5-KemKeyId"
_KEY_ID_BYTES = 16
_SYMMETRIC_KEY_BYTES = 32
_HPKE_ENCAPSULATED_KEY_BYTES = KEM_CIPHERTEXT_BYTES


class RelayV5Error(relay_e2ee.RelayCryptoError):
    """Base class for v5 relay crypto failures."""


class RelayV5UnsupportedError(RelayV5Error):
    """The installed cryptography backend does not expose the required PQ APIs."""


class RelayV5SignatureError(relay_e2ee_v4.RelayV4SignatureError):
    """The v5 Ed25519 signature/transcript is invalid."""


@dataclass(frozen=True)
class RelayKemPublicKey:
    """Hybrid ML-KEM-768/X25519 public key.

    Wire form is exactly ``MLKEM768 public(1184) || X25519 public(32)``.
    """

    raw_representation: bytes

    def __post_init__(self) -> None:
        if len(self.raw_representation) != KEM_PUBLIC_KEY_BYTES:
            raise relay_e2ee.InvalidPublicKeyError(
                "relay KEM public key must be 1216 bytes"
            )
        # Validate both component keys now so a substituted malformed KEM key
        # cannot survive until a later HPKE operation.
        _mlkem_public_from_raw(self.mlkem_public_key_bytes())
        _x25519_public_from_raw(self.x25519_public_key_bytes())

    @classmethod
    def from_raw(cls, raw: bytes) -> "RelayKemPublicKey":
        return cls(bytes(raw))

    @classmethod
    def from_base64(cls, value: str) -> "RelayKemPublicKey":
        try:
            return cls(base64.b64decode(value, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise relay_e2ee.InvalidPublicKeyError("relay KEM public key is invalid") from exc

    def mlkem_public_key_bytes(self) -> bytes:
        return self.raw_representation[:MLKEM768_PUBLIC_KEY_BYTES]

    def x25519_public_key_bytes(self) -> bytes:
        return self.raw_representation[MLKEM768_PUBLIC_KEY_BYTES:]

    def public_key_base64(self) -> str:
        return base64.b64encode(self.raw_representation).decode("ascii")

    def key_id(self) -> str:
        return kem_key_id(self.raw_representation)

    def _hpke_public_key(self):
        from cryptography.hazmat.primitives import hpke

        return hpke.MLKEM768X25519PublicKey(
            _mlkem_public_from_raw(self.mlkem_public_key_bytes()),
            _x25519_public_from_raw(self.x25519_public_key_bytes()),
        )


@dataclass(frozen=True)
class RelayKemPrivateKey:
    """Hybrid KEM private key stored as the X-Wing 32-byte seed.

    The seed expands with SHAKE256 into the 64-byte ML-KEM seed and 32-byte
    X25519 private scalar. Only the 32-byte seed is persisted so the wire/storage
    contract matches the X-Wing draft key shape and avoids exporting expanded
    ML-KEM private material.
    """

    seed: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != KEM_PRIVATE_SEED_BYTES:
            raise relay_e2ee.InvalidPublicKeyError(
                "relay KEM private key seed must be 32 bytes"
            )
        # Force component derivation during construction so invalid backend support
        # is surfaced as a typed failure at load/pairing time.
        self.public_key()

    @classmethod
    def generate(cls) -> "RelayKemPrivateKey":
        return cls(os.urandom(KEM_PRIVATE_SEED_BYTES))

    @classmethod
    def from_raw(cls, raw: bytes) -> "RelayKemPrivateKey":
        return cls(bytes(raw))

    @classmethod
    def from_base64(cls, value: str) -> "RelayKemPrivateKey":
        try:
            return cls(base64.b64decode(value, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise relay_e2ee.InvalidPublicKeyError("relay KEM private key is invalid") from exc

    def raw_base64(self) -> str:
        return base64.b64encode(self.seed).decode("ascii")

    def to_wire(self) -> dict[str, str]:
        return {
            "privateSeedBase64": self.raw_base64(),
            "publicKeyBase64": self.public_key_base64(),
            "keyID": self.key_id(),
        }

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> "RelayKemPrivateKey":
        key = cls.from_base64(str(value["privateSeedBase64"]))
        advertised = str(value.get("publicKeyBase64") or "")
        if advertised and not hmac.compare_digest(advertised, key.public_key_base64()):
            raise relay_e2ee.InvalidPublicKeyError("relay KEM public key does not match private seed")
        return key

    def _expanded(self) -> bytes:
        return hashlib.shake_256(self.seed).digest(96)

    def _mlkem_private_key(self):
        from cryptography.hazmat.primitives.asymmetric import mlkem

        expanded = self._expanded()
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])

    def _x25519_private_key(self):
        from cryptography.hazmat.primitives.asymmetric import x25519

        expanded = self._expanded()
        return x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])

    def _hpke_private_key(self):
        from cryptography.hazmat.primitives import hpke

        return hpke.MLKEM768X25519PrivateKey(
            self._mlkem_private_key(),
            self._x25519_private_key(),
        )

    def public_key(self) -> RelayKemPublicKey:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        mlkem_pub = self._mlkem_private_key().public_key().public_bytes_raw()
        x_pub = self._x25519_private_key().public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        return RelayKemPublicKey(mlkem_pub + x_pub)

    def public_key_base64(self) -> str:
        return self.public_key().public_key_base64()

    def public_key_bytes(self) -> bytes:
        return self.public_key().raw_representation

    def key_id(self) -> str:
        return self.public_key().key_id()


@dataclass(frozen=True)
class AgentKemIdentity:
    private_key: RelayKemPrivateKey

    @property
    def public_key_base64(self) -> str:
        return self.private_key.public_key_base64()

    @classmethod
    def load_or_create(
        cls,
        *,
        env_var: str = RELAY_KEM_PRIVATE_KEY_ENV,
        persist=None,
        environ=None,
    ) -> "AgentKemIdentity":
        source = environ if environ is not None else os.environ
        raw_base64 = source.get(env_var)
        if raw_base64:
            try:
                return cls(RelayKemPrivateKey.from_base64(raw_base64.strip()))
            except relay_e2ee.RelayCryptoError as exc:
                raise relay_e2ee.CorruptIdentityError(
                    f"{env_var} is present but invalid; re-pair required"
                ) from exc
        private_key = RelayKemPrivateKey.generate()
        minted = private_key.raw_base64()
        try:
            source[env_var] = minted
        except Exception:
            pass
        if persist is not None:
            try:
                persist(env_var, minted)
            except Exception:
                import logging

                logging.getLogger(__name__).debug(
                    "KEM identity persist callback failed; key kept in-process only",
                    exc_info=True,
                )
        return cls(private_key)


@dataclass(frozen=True)
class RelayKeyWrapV5:
    enc: str
    wrapped_key: str
    relay_encryption: str = RELAY_ENCRYPTION_V5
    relay_key_version: int = RELAY_KEY_VERSION_V5


@dataclass(frozen=True)
class RelaySignedEnvelopeV5:
    enc: str
    wrapped_key: str
    payload_ciphertext: str
    sender_sig: str
    relay_encryption: str = RELAY_ENCRYPTION_V5
    relay_key_version: int = RELAY_KEY_VERSION_V5


def is_supported() -> bool:
    try:
        _hpke_suite()
        RelayKemPrivateKey.generate()
        return True
    except Exception:
        return False


def generate_kem_private_key() -> RelayKemPrivateKey:
    return RelayKemPrivateKey.generate()


def kem_key_id(public_key: bytes | RelayKemPublicKey | str) -> str:
    public = _coerce_kem_public_key(public_key)
    return hashlib.sha256(_KEY_ID_LABEL + public.raw_representation).hexdigest()[: _KEY_ID_BYTES * 2]


def wrap_symmetric_key_v5(
    key_data: bytes,
    recipient_public_key: RelayKemPublicKey | str | bytes,
    aad: bytes,
) -> RelayKeyWrapV5:
    """HPKE base-mode hybrid wrap of one 32-byte content key."""
    if len(key_data) != _SYMMETRIC_KEY_BYTES:
        raise relay_e2ee.InvalidSymmetricKeyError("symmetric key must be 32 bytes")
    recipient = _coerce_kem_public_key(recipient_public_key)
    combined = _hpke_suite().encrypt(
        key_data,
        recipient._hpke_public_key(),
        info=_hpke_info(aad),
    )
    if len(combined) <= _HPKE_ENCAPSULATED_KEY_BYTES:
        raise relay_e2ee.InvalidCiphertextError("HPKE v5 output is too short")
    return RelayKeyWrapV5(
        enc=base64.b64encode(combined[:_HPKE_ENCAPSULATED_KEY_BYTES]).decode("ascii"),
        wrapped_key=base64.b64encode(combined[_HPKE_ENCAPSULATED_KEY_BYTES:]).decode("ascii"),
    )


def unwrap_symmetric_key_v5(
    enc: str | bytes,
    wrapped_key: str | bytes,
    private_key: RelayKemPrivateKey | str | bytes,
    aad: bytes,
) -> bytes:
    recipient = _coerce_kem_private_key(private_key)
    enc_bytes = _coerce_b64_field(enc, "enc")
    if len(enc_bytes) != _HPKE_ENCAPSULATED_KEY_BYTES:
        raise relay_e2ee.InvalidCiphertextError("HPKE v5 enc must be 1120 bytes")
    wrapped = _coerce_b64_field(wrapped_key, "wrappedKey")
    return _hpke_suite().decrypt(
        enc_bytes + wrapped,
        recipient._hpke_private_key(),
        info=_hpke_info(aad),
    )


def seal_signed_v5(
    payload_plaintext: bytes,
    *,
    recipient_kem_public: RelayKemPublicKey | str | bytes,
    recipient_verify_key: relay_e2ee_v4.RelayVerifyKey | str | bytes,
    sender_signing_key: relay_e2ee_v4.RelaySigningKey,
    key_aad: bytes,
    payload_aad: bytes,
    content_key: bytes | None = None,
) -> RelaySignedEnvelopeV5:
    recipient_kem = _coerce_kem_public_key(recipient_kem_public)
    recipient_vk = relay_e2ee_v4._coerce_verify_key(recipient_verify_key)
    if content_key is None:
        content_key = relay_e2ee.generate_symmetric_key()
    wrap = wrap_symmetric_key_v5(content_key, recipient_kem, key_aad)
    payload_ct = relay_e2ee.seal_to_base64(
        relay_e2ee_v4.padme_pad(payload_plaintext),
        content_key,
        payload_aad,
    )
    transcript = relay_e2ee_v4.relay_signing_transcript(
        sender_verify_key=sender_signing_key.public_key_raw(),
        recipient_verify_key=recipient_vk.public_key_raw(),
        recipient_enc_x963=recipient_kem.raw_representation,
        key_aad=key_aad,
        raw_enc=base64.b64decode(wrap.enc),
        raw_wrapped_key=base64.b64decode(wrap.wrapped_key),
        payload_aad=payload_aad,
        raw_payload_seal=base64.b64decode(payload_ct),
        label=_SIG_LABEL_V5,
        version=RELAY_KEY_VERSION_V5,
    )
    signature = sender_signing_key.sign(transcript)
    return RelaySignedEnvelopeV5(
        enc=wrap.enc,
        wrapped_key=wrap.wrapped_key,
        payload_ciphertext=payload_ct,
        sender_sig=base64.b64encode(signature).decode("ascii"),
    )


def open_signed_v5(
    envelope: RelaySignedEnvelopeV5 | dict,
    *,
    recipient_kem_private: RelayKemPrivateKey | str | bytes,
    recipient_verify_key: relay_e2ee_v4.RelayVerifyKey | str | bytes,
    pinned_sender_verify_key: relay_e2ee_v4.RelayVerifyKey | str | bytes,
    key_aad: bytes,
    payload_aad: bytes,
) -> bytes:
    if isinstance(envelope, RelaySignedEnvelopeV5):
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
        raise RelayV5SignatureError("v5 envelope missing enc/wrappedKey/payload/senderSig")

    recipient_kem = _coerce_kem_private_key(recipient_kem_private)
    recipient_vk = relay_e2ee_v4._coerce_verify_key(recipient_verify_key)
    sender_vk = relay_e2ee_v4._coerce_verify_key(pinned_sender_verify_key)
    try:
        enc_bytes = base64.b64decode(enc, validate=True)
        wrapped_bytes = base64.b64decode(wrapped_key, validate=True)
        payload_bytes = base64.b64decode(payload_ct, validate=True)
        signature = base64.b64decode(sender_sig, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayV5SignatureError("v5 envelope field is not valid base64") from exc

    transcript = relay_e2ee_v4.relay_signing_transcript(
        sender_verify_key=sender_vk.public_key_raw(),
        recipient_verify_key=recipient_vk.public_key_raw(),
        recipient_enc_x963=recipient_kem.public_key_bytes(),
        key_aad=key_aad,
        raw_enc=enc_bytes,
        raw_wrapped_key=wrapped_bytes,
        payload_aad=payload_aad,
        raw_payload_seal=payload_bytes,
        label=_SIG_LABEL_V5,
        version=RELAY_KEY_VERSION_V5,
    )
    try:
        sender_vk.verify(signature, transcript)
    except relay_e2ee_v4.RelayV4SignatureError as exc:
        raise RelayV5SignatureError("v5 envelope signature verification failed") from exc
    content_key = unwrap_symmetric_key_v5(enc, wrapped_key, recipient_kem, key_aad)
    return relay_e2ee_v4.padme_unpad(
        relay_e2ee.open_base64(payload_ct, content_key, payload_aad)
    )


def xwing_encapsulate(public_key: RelayKemPublicKey | str | bytes) -> tuple[bytes, bytes]:
    """Return ``(shared_secret, ciphertext)`` for ratchet-init root seeding."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = _coerce_kem_public_key(public_key)
    mlkem_public = _mlkem_public_from_raw(public.mlkem_public_key_bytes())
    ss_m, ct_m = mlkem_public.encapsulate()
    ek_x = x25519.X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_x = ek_x.exchange(_x25519_public_from_raw(public.x25519_public_key_bytes()))
    return _xwing_combiner(ss_m, ss_x, ct_x, public.x25519_public_key_bytes()), ct_m + ct_x


def xwing_decapsulate(
    private_key: RelayKemPrivateKey | str | bytes,
    ciphertext: bytes,
) -> bytes:
    private = _coerce_kem_private_key(private_key)
    if len(ciphertext) != KEM_CIPHERTEXT_BYTES:
        raise relay_e2ee.InvalidCiphertextError("X-Wing ciphertext must be 1120 bytes")
    ct_m = ciphertext[:MLKEM768_CIPHERTEXT_BYTES]
    ct_x = ciphertext[MLKEM768_CIPHERTEXT_BYTES:]
    ss_m = private._mlkem_private_key().decapsulate(ct_m)
    ss_x = private._x25519_private_key().exchange(_x25519_public_from_raw(ct_x))
    pk_x = private.public_key().x25519_public_key_bytes()
    return _xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def _xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    if len(ss_m) != 32 or len(ss_x) != 32 or len(ct_x) != 32 or len(pk_x) != 32:
        raise relay_e2ee.InvalidCiphertextError("invalid X-Wing component length")
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()


def _hpke_suite():
    try:
        from cryptography.hazmat.primitives import hpke

        return hpke.Suite(
            hpke.KEM.MLKEM768_X25519,
            hpke.KDF.HKDF_SHA256,
            hpke.AEAD.AES_256_GCM,
        )
    except Exception as exc:
        raise RelayV5UnsupportedError(
            "cryptography with HPKE MLKEM768_X25519 support is required for v5"
        ) from exc


def _hpke_info(aad: bytes) -> bytes:
    return _HPKE_INFO_PREFIX_V5 + aad


def _mlkem_public_from_raw(raw: bytes):
    if len(raw) != MLKEM768_PUBLIC_KEY_BYTES:
        raise relay_e2ee.InvalidPublicKeyError("ML-KEM-768 public key must be 1184 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem

        return mlkem.MLKEM768PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise relay_e2ee.InvalidPublicKeyError("ML-KEM-768 public key is invalid") from exc


def _x25519_public_from_raw(raw: bytes):
    if len(raw) != X25519_PUBLIC_KEY_BYTES:
        raise relay_e2ee.InvalidPublicKeyError("X25519 public key must be 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519

        return x25519.X25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise relay_e2ee.InvalidPublicKeyError("X25519 public key is invalid") from exc


def _coerce_kem_public_key(value: RelayKemPublicKey | str | bytes) -> RelayKemPublicKey:
    if isinstance(value, RelayKemPublicKey):
        return value
    if isinstance(value, str):
        return RelayKemPublicKey.from_base64(value)
    if isinstance(value, (bytes, bytearray)):
        return RelayKemPublicKey.from_raw(bytes(value))
    raise relay_e2ee.InvalidPublicKeyError(
        "relay KEM public key must be RelayKemPublicKey, base64 str, or raw bytes"
    )


def _coerce_kem_private_key(value: RelayKemPrivateKey | str | bytes) -> RelayKemPrivateKey:
    if isinstance(value, RelayKemPrivateKey):
        return value
    if isinstance(value, str):
        return RelayKemPrivateKey.from_base64(value)
    if isinstance(value, (bytes, bytearray)):
        return RelayKemPrivateKey.from_raw(bytes(value))
    raise relay_e2ee.InvalidPublicKeyError(
        "relay KEM private key must be RelayKemPrivateKey, base64 str, or raw seed"
    )


def _coerce_b64_field(value: str | bytes, field: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise relay_e2ee.InvalidCiphertextError(f"HPKE v5 {field} is not valid base64") from exc
    raise relay_e2ee.InvalidCiphertextError(f"HPKE v5 {field} must be bytes or base64 str")


__all__ = [
    "RELAY_KEY_VERSION_V5",
    "RELAY_ENCRYPTION_V5",
    "RELAY_KEM_PRIVATE_KEY_ENV",
    "KEM_PUBLIC_KEY_BYTES",
    "KEM_PRIVATE_SEED_BYTES",
    "KEM_CIPHERTEXT_BYTES",
    "RelayV5Error",
    "RelayV5UnsupportedError",
    "RelayV5SignatureError",
    "RelayKemPublicKey",
    "RelayKemPrivateKey",
    "AgentKemIdentity",
    "RelayKeyWrapV5",
    "RelaySignedEnvelopeV5",
    "is_supported",
    "generate_kem_private_key",
    "kem_key_id",
    "wrap_symmetric_key_v5",
    "unwrap_symmetric_key_v5",
    "seal_signed_v5",
    "open_signed_v5",
    "xwing_encapsulate",
    "xwing_decapsulate",
]
