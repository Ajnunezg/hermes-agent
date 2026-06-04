"""Self-contained RFC 9180 HPKE **Auth-mode** reference for the BurnBar relay v3
content-key wrap — a cross-language *conformance oracle*, NOT production crypto.

The cross-stream HPKE v3 contract (frozen in ``plans/agents/burnbar-hpke-v3-*``
and mirrored byte-for-byte by ``gateway/crypto/relay_e2ee.py`` and the Swift
``HermesRelayCrypto``):

* Suite: ``DHKEM(P-256, HKDF-SHA256)`` [KEM 0x0010] + ``HKDF-SHA256`` [KDF 0x0001]
  + ``AES-256-GCM`` [AEAD 0x0002].
* Mode: HPKE **auth** (``mode_auth`` = 0x02) — the recipient binds the *pinned*
  sender static key, so a relay cannot forge a wrap.
* ``info = b"OpenBurnBar-HermesRelay-HPKE-v3|" + key_aad``
* ``aad  = key_aad`` (the single HPKE-sealed message's AEAD associated data).
* ``pt   = 32-byte content key`` (the symmetric key that seals the payload /
  attachment AES-GCM layers — those layers are unchanged from v2).
* Wire: ``enc`` = base64 of the 65-byte X9.63 uncompressed ephemeral public key;
  ``wrappedKey`` = base64 of the 48-byte HPKE ciphertext (``ct(32) ‖ tag(16)``).
* Envelope markers: ``relayKeyVersion = 3``,
  ``relayEncryption = "hpke-auth-p256-hkdfsha256-aes256gcm"``.

This module deliberately re-implements RFC 9180 §5.1 (KeySchedule), §6.1
(single-shot), and §7.1.1/§7.1.3 (DHKEM AuthEncap/AuthDecap, DeriveKeyPair) from
the spec using only :mod:`hashlib`/:mod:`hmac` + the ``cryptography`` EC/AEAD
primitives, so a reviewer can audit every authenticated byte against the RFC
without trusting the production module it is meant to check. Correctness is
triangulated three ways: (1) this reference's own round-trip + forgery
``run_self_test``; (2) the verifier cross-checks the production ``relay_e2ee``
HPKE primitives produce identical bytes; (3) Swift CryptoKit (an independent
RFC 9180 implementation) opens the same fixture.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Suite parameters (RFC 9180 §7) — identical to relay_e2ee.py's _HPKE_* block.
# ---------------------------------------------------------------------------

KEM_ID = 0x0010   # DHKEM(P-256, HKDF-SHA256)
KDF_ID = 0x0001   # HKDF-SHA256
AEAD_ID = 0x0002  # AES-256-GCM
MODE_AUTH = 0x02

RELAY_KEY_VERSION_V3 = 3
RELAY_ENCRYPTION_V3 = "hpke-auth-p256-hkdfsha256-aes256gcm"
INFO_PREFIX = b"OpenBurnBar-HermesRelay-HPKE-v3|"

_VERSION_LABEL = b"HPKE-v1"
_NH = 32        # HKDF-SHA256 output length
_NSECRET = 32   # DHKEM(P-256, HKDF-SHA256) shared-secret length
_NK = 32        # AES-256-GCM key length
_NN = 12        # AES-256-GCM nonce length
_NPK = 65       # P-256 X9.63 uncompressed public key length
_NSK = 32       # P-256 private scalar length
_TAG = 16       # AES-GCM tag length

# Order of the P-256 group (used only by DeriveKeyPair rejection sampling).
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (
    b"HPKE"
    + KEM_ID.to_bytes(2, "big")
    + KDF_ID.to_bytes(2, "big")
    + AEAD_ID.to_bytes(2, "big")
)


class HpkeError(Exception):
    """Raised for malformed v3 inputs (bad point, wrong length)."""


# ---------------------------------------------------------------------------
# HKDF primitives (RFC 5869) and HPKE labeled KDF (RFC 9180 §4)
# ---------------------------------------------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # Extract(salt, ikm) = HMAC-Hash(salt, ikm). An empty salt is the RFC 5869
    # default of HashLen zero bytes (HMAC also zero-pads the key to the block
    # size, so HMAC(b"") == HMAC(b"\x00"*32) — we normalise for readability).
    if not salt:
        salt = b"\x00" * _NH
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * _NH:
        raise HpkeError("HKDF-Expand length out of range")
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, _VERSION_LABEL + suite_id + label + ikm)


def _labeled_expand(
    suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    labeled_info = length.to_bytes(2, "big") + _VERSION_LABEL + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


# ---------------------------------------------------------------------------
# P-256 key (de)serialization + DH (RFC 9180 §7.1.1)
# ---------------------------------------------------------------------------


def private_from_raw(raw: bytes) -> ec.EllipticCurvePrivateKey:
    if len(raw) != _NSK:
        raise HpkeError("P-256 private key must be the raw 32-byte scalar")
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def public_from_x963(x963: bytes) -> ec.EllipticCurvePublicKey:
    if len(x963) != _NPK or x963[0] != 0x04:
        raise HpkeError("P-256 public key must be 65-byte X9.63 uncompressed (0x04)")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), x963)
    except ValueError as exc:  # off-curve / invalid point
        raise HpkeError("invalid P-256 public key point") from exc


def serialize_public(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _dh(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey) -> bytes:
    # DHKEM DH(skX, pkY) for the NIST curves is the raw big-endian x-coordinate
    # of the shared point (RFC 9180 §7.1.1) — exactly what ``exchange`` returns.
    return priv.exchange(ec.ECDH(), pub)


def derive_key_pair(ikm: bytes) -> ec.EllipticCurvePrivateKey:
    """RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(P-256, HKDF-SHA256).

    Present for completeness / future RFC known-answer tests; the generator uses
    random ephemerals and explicit static scalars, so this is not on the wrap
    path. Rejection-samples a candidate scalar in ``[1, n-1]``.
    """
    dkp_prk = _labeled_extract(_KEM_SUITE_ID, b"", b"dkp_prk", ikm)
    for counter in range(256):
        candidate = _labeled_expand(
            _KEM_SUITE_ID, dkp_prk, b"candidate", bytes([counter]), _NSK
        )
        # bitmask for P-256 is 0xFF (no high-bit clearing); interpret big-endian.
        sk_int = int.from_bytes(candidate, "big")
        if 1 <= sk_int < _P256_ORDER:
            return ec.derive_private_key(sk_int, ec.SECP256R1())
    raise HpkeError("DeriveKeyPair exhausted rejection sampling")  # pragma: no cover


# ---------------------------------------------------------------------------
# DHKEM AuthEncap / AuthDecap (RFC 9180 §5.1.3, §7.1.1)
# ---------------------------------------------------------------------------


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(_KEM_SUITE_ID, b"", b"eae_prk", dh)
    return _labeled_expand(
        _KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, _NSECRET
    )


def auth_encap(
    pk_r: ec.EllipticCurvePublicKey,
    sk_s: ec.EllipticCurvePrivateKey,
    sk_e: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[bytes, bytes]:
    """AuthEncap(pkR, skS) -> (shared_secret, enc). ``sk_e`` may be supplied for
    deterministic vectors; production uses a fresh random ephemeral."""
    if sk_e is None:
        sk_e = ec.generate_private_key(ec.SECP256R1())
    enc = serialize_public(sk_e.public_key())
    dh = _dh(sk_e, pk_r) + _dh(sk_s, pk_r)  # CONCAT: ephemeral leg then static leg
    kem_context = enc + serialize_public(pk_r) + serialize_public(sk_s.public_key())
    return _extract_and_expand(dh, kem_context), enc


def auth_decap(
    enc: bytes,
    sk_r: ec.EllipticCurvePrivateKey,
    pk_s: ec.EllipticCurvePublicKey,
) -> bytes:
    """AuthDecap(enc, skR, pkS) -> shared_secret. ``pk_s`` is the PINNED sender
    static key (never a wire-supplied field) — the forgery defense."""
    pk_e = public_from_x963(enc)
    dh = _dh(sk_r, pk_e) + _dh(sk_r, pk_s)
    kem_context = enc + serialize_public(sk_r.public_key()) + serialize_public(pk_s)
    return _extract_and_expand(dh, kem_context)


# ---------------------------------------------------------------------------
# Key schedule (mode_auth, no PSK) — RFC 9180 §5.1
# ---------------------------------------------------------------------------


def key_schedule_auth(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"info_hash", info)
    key_schedule_context = bytes([MODE_AUTH]) + psk_id_hash + info_hash
    secret = _labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(_HPKE_SUITE_ID, secret, b"key", key_schedule_context, _NK)
    base_nonce = _labeled_expand(
        _HPKE_SUITE_ID, secret, b"base_nonce", key_schedule_context, _NN
    )
    return key, base_nonce


def info_for(key_aad: bytes) -> bytes:
    return INFO_PREFIX + key_aad


# ---------------------------------------------------------------------------
# Single-shot Seal / Open (sequence number 0 -> nonce == base_nonce)
# ---------------------------------------------------------------------------


def seal_auth(
    pk_r: ec.EllipticCurvePublicKey,
    sk_s: ec.EllipticCurvePrivateKey,
    info: bytes,
    aad: bytes,
    pt: bytes,
    sk_e: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[bytes, bytes]:
    shared, enc = auth_encap(pk_r, sk_s, sk_e)
    key, base_nonce = key_schedule_auth(shared, info)
    ct = AESGCM(key).encrypt(base_nonce, pt, aad)
    return enc, ct


def open_auth(
    enc: bytes,
    sk_r: ec.EllipticCurvePrivateKey,
    pk_s: ec.EllipticCurvePublicKey,
    info: bytes,
    aad: bytes,
    ct: bytes,
) -> bytes:
    shared = auth_decap(enc, sk_r, pk_s)
    key, base_nonce = key_schedule_auth(shared, info)
    return AESGCM(key).decrypt(base_nonce, ct, aad)


# ---------------------------------------------------------------------------
# BurnBar v3 content-key wrap (the wire surface used by the generator/verifier)
# ---------------------------------------------------------------------------


def wrap_content_key(
    content_key: bytes,
    recipient_public_x963: bytes,
    sender_private_raw: bytes,
    key_aad: bytes,
    *,
    ephemeral_private: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[str, str]:
    """Wrap a 32-byte ``content_key`` to ``recipient_public_x963`` authenticated
    by ``sender_private_raw``. Returns ``(enc_base64, wrapped_key_base64)``."""
    if len(content_key) != _NK:
        raise HpkeError("content key must be 32 bytes")
    pk_r = public_from_x963(recipient_public_x963)
    sk_s = private_from_raw(sender_private_raw)
    enc, ct = seal_auth(
        pk_r, sk_s, info_for(key_aad), key_aad, content_key, ephemeral_private
    )
    return (
        base64.b64encode(enc).decode("ascii"),
        base64.b64encode(ct).decode("ascii"),
    )


def open_content_key(
    enc_base64: str,
    wrapped_key_base64: str,
    recipient_private_raw: bytes,
    pinned_sender_public_x963: bytes,
    key_aad: bytes,
) -> bytes:
    """Open a v3 wrap, binding the PINNED sender key. Raises on any forgery /
    tamper (``cryptography.exceptions.InvalidTag``) or malformed input
    (:class:`HpkeError`)."""
    enc = base64.b64decode(enc_base64, validate=True)
    ct = base64.b64decode(wrapped_key_base64, validate=True)
    sk_r = private_from_raw(recipient_private_raw)
    pk_s = public_from_x963(pinned_sender_public_x963)
    return open_auth(enc, sk_r, pk_s, info_for(key_aad), key_aad, ct)


# ---------------------------------------------------------------------------
# Payload / attachment AES-GCM layer (UNCHANGED from v1/v2: base64(nonce ‖ ct ‖
# tag)). v3 only swaps the *content-key wrap*; the sealed payload that the
# unwrapped content key opens uses the same combined-box format as
# relay_e2ee.seal_to_base64 / Swift HermesRelayCrypto.sealToBase64.
# ---------------------------------------------------------------------------


def seal_payload_base64(plaintext: bytes, content_key: bytes, aad: bytes) -> str:
    import os

    if len(content_key) != _NK:
        raise HpkeError("content key must be 32 bytes")
    nonce = os.urandom(_NN)
    return base64.b64encode(nonce + AESGCM(content_key).encrypt(nonce, plaintext, aad)).decode(
        "ascii"
    )


def open_payload_base64(ciphertext_base64: str, content_key: bytes, aad: bytes) -> bytes:
    if len(content_key) != _NK:
        raise HpkeError("content key must be 32 bytes")
    raw = base64.b64decode(ciphertext_base64, validate=True)
    if len(raw) <= _NN:
        raise HpkeError("payload ciphertext too short")
    return AESGCM(content_key).decrypt(raw[:_NN], raw[_NN:], aad)


# ---------------------------------------------------------------------------
# v3 admission predicate — what the gateway's v3 open path requires before it
# will run the v3 HPKE opener. This is the *v3 consumer's* strict admission, NOT
# the full multi-version adapter dispatch: the production adapter accepts the
# supported set {2, 3} and routes by version (a v2-relabeled frame goes to the
# v2 opener, which fails closed on the 48-byte v3 wrappedKey's length; a v1 or
# unknown version is refused at the version gate). The fail-closed *property*
# (a downgraded/stripped frame never yields the content key) is proven end-to-end
# against the production dispatch in test_burnbar_hpke_v3_vectors.py.
# ---------------------------------------------------------------------------


class RelayV3EnvelopeError(Exception):
    """An envelope failed the v3 open path's admission checks (not v3-marked /
    missing the HPKE marker / missing enc|wrappedKey)."""


def parse_strict_v3_envelope(envelope: dict) -> tuple[str, str]:
    """Return ``(enc, wrappedKey)`` iff ``envelope`` would be admitted to the v3
    HPKE opener, else raise. A frame that is not marked ``relayKeyVersion == 3``,
    lacks the HPKE ``relayEncryption`` marker, or is missing ``enc``/``wrappedKey``
    is not a v3 frame and is refused here — the v3 opener never runs on it."""
    version = envelope.get("relayKeyVersion")
    if version != RELAY_KEY_VERSION_V3:  # exact int 3; "2"/"1"/None all reject
        raise RelayV3EnvelopeError(
            f"refusing non-v3 gateway envelope (relayKeyVersion={version!r}); "
            "the relay may not downgrade a sealed v3 frame"
        )
    if envelope.get("relayEncryption") != RELAY_ENCRYPTION_V3:
        raise RelayV3EnvelopeError(
            "refusing sealed v3 frame without the "
            f"relayEncryption={RELAY_ENCRYPTION_V3!r} marker"
        )
    enc = envelope.get("enc")
    wrapped = envelope.get("wrappedKey")
    if not isinstance(enc, str) or not enc:
        raise RelayV3EnvelopeError("sealed v3 frame is missing the HPKE 'enc' field")
    if not isinstance(wrapped, str) or not wrapped:
        raise RelayV3EnvelopeError("sealed v3 frame is missing the 'wrappedKey' field")
    return enc, wrapped


# ---------------------------------------------------------------------------
# Self-test (called by the verifier as a pytest) — round trip + forgery + shapes
# ---------------------------------------------------------------------------


# RFC 9180 Appendix A known-answer vector for the EXACT shipped suite —
# DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, mode_auth — taken
# verbatim from the canonical CFRG test-vectors.json (mode=2, kem_id=16,
# kdf_id=1, aead_id=2). Anchors the construction to the RFC text itself, not
# only to CryptoKit/production interop. (The RFC's own `info` "Ode on a Grecian
# Urn" is used here; production uses a different `info` over the SAME construction.)
_RFC9180_AUTH_P256_AES256_KAT = {
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "ikmE": "d6c49e442aad90bcc1bc0d166e5c4d3df845c803ba08b8a4d891af2eeae4f97e",
    "skEm": "7a6cb29fab4e249d1796f95645288a6504d2167c7ff463bc447ab6022462af42",
    "skRm": "d9f10996a02cd6c9dbda1d1f225f18f781ea3c893b8c2a6cb2e266e59f3cd9a9",
    "skSm": "6e7b14befe49443dc501def1cc2f0f293d9c5cfa045a23e9a2e0e7703b42705d",
    "pkRm": "04cd38ef80923e26f157e06c9887f80177c97e1005a41104127271237f946df2"
            "2eda13d40801bce6184f1a631c44b0807a1a5e8d039975ed0f6079fcbd2dfe6652",
    "pkSm": "04ece9b48cc98ee03ba742fe1218a3fbec960cc34b6e1defdcd3285276f39028e9"
            "5b90f9526607565888766a1101f429dc3ec87364b5c8c613f0a081881950427f",
    "enc": "04a7aeac79fda402674ef247c12d6f5fdfd21498d896b67ff04ec181382d4516b7"
           "662be32b4a2ae817c2d57104ecb6fcaa527438939810612d1b3d0af36ffc66ce",
    "shared_secret": "4b6e403bf494c60342caaa46b3738ee0423892720751607338034b0a067cc1db",
    "key": "640064834667025be3ce7abf1eb42ccc0dea2db9782b9823519f474e054524e7",
    "base_nonce": "29240057274f71e55bfcca28",
    "pt": "4265617574792069732074727574682c20747275746820626561757479",
    "aad": "436f756e742d30",
    "ct": "59b9890aabf94c1d502c39d8d356989ab0880ed43e984255db7b32a8d7b0ad5beba"
          "799a4ec326a0ddca3dd5e5d",
}


def run_rfc9180_kat() -> None:
    """Validate the reference against the canonical RFC 9180 known-answer vector
    for the exact shipped suite: DeriveKeyPair, AuthEncap (reproduces ``enc`` +
    ``shared_secret`` byte-for-byte with the RFC's fixed ephemeral), the key
    schedule (``key`` + ``base_nonce``), Seal (``ct``), and the AuthDecap round
    trip — every value matched to the RFC."""
    v = {k: bytes.fromhex(s) for k, s in _RFC9180_AUTH_P256_AES256_KAT.items()}

    # DeriveKeyPair(ikmE) must yield skEm (validates rejection sampling + labels).
    derived = derive_key_pair(v["ikmE"]).private_numbers().private_value
    assert derived == int.from_bytes(v["skEm"], "big"), "DeriveKeyPair(ikmE) != skEm"

    sk_e = private_from_raw(v["skEm"])
    sk_r = private_from_raw(v["skRm"])
    sk_s = private_from_raw(v["skSm"])
    pk_r = public_from_x963(v["pkRm"])
    pk_s = public_from_x963(v["pkSm"])

    shared, enc = auth_encap(pk_r, sk_s, sk_e)
    assert enc == v["enc"], "AuthEncap enc != RFC"
    assert shared == v["shared_secret"], "AuthEncap shared_secret != RFC"

    key, base_nonce = key_schedule_auth(shared, v["info"])
    assert key == v["key"], "KeySchedule key != RFC"
    assert base_nonce == v["base_nonce"], "KeySchedule base_nonce != RFC"

    _, ct = seal_auth(pk_r, sk_s, v["info"], v["aad"], v["pt"], sk_e)
    assert ct == v["ct"], "Seal ct != RFC"

    shared_r = auth_decap(enc, sk_r, pk_s)
    assert shared_r == shared, "AuthDecap shared_secret != AuthEncap"
    assert open_auth(enc, sk_r, pk_s, v["info"], v["aad"], ct) == v["pt"], "Open != pt"


def run_self_test() -> None:
    """Prove the reference is internally RFC-correct: structural suite IDs, a
    round trip, and that every forgery / tamper raises. No external vectors."""
    from cryptography.exceptions import InvalidTag

    assert _KEM_SUITE_ID == b"KEM\x00\x10", _KEM_SUITE_ID
    assert _HPKE_SUITE_ID == b"HPKE\x00\x10\x00\x01\x00\x02", _HPKE_SUITE_ID
    assert INFO_PREFIX == b"OpenBurnBar-HermesRelay-HPKE-v3|"

    recipient = ec.generate_private_key(ec.SECP256R1())
    sender = ec.generate_private_key(ec.SECP256R1())
    recipient_raw = recipient.private_numbers().private_value.to_bytes(32, "big")
    sender_raw = sender.private_numbers().private_value.to_bytes(32, "big")
    recipient_pub = serialize_public(recipient.public_key())
    sender_pub = serialize_public(sender.public_key())

    content_key = bytes(range(32))
    key_aad = b"OpenBurnBar-HermesRelay-v1|gatewayEventKey|u|c|e"

    enc_b64, wrapped_b64 = wrap_content_key(
        content_key, recipient_pub, sender_raw, key_aad
    )
    assert len(base64.b64decode(enc_b64)) == _NPK, "enc must be 65-byte X9.63"
    assert len(base64.b64decode(wrapped_b64)) == _NK + _TAG, "wrappedKey must be 48B"

    opened = open_content_key(enc_b64, wrapped_b64, recipient_raw, sender_pub, key_aad)
    assert opened == content_key, "round trip must recover the content key"

    # Forgery / tamper: every one of these MUST raise.
    other = ec.generate_private_key(ec.SECP256R1())
    other_raw = other.private_numbers().private_value.to_bytes(32, "big")
    other_pub = serialize_public(other.public_key())

    def _must_raise(fn, *exc):
        try:
            fn()
        except exc:  # type: ignore[misc]
            return
        raise AssertionError("expected a rejection but the open succeeded")

    # wrong pinned sender key
    _must_raise(
        lambda: open_content_key(enc_b64, wrapped_b64, recipient_raw, other_pub, key_aad),
        InvalidTag,
    )
    # wrong recipient private key
    _must_raise(
        lambda: open_content_key(enc_b64, wrapped_b64, other_raw, sender_pub, key_aad),
        InvalidTag,
    )
    # wrong key_aad (changes both info and aad)
    _must_raise(
        lambda: open_content_key(
            enc_b64, wrapped_b64, recipient_raw, sender_pub, key_aad + b"X"
        ),
        InvalidTag,
    )
    # mutated wrappedKey (flip a ciphertext byte)
    bad_ct = bytearray(base64.b64decode(wrapped_b64))
    bad_ct[0] ^= 0x01
    _must_raise(
        lambda: open_content_key(
            enc_b64, base64.b64encode(bytes(bad_ct)).decode(), recipient_raw, sender_pub, key_aad
        ),
        InvalidTag,
    )
    # mutated enc (flip an encapsulated-key byte): either an invalid point or a
    # wrong DH -> reject. Flip a low byte to stay on a parseable-but-wrong point
    # where possible; both HpkeError and InvalidTag are acceptable rejections.
    bad_enc = bytearray(base64.b64decode(enc_b64))
    bad_enc[40] ^= 0x01
    _must_raise(
        lambda: open_content_key(
            base64.b64encode(bytes(bad_enc)).decode(), wrapped_b64, recipient_raw, sender_pub, key_aad
        ),
        InvalidTag,
        HpkeError,
        ValueError,
    )


if __name__ == "__main__":  # pragma: no cover
    run_rfc9180_kat()
    print("hpke_v3_reference: RFC 9180 known-answer vector OK")
    run_self_test()
    print("hpke_v3_reference: self-test OK")
