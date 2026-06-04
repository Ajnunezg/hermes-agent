"""RFC 9180 HPKE Auth-mode v3 relay key-wrap: conformance + behaviour.

First pins the v3 key wrap added to :mod:`gateway.crypto.relay_e2ee` against the
published RFC 9180 Appendix A.3.3 known-answer vector (so a reviewer can point at
the RFC rather than a bespoke KEM), then exercises the typed wrap/unwrap helpers
for round trip and every forged-input failure: wrong pinned sender, wrong
recipient, wrong AAD, mutated ``enc``, mutated ``wrappedKey``, plus v2<->v3
domain separation.

The v3 suite is ``DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM``,
``mode_auth``. RFC 9180 A.3.3 uses the same KEM + KDF but AES-128-GCM; the KEM
and key-schedule construction are AEAD-independent, so the A.3.3 vector pins the
module's DHKEM AuthEncap/AuthDecap and labeled key schedule exactly, and a
separate consistency check pins the production AES-256 schedule against the same
RFC labeled KDF.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("cryptography")

from gateway.crypto import relay_e2ee  # noqa: E402


# --- RFC 9180 Appendix A.3.3 -------------------------------------------------
# DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode_auth (mode = 0x02).
# https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.3
_A33 = {
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "skEm": "6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91",
    "skRm": "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e",
    "skSm": "1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9",
    "enc": "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b"
    "79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454",
    "shared_secret": "d4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f",
    "key_schedule_context": "02b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e0"
    "88c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85",
    "secret": "fd0a93c7c6f6b1b0dd6a822d7b16f6c61c83d98ad88426df4613c3581a2319f1",
    "key": "19aa8472b3fdc530392b0e54ca17c0f5",
    "base_nonce": "b390052d26b67a5b8a8fcaa4",
    "pt": "4265617574792069732074727574682c20747275746820626561757479",
    "aad": "436f756e742d30",
    "ct": "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb"
    "8f265db4a099ed3289ffe19",
}
# A.3.3 uses AES-128-GCM (aead_id 0x0001); the production v3 suite is AES-256-GCM
# (0x0002). Drive the module's RFC labeled KDF with the A.3.3 HPKE suite_id.
_A33_SUITE_ID = (
    b"HPKE"
    + (0x0010).to_bytes(2, "big")
    + (0x0001).to_bytes(2, "big")
    + (0x0001).to_bytes(2, "big")
)


def _ec_priv(hex_scalar: str):
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.derive_private_key(
        int.from_bytes(bytes.fromhex(hex_scalar), "big"), ec.SECP256R1()
    )


def test_rfc9180_a33_dhkem_authencap_matches_vector():
    """DHKEM(P-256) AuthEncap/AuthDecap: enc + shared_secret match RFC 9180 A.3.3."""
    sk_e = _ec_priv(_A33["skEm"])
    sk_r = _ec_priv(_A33["skRm"])
    sk_s = _ec_priv(_A33["skSm"])
    shared_secret, enc = relay_e2ee._hpke_auth_encap(
        sk_r.public_key(), sk_s, ephemeral_private=sk_e
    )
    assert enc.hex() == _A33["enc"]
    assert shared_secret.hex() == _A33["shared_secret"]
    # AuthDecap against the pinned sender recovers the identical shared secret.
    recovered = relay_e2ee._hpke_auth_decap(enc, sk_r, sk_s.public_key())
    assert recovered == shared_secret


def test_rfc9180_a33_key_schedule_and_seal_match_vector():
    """mode_auth key schedule (ksc/secret/key/base_nonce) + seal match A.3.3."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    suite = _A33_SUITE_ID
    info = bytes.fromhex(_A33["info"])
    shared_secret = bytes.fromhex(_A33["shared_secret"])
    psk_id_hash = relay_e2ee._hpke_labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = relay_e2ee._hpke_labeled_extract(suite, b"", b"info_hash", info)
    ksc = bytes([relay_e2ee._HPKE_AUTH_MODE]) + psk_id_hash + info_hash
    assert ksc.hex() == _A33["key_schedule_context"]
    secret = relay_e2ee._hpke_labeled_extract(suite, shared_secret, b"secret", b"")
    assert secret.hex() == _A33["secret"]
    key = relay_e2ee._hpke_labeled_expand(suite, secret, b"key", ksc, 16)
    base_nonce = relay_e2ee._hpke_labeled_expand(suite, secret, b"base_nonce", ksc, 12)
    assert key.hex() == _A33["key"]
    assert base_nonce.hex() == _A33["base_nonce"]
    # Single-shot seal at seq 0: nonce == base_nonce.
    ct = AESGCM(key).encrypt(
        base_nonce, bytes.fromhex(_A33["pt"]), bytes.fromhex(_A33["aad"])
    )
    assert ct.hex() == _A33["ct"]


def test_v3_production_key_schedule_is_rfc_consistent():
    """The hardwired AES-256 key schedule equals an independent RFC assembly.

    There is no published AES-256 P-256/HKDF-SHA256 Auth vector, so cross-check
    ``_hpke_auth_key_schedule`` (which hardwires the AES-256-GCM suite_id and
    Nk=32) against the same RFC labeled KDF the A.3.3 test pins.
    """
    shared_secret = bytes(range(32))
    info = relay_e2ee._hpke_info(relay_e2ee.key_aad("u", "c", "r"))
    key, base_nonce = relay_e2ee._hpke_auth_key_schedule(shared_secret, info)
    suite = relay_e2ee._HPKE_SUITE_ID
    psk_id_hash = relay_e2ee._hpke_labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = relay_e2ee._hpke_labeled_extract(suite, b"", b"info_hash", info)
    ksc = bytes([relay_e2ee._HPKE_AUTH_MODE]) + psk_id_hash + info_hash
    secret = relay_e2ee._hpke_labeled_extract(suite, shared_secret, b"secret", b"")
    assert key == relay_e2ee._hpke_labeled_expand(suite, secret, b"key", ksc, 32)
    assert base_nonce == relay_e2ee._hpke_labeled_expand(
        suite, secret, b"base_nonce", ksc, 12
    )
    assert len(key) == 32 and len(base_nonce) == 12


def test_v3_suite_markers():
    assert relay_e2ee.HPKE_ALGORITHM == "hpke-auth-p256-hkdfsha256-aes256gcm"
    assert relay_e2ee.HPKE_KEY_VERSION == 3
    aad = relay_e2ee.key_aad("u", "c", "r")
    assert relay_e2ee._hpke_info(aad) == b"OpenBurnBar-HermesRelay-HPKE-v3|" + aad


# --- behaviour ---------------------------------------------------------------


@pytest.fixture
def parties():
    return relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()


@pytest.fixture
def content_key():
    return relay_e2ee.generate_symmetric_key()


def _aad() -> bytes:
    return relay_e2ee.key_aad("u-v3", "c-v3", "r-v3")


def _wrap(recipient, sender, content_key, aad=None):
    return relay_e2ee.wrap_symmetric_key_v3(
        content_key,
        recipient.public_key_base64(),
        aad if aad is not None else _aad(),
        sender_private=sender,
    )


def test_v3_round_trip(parties, content_key):
    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    opened = relay_e2ee.unwrap_symmetric_key_v3(
        wrap.enc,
        wrap.wrapped_key,
        recipient,
        aad,
        pinned_sender_public=sender.public_key_base64(),
    )
    assert opened == content_key


def test_v3_round_trip_accepts_relay_public_key_types(parties, content_key):
    """The helpers accept RelayPublicKey/RelayPrivateKey, not just base64."""
    recipient, sender = parties
    aad = _aad()
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        content_key,
        relay_e2ee.RelayPublicKey.from_base64(recipient.public_key_base64()),
        aad,
        sender_private=sender,
    )
    opened = relay_e2ee.unwrap_symmetric_key_v3(
        base64.b64decode(wrap.enc),  # raw bytes also accepted
        wrap.wrapped_key,
        recipient,
        aad,
        pinned_sender_public=relay_e2ee.RelayPublicKey.from_base64(
            sender.public_key_base64()
        ),
    )
    assert opened == content_key


def test_v3_wrap_envelope_shape(parties, content_key):
    recipient, sender = parties
    wrap = _wrap(recipient, sender, content_key)
    assert wrap.relay_key_version == relay_e2ee.HPKE_KEY_VERSION == 3
    assert wrap.relay_encryption == relay_e2ee.HPKE_ALGORITHM
    enc = base64.b64decode(wrap.enc)
    assert len(enc) == 65 and enc[0] == 0x04  # X9.63 uncompressed P-256 point
    ct = base64.b64decode(wrap.wrapped_key)
    assert len(ct) == 32 + 16  # AES-256-GCM over the 32-byte content key + tag


def test_v3_wrong_pinned_sender_raises_invalid_tag(parties, content_key):
    from cryptography.exceptions import InvalidTag

    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    wrong = relay_e2ee.generate_private_key()
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            wrap.enc,
            wrap.wrapped_key,
            recipient,
            aad,
            pinned_sender_public=wrong.public_key_base64(),
        )


def test_v3_wrong_recipient_raises_invalid_tag(parties, content_key):
    from cryptography.exceptions import InvalidTag

    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    wrong = relay_e2ee.generate_private_key()
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            wrap.enc,
            wrap.wrapped_key,
            wrong,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_wrong_aad_raises_invalid_tag(parties, content_key):
    from cryptography.exceptions import InvalidTag

    recipient, sender = parties
    wrap = _wrap(recipient, sender, content_key, _aad())
    other_aad = relay_e2ee.key_aad("u-other", "c-v3", "r-v3")
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            wrap.enc,
            wrap.wrapped_key,
            recipient,
            other_aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_mutated_enc_breaks_open(parties, content_key):
    """A well-formed but wrong ``enc`` yields a wrong shared secret -> InvalidTag."""
    from cryptography.exceptions import InvalidTag

    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    other = _wrap(recipient, sender, content_key, aad)  # fresh ephemeral -> diff enc
    assert other.enc != wrap.enc
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            other.enc,
            wrap.wrapped_key,
            recipient,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_corrupt_enc_point_raises(parties, content_key):
    """A non-point ``enc`` is rejected before any DH (fail closed)."""
    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    bad_enc = base64.b64encode(b"\x04" + b"\x00" * 64).decode("ascii")  # not on curve
    with pytest.raises(relay_e2ee.InvalidPublicKeyError):
        relay_e2ee.unwrap_symmetric_key_v3(
            bad_enc,
            wrap.wrapped_key,
            recipient,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_short_enc_raises(parties, content_key):
    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    with pytest.raises(relay_e2ee.InvalidCiphertextError):
        relay_e2ee.unwrap_symmetric_key_v3(
            base64.b64encode(b"\x04\x05\x06").decode("ascii"),
            wrap.wrapped_key,
            recipient,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_mutated_wrapped_key_raises_invalid_tag(parties, content_key):
    from cryptography.exceptions import InvalidTag

    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    raw = bytearray(base64.b64decode(wrap.wrapped_key))
    raw[0] ^= 0x01
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            wrap.enc,
            base64.b64encode(bytes(raw)).decode("ascii"),
            recipient,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_rejects_non_32_byte_content_key(parties):
    recipient, sender = parties
    with pytest.raises(relay_e2ee.InvalidSymmetricKeyError):
        relay_e2ee.wrap_symmetric_key_v3(
            b"\x00" * 31, recipient.public_key_base64(), _aad(), sender_private=sender
        )


def test_v2_wrap_is_not_openable_as_v3(parties, content_key):
    """A v2 envelope (no separate ``enc``) must fail closed on the v3 path."""
    recipient, sender = parties
    aad = _aad()
    v2_wrapped = relay_e2ee.wrap_symmetric_key(
        content_key, recipient.public_key_base64(), aad, sender_private=sender
    )
    # The v2 blob is 125 bytes; it is not a 65-byte HPKE enc, so v3 fails closed.
    with pytest.raises(relay_e2ee.RelayCryptoError):
        relay_e2ee.unwrap_symmetric_key_v3(
            v2_wrapped,
            v2_wrapped,
            recipient,
            aad,
            pinned_sender_public=sender.public_key_base64(),
        )


def test_v3_wrap_is_not_openable_as_v2(parties, content_key):
    """A v3 HPKE ciphertext is too short to be a v2 envelope -> fail closed."""
    recipient, sender = parties
    aad = _aad()
    wrap = _wrap(recipient, sender, content_key, aad)
    with pytest.raises(relay_e2ee.RelayCryptoError):
        relay_e2ee.unwrap_symmetric_key(
            wrap.wrapped_key,
            recipient,
            aad,
            sender_public_base64=sender.public_key_base64(),
        )
