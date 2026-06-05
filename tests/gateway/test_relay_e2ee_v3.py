"""v3 RFC 9180 HPKE Auth-mode known-answer tests for the gateway content-key wrap.

Three layers of proof:

1. **RFC conformance** — the production HPKE primitives in
   :mod:`gateway.crypto.relay_e2ee` reproduce the canonical RFC 9180 Appendix-A
   known-answer vector for the EXACT shipped suite (``mode_auth`` /
   DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM) byte-for-byte: the
   encapsulated key, the DHKEM shared secret, the key-schedule key + base nonce,
   and the AEAD ciphertext. This anchors the construction to the RFC text, not
   only to interop.
2. **Wire vector** — every slot of the committed
   ``HermesGatewayWireVectorV3.json`` unwraps + opens through the production
   path. That fixture is regenerated and byte-verified in-tree by
   ``tests/gateway/vectors/generate_wire_vectors.py`` (``--check``).
3. **Negative space** — wrong sender, wrong recipient, tampered AAD / ciphertext
   / ``enc``, a stripped ``enc``, and cross-version (v3<->v2/v1) confusion all
   raise. Cross-language parity with the Swift / Kotlin clients is maintained in
   those client repositories and is not re-proven here.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from gateway.crypto import relay_e2ee  # noqa: E402

_FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "HermesGatewayWireVectorV3.json"
)


# RFC 9180 Appendix-A known-answer vector for mode_auth / DHKEM(P-256, HKDF-SHA256)
# / HKDF-SHA256 / AES-256-GCM (the canonical CFRG test-vectors.json entry with
# kem_id=16, kdf_id=1, aead_id=2, mode=2). The RFC's own "Ode on a Grecian Urn"
# info + "Beauty is truth..." plaintext are used here to match the RFC bytes;
# the gateway uses its own info over the SAME construction.
_RFC9180_AUTH_P256_AES256_KAT = {
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "skEm": "7a6cb29fab4e249d1796f95645288a6504d2167c7ff463bc447ab6022462af42",
    "skRm": "d9f10996a02cd6c9dbda1d1f225f18f781ea3c893b8c2a6cb2e266e59f3cd9a9",
    "skSm": "6e7b14befe49443dc501def1cc2f0f293d9c5cfa045a23e9a2e0e7703b42705d",
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


def test_production_hpke_primitives_match_rfc9180_kat():
    """The production HPKE primitives reproduce the RFC 9180 Appendix-A vector."""
    v = {k: bytes.fromhex(s) for k, s in _RFC9180_AUTH_P256_AES256_KAT.items()}
    sk_e = ec.derive_private_key(int.from_bytes(v["skEm"], "big"), ec.SECP256R1())
    sk_r = ec.derive_private_key(int.from_bytes(v["skRm"], "big"), ec.SECP256R1())
    sk_s = ec.derive_private_key(int.from_bytes(v["skSm"], "big"), ec.SECP256R1())

    shared, enc = relay_e2ee._hpke_auth_encap(
        sk_r.public_key(), sk_s, ephemeral_private=sk_e
    )
    assert enc == v["enc"], "AuthEncap enc != RFC"
    assert shared == v["shared_secret"], "AuthEncap shared_secret != RFC"

    key, base_nonce = relay_e2ee._hpke_auth_key_schedule(shared, v["info"])
    assert key == v["key"], "KeySchedule key != RFC"
    assert base_nonce == v["base_nonce"], "KeySchedule base_nonce != RFC"

    assert AESGCM(key).encrypt(base_nonce, v["pt"], v["aad"]) == v["ct"], "Seal ct != RFC"

    shared_r = relay_e2ee._hpke_auth_decap(enc, sk_r, sk_s.public_key())
    assert shared_r == shared, "AuthDecap shared_secret != AuthEncap"


def test_suite_identifiers_are_the_shipped_suite():
    assert relay_e2ee.HPKE_KEY_VERSION == 3
    assert relay_e2ee.HPKE_ALGORITHM == "hpke-auth-p256-hkdfsha256-aes256gcm"
    assert relay_e2ee._HPKE_KEM_SUITE_ID == b"KEM\x00\x10"
    assert relay_e2ee._HPKE_SUITE_ID == b"HPKE\x00\x10\x00\x01\x00\x02"
    assert relay_e2ee._HPKE_AUTH_MODE == 0x02


@pytest.fixture(scope="module")
def v3_vector() -> dict:
    with _FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _open_slot(node: dict) -> bytes:
    return relay_e2ee.unwrap_symmetric_key_v3(
        node["enc"],
        node["wrappedKey"],
        relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
        node["keyAAD"].encode("utf-8"),
        pinned_sender_public=node["senderPublicKey"],
    )


def test_fixture_is_the_v3_contract(v3_vector):
    assert v3_vector["revision"] == "v3"
    assert v3_vector["keyVersion"] == 3
    assert v3_vector["algorithm"] == relay_e2ee.HPKE_ALGORITHM
    for slot in ("event", "message", "modelSwitch", "attachment"):
        node = v3_vector[slot]
        assert node["relayKeyVersion"] == 3, f"{slot} relayKeyVersion"
        assert node["relayEncryption"] == relay_e2ee.HPKE_ALGORITHM, f"{slot} relayEncryption"
        assert len(base64.b64decode(node["enc"])) == 65, f"{slot} enc must be 65B X9.63"
        assert base64.b64decode(node["enc"])[0] == 0x04, f"{slot} enc must be uncompressed"
        assert len(base64.b64decode(node["wrappedKey"])) == 48, f"{slot} wrappedKey must be 48B"


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch"])
def test_v3_unwrap_then_open_payload(v3_vector, slot):
    node = v3_vector[slot]
    sym = _open_slot(node)
    assert sym == base64.b64decode(node["symmetricKey"])
    plaintext = relay_e2ee.open_base64(
        node["payloadCiphertext"], sym, node["payloadAAD"].encode("utf-8")
    )
    assert plaintext == base64.b64decode(node["encodedPlaintext"])


def test_v3_attachment_unwraps_body_key_and_opens_manifest_and_body(v3_vector):
    node = v3_vector["attachment"]
    body_key = _open_slot(node)
    assert body_key == base64.b64decode(node["bodyKey"])
    manifest = relay_e2ee.open_base64(
        node["manifestCiphertext"], body_key, node["manifestAAD"].encode("utf-8")
    )
    assert manifest.decode("utf-8") == node["manifestPlaintext"]
    body = relay_e2ee.open_base64(
        node["bodyCiphertext"], body_key, node["bodyAAD"].encode("utf-8")
    )
    assert body.decode("utf-8") == node["bodyPlaintext"]


def test_v3_attachment_manifest_body_slot_swap_rejected(v3_vector):
    node = v3_vector["attachment"]
    body_key = _open_slot(node)
    # The manifest and body share the body key but are bound to DISTINCT AADs, so a
    # relay cannot swap the manifest ciphertext into the body slot (or vice versa).
    with pytest.raises(InvalidTag):
        relay_e2ee.open_base64(
            node["manifestCiphertext"], body_key, node["bodyAAD"].encode("utf-8")
        )
    with pytest.raises(InvalidTag):
        relay_e2ee.open_base64(
            node["bodyCiphertext"], body_key, node["manifestAAD"].encode("utf-8")
        )


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch", "attachment"])
def test_v3_wrong_pinned_sender_raises_invalid_tag(v3_vector, slot):
    node = v3_vector[slot]
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            node["enc"],
            node["wrappedKey"],
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["recipientPublicKey"],  # wrong (not the sender)
        )


@pytest.mark.parametrize("slot", ["event", "message", "modelSwitch", "attachment"])
def test_v3_wrong_recipient_raises_invalid_tag(v3_vector, slot):
    node = v3_vector[slot]
    wrong_recipient = relay_e2ee.generate_private_key()
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            node["enc"],
            node["wrappedKey"],
            wrong_recipient,
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_tampered_aad_raises_invalid_tag(v3_vector):
    node = v3_vector["event"]
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            node["enc"],
            node["wrappedKey"],
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8") + b"X",  # tampered AAD -> info + aad change
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_tampered_ciphertext_raises_invalid_tag(v3_vector):
    node = v3_vector["event"]
    bad = bytearray(base64.b64decode(node["wrappedKey"]))
    bad[0] ^= 0x01
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            node["enc"],
            base64.b64encode(bytes(bad)).decode("ascii"),
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_tampered_enc_is_rejected(v3_vector):
    node = v3_vector["event"]
    bad = bytearray(base64.b64decode(node["enc"]))
    bad[40] ^= 0x01  # perturb the encapsulated key
    with pytest.raises((InvalidTag, relay_e2ee.InvalidPublicKeyError, ValueError)):
        relay_e2ee.unwrap_symmetric_key_v3(
            base64.b64encode(bytes(bad)).decode("ascii"),
            node["wrappedKey"],
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_substituted_valid_enc_raises_invalid_tag(v3_vector):
    """A different *on-curve* encapsulated key (not just an off-curve perturbation)
    yields a different DHKEM shared secret -> InvalidTag, distinct from the
    point-parse rejection in `test_v3_tampered_enc_is_rejected`."""
    node = v3_vector["event"]
    other_enc = relay_e2ee.generate_private_key().public_key_base64()  # valid P-256 point
    with pytest.raises(InvalidTag):
        relay_e2ee.unwrap_symmetric_key_v3(
            other_enc,
            node["wrappedKey"],
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_wrong_length_enc_is_rejected(v3_vector):
    node = v3_vector["event"]
    with pytest.raises(relay_e2ee.InvalidCiphertextError):
        relay_e2ee.unwrap_symmetric_key_v3(
            base64.b64encode(b"\x04" + b"\x00" * 32).decode("ascii"),  # 33B, not 65B
            node["wrappedKey"],
            relay_e2ee.RelayPrivateKey.from_base64(node["recipientPrivateKey"]),
            node["keyAAD"].encode("utf-8"),
            pinned_sender_public=node["senderPublicKey"],
        )


def test_v3_round_trip_with_fresh_keys():
    recipient = relay_e2ee.generate_private_key()
    sender = relay_e2ee.generate_private_key()
    content_key = relay_e2ee.generate_symmetric_key()
    aad = relay_e2ee.key_aad("u", "c", "r")
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        content_key, recipient.public_key_base64(), aad, sender_private=sender
    )
    assert wrap.relay_key_version == 3
    assert wrap.relay_encryption == relay_e2ee.HPKE_ALGORITHM
    opened = relay_e2ee.unwrap_symmetric_key_v3(
        wrap.enc, wrap.wrapped_key, recipient, aad,
        pinned_sender_public=sender.public_key_base64(),
    )
    assert opened == content_key


def test_v3_wrap_does_not_open_under_v2_unwrap():
    """A v3 HPKE wrap must NOT open under the v2 2-DH unwrap (cross-version safety)."""
    recipient = relay_e2ee.generate_private_key()
    sender = relay_e2ee.generate_private_key()
    content_key = relay_e2ee.generate_symmetric_key()
    aad = relay_e2ee.key_aad("u", "c", "r")
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        content_key, recipient.public_key_base64(), aad, sender_private=sender
    )
    # The v2 unwrap expects base64(enc(65) ‖ nonce(12) ‖ ct ‖ tag) as a single
    # field; feeding it the v3 wrappedKey (48B, no enc prefix) must fail closed.
    with pytest.raises((InvalidTag, relay_e2ee.InvalidCiphertextError, relay_e2ee.InvalidPublicKeyError)):
        relay_e2ee.unwrap_symmetric_key(
            wrap.wrapped_key, recipient, aad,
            sender_public_base64=sender.public_key_base64(),
        )


def test_v2_wrap_does_not_open_under_v3_unwrap():
    """The reverse: a v2 wrap must NOT open under the v3 HPKE opener."""
    recipient = relay_e2ee.generate_private_key()
    sender = relay_e2ee.generate_private_key()
    content_key = relay_e2ee.generate_symmetric_key()
    aad = relay_e2ee.key_aad("u", "c", "r")
    wrapped_v2 = relay_e2ee.wrap_symmetric_key(
        content_key, recipient.public_key_base64(), aad, sender_private=sender
    )
    # Split the v2 envelope into a v3-shaped (enc, wrappedKey) and try the v3 open.
    envelope = base64.b64decode(wrapped_v2)
    enc, body = envelope[:65], envelope[65:]
    with pytest.raises((InvalidTag, relay_e2ee.InvalidCiphertextError)):
        relay_e2ee.unwrap_symmetric_key_v3(
            enc, body, recipient, aad, pinned_sender_public=sender.public_key_base64()
        )
