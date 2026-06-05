"""v4 relay-hardening tests: explicit Ed25519 authentication (KCI resistance),
Padmé length padding, all-key pairing safety code, key-id selectors, and
authenticated key rotation.

Correctness anchors:
* The Ed25519 primitive is validated against the **RFC 8032 Section 7.1**
  known-answer vectors (the production signing key reproduces the RFC's public
  key and signature byte-for-byte).
* The signed-envelope path proves the headline property — a holder of the
  *recipient* static key (the KCI threat) still cannot forge a sender — and the
  full tamper/forgery matrix.
* Padmé is checked against the paper's anchor points and the ``<=~12%`` overhead
  bound; the rotation event against its replay / window / wrong-signer space.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")

from gateway.crypto import relay_e2ee  # noqa: E402
from gateway.crypto import relay_e2ee_v4 as v4  # noqa: E402


# ---------------------------------------------------------------------------
# RFC 8032 Section 7.1 Ed25519 known-answer vectors
# ---------------------------------------------------------------------------

_RFC8032_ED25519 = [
    {
        "sk": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pk": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "sk": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "72",
        "sig": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
]


@pytest.mark.parametrize("vec", _RFC8032_ED25519)
def test_ed25519_matches_rfc8032(vec):
    sk = v4.RelaySigningKey(bytes.fromhex(vec["sk"]))
    assert sk.public_key_raw() == bytes.fromhex(vec["pk"]), "derived public key != RFC 8032"
    msg = bytes.fromhex(vec["msg"])
    assert sk.sign(msg) == bytes.fromhex(vec["sig"]), "signature != RFC 8032"
    # The pinned verify key accepts the RFC signature and rejects a flipped one.
    vk = v4.RelayVerifyKey(bytes.fromhex(vec["pk"]))
    vk.verify(bytes.fromhex(vec["sig"]), msg)
    bad = bytearray(bytes.fromhex(vec["sig"]))
    bad[0] ^= 0x01
    with pytest.raises(v4.RelayV4SignatureError):
        vk.verify(bytes(bad), msg)


# ---------------------------------------------------------------------------
# Signed envelope: round trip + KCI resistance + tamper/forgery matrix
# ---------------------------------------------------------------------------


@pytest.fixture
def keys():
    return {
        "agent_enc": relay_e2ee.generate_private_key(),
        "phone_enc": relay_e2ee.generate_private_key(),
        "agent_sig": v4.generate_signing_key(),
        "phone_sig": v4.generate_signing_key(),
        "key_aad": relay_e2ee.key_aad("u", "c", "req"),
        "payload_aad": relay_e2ee.request_aad("u", "c", "req"),
    }


def _seal(keys, text=b'{"text":"hi"}'):
    return v4.seal_signed_v4(
        text,
        recipient_enc_public=keys["phone_enc"].public_key_base64(),
        recipient_verify_key=keys["phone_sig"].public_key_base64(),
        sender_enc_private=keys["agent_enc"],
        sender_signing_key=keys["agent_sig"],
        key_aad=keys["key_aad"],
        payload_aad=keys["payload_aad"],
    )


def _open(keys, env, **over):
    kw = dict(
        recipient_enc_private=keys["phone_enc"],
        recipient_verify_key=keys["phone_sig"].public_key_base64(),
        pinned_sender_enc_public=keys["agent_enc"].public_key_base64(),
        pinned_sender_verify_key=keys["agent_sig"].public_key_base64(),
        key_aad=keys["key_aad"],
        payload_aad=keys["payload_aad"],
    )
    kw.update(over)
    return v4.open_signed_v4(env, **kw)


def test_v4_signed_round_trip(keys):
    env = _seal(keys)
    assert env.relay_key_version == 4
    assert env.relay_encryption == v4.RELAY_ENCRYPTION_V4
    assert _open(keys, env) == b'{"text":"hi"}'


def test_v4_kci_recipient_key_holder_cannot_forge(keys):
    """The headline remediation: a holder of the RECIPIENT static private key
    (the KCI threat) builds a valid HPKE wrap but lacks the agent's Ed25519
    signing key, so open_signed_v4 rejects it on the signature."""
    attacker_sig = v4.generate_signing_key()
    forged = v4.seal_signed_v4(
        b'{"text":"forged as agent"}',
        recipient_enc_public=keys["phone_enc"].public_key_base64(),
        recipient_verify_key=keys["phone_sig"].public_key_base64(),
        sender_enc_private=keys["phone_enc"],  # the compromised recipient key
        sender_signing_key=attacker_sig,       # NOT the agent's signing key
        key_aad=keys["key_aad"],
        payload_aad=keys["payload_aad"],
    )
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, forged)  # pinned to the REAL agent verify key


def test_v4_wrong_pinned_verify_key_rejected(keys):
    env = _seal(keys)
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, env, pinned_sender_verify_key=v4.generate_signing_key().public_key_base64())


def test_v4_tampered_payload_rejected_by_signature(keys):
    import base64

    env = _seal(keys)
    raw = bytearray(base64.b64decode(env.payload_ciphertext))
    raw[-1] ^= 0x01
    bad = {
        "enc": env.enc,
        "wrappedKey": env.wrapped_key,
        "payloadCiphertext": base64.b64encode(bytes(raw)).decode(),
        "senderSig": env.sender_sig,
    }
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, bad)


def test_v4_tampered_wrapped_key_rejected(keys):
    import base64

    env = _seal(keys)
    raw = bytearray(base64.b64decode(env.wrapped_key))
    raw[0] ^= 0x01
    bad = {
        "enc": env.enc,
        "wrappedKey": base64.b64encode(bytes(raw)).decode(),
        "payloadCiphertext": env.payload_ciphertext,
        "senderSig": env.sender_sig,
    }
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, bad)


@pytest.mark.parametrize("field", ["key_aad", "payload_aad"])
def test_v4_tampered_aad_rejected(keys, field):
    env = _seal(keys)
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, env, **{field: keys[field] + b"X"})


def test_v4_missing_signature_rejected(keys):
    env = _seal(keys)
    bad = {
        "enc": env.enc,
        "wrappedKey": env.wrapped_key,
        "payloadCiphertext": env.payload_ciphertext,
        "senderSig": "",
    }
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, bad)


def test_v4_recipient_enc_binding_rejects_wrong_recipient(keys):
    """A frame's recipient P-256 enc key is bound into the signed transcript, so
    opening as a different recipient fails the signature (recipient binding)."""
    env = _seal(keys)
    wrong_recipient = relay_e2ee.generate_private_key()
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, env, recipient_enc_private=wrong_recipient)


def test_v4_aead_is_independently_required_and_not_or(keys):
    """A genuine AND-not-OR: a sender wraps content key K1 but seals the payload
    under a DIFFERENT key K2, then signs a correct transcript over those bytes.
    The signature verifies, but the recipient unwraps K1 and the AES-GCM payload
    open under K1 fails — proving the AEAD layer is independently required."""
    import base64

    k1 = relay_e2ee.generate_symmetric_key()
    k2 = relay_e2ee.generate_symmetric_key()
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        k1, keys["phone_enc"].public_key_base64(), keys["key_aad"],
        sender_private=keys["agent_enc"],
    )
    payload_ct = relay_e2ee.seal_to_base64(v4.padme_pad(b"mismatch"), k2, keys["payload_aad"])
    transcript = v4.relay_signing_transcript(
        sender_verify_key=keys["agent_sig"].public_key_raw(),
        recipient_verify_key=keys["phone_sig"].public_key_raw(),
        recipient_enc_x963=keys["phone_enc"].public_key_x963(),
        key_aad=keys["key_aad"], raw_enc=base64.b64decode(wrap.enc),
        raw_wrapped_key=base64.b64decode(wrap.wrapped_key), payload_aad=keys["payload_aad"],
        raw_payload_seal=base64.b64decode(payload_ct),
    )
    env = {
        "enc": wrap.enc, "wrappedKey": wrap.wrapped_key, "payloadCiphertext": payload_ct,
        "senderSig": base64.b64encode(keys["agent_sig"].sign(transcript)).decode(),
    }
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):  # signature passed; AEAD open under K1 fails
        _open(keys, env)


def test_v4_cannot_be_re_targeted_to_another_recipient(keys):
    """Davis surreptitious-forwarding: a frame sealed+signed for phone1 cannot be
    re-presented to a phone2 with a different identity key — the recipient verify
    key is bound into the transcript, so phone2's open fails the signature."""
    env = _seal(keys)
    phone2_sig = v4.generate_signing_key()
    with pytest.raises(v4.RelayV4SignatureError):
        _open(keys, env, recipient_verify_key=phone2_sig.public_key_base64())


def test_v4_transcript_is_length_prefixed_and_deterministic():
    """The signed transcript is byte-deterministic (a cross-language KAT surface)
    and injective in its fields (length-prefixed, no '|' re-segmentation)."""
    base = dict(
        sender_verify_key=b"\x01" * 32, recipient_verify_key=b"\x02" * 32,
        recipient_enc_x963=b"\x04" + b"\x00" * 64, key_aad=b"ka", raw_enc=b"e",
        raw_wrapped_key=b"w", payload_aad=b"pa", raw_payload_seal=b"p",
    )
    assert v4.relay_signing_transcript(**base) == v4.relay_signing_transcript(**base)
    assert v4.relay_signing_transcript(**base).startswith(v4._SIG_LABEL)
    # Moving a byte across the key_aad/raw_enc boundary changes the transcript.
    a = v4.relay_signing_transcript(**{**base, "key_aad": b"kaX", "raw_enc": b"e"})
    b = v4.relay_signing_transcript(**{**base, "key_aad": b"ka", "raw_enc": b"Xe"})
    assert a != b
    # Moving a byte across the enc/wrappedKey boundary changes the transcript.
    c = v4.relay_signing_transcript(**{**base, "raw_enc": b"ee", "raw_wrapped_key": b""})
    d = v4.relay_signing_transcript(**{**base, "raw_enc": b"e", "raw_wrapped_key": b"e"})
    assert c != d


def test_v4_chunk_transcript_is_domain_separated_from_payload():
    """The chunk transcript uses a distinct label so a payload signature can never
    be replayed as a chunk signature (cross-object replay resistance)."""
    chunk = v4.relay_chunk_signing_transcript(
        sender_verify_key=b"\x01" * 32, recipient_verify_key=b"\x02" * 32,
        chunk_aad=b"ca", raw_chunk_seal=b"cs",
    )
    assert chunk == v4.relay_chunk_signing_transcript(
        sender_verify_key=b"\x01" * 32, recipient_verify_key=b"\x02" * 32,
        chunk_aad=b"ca", raw_chunk_seal=b"cs",
    )
    assert chunk.startswith(v4._CHUNK_SIG_LABEL)
    assert not chunk.startswith(v4._SIG_LABEL)


# ---------------------------------------------------------------------------
# Padmé length padding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length,expected", [(1, 1), (2, 2), (9, 10), (88, 88), (100, 104), (1000, 1024)])
def test_padme_length_table(length, expected):
    assert v4.padme_padded_len(length) == expected


def test_padme_round_trip_and_zeroing():
    for n in [0, 1, 4, 5, 30, 101, 200, 1000, 5000]:
        content = os.urandom(n)
        padded = v4.padme_pad(content)
        assert v4.padme_unpad(padded) == content
        # padding region (if any) is all zero
        assert all(b == 0 for b in padded[4 + n:])


def test_padme_overhead_bound():
    worst = 0.0
    for n in range(0, 4096):
        padded = v4.padme_pad(b"\x00" * n)
        worst = max(worst, (len(padded) - (n + 4)) / max(n + 4, 1))
    assert worst < 0.12, f"Padmé overhead {worst:.3f} exceeds ~12%"


def test_padme_rejects_nonzero_pad():
    content = os.urandom(101)  # body 105 -> padded 112 (7 pad bytes)
    padded = bytearray(v4.padme_pad(content))
    assert len(padded) == 112
    padded[-1] = 0x01
    with pytest.raises(relay_e2ee.InvalidCiphertextError):
        v4.padme_unpad(bytes(padded))


def test_padme_rejects_overlong_declared_length():
    padded = bytearray(v4.padme_pad(os.urandom(10)))
    padded[:4] = (10_000).to_bytes(4, "big")  # claim more content than present
    with pytest.raises(relay_e2ee.InvalidCiphertextError):
        v4.padme_unpad(bytes(padded))


# ---------------------------------------------------------------------------
# All-key pairing safety code
# ---------------------------------------------------------------------------


def _keyset(enc, sig):
    return [
        (v4.PAIRING_TAG_ENCRYPTION, enc.public_key_x963()),
        (v4.PAIRING_TAG_SIGNING, sig.public_key_raw()),
    ]


def test_safety_code_is_role_free_and_128_bit():
    a_enc, b_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    a_sig, b_sig = v4.generate_signing_key(), v4.generate_signing_key()
    a, b = _keyset(a_enc, a_sig), _keyset(b_enc, b_sig)
    code = v4.relay_safety_code_v4(self_keys=a, peer_keys=b)
    assert code == v4.relay_safety_code_v4(self_keys=b, peer_keys=a)  # role-free
    assert len(code.replace(" ", "")) == 32  # 128-bit


def test_safety_code_binds_every_key_class():
    a_enc, b_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    a_sig, b_sig = v4.generate_signing_key(), v4.generate_signing_key()
    full = v4.relay_safety_code_v4(self_keys=_keyset(a_enc, a_sig), peer_keys=_keyset(b_enc, b_sig))
    enc_only = v4.relay_safety_code_v4(
        self_keys=[(v4.PAIRING_TAG_ENCRYPTION, a_enc.public_key_x963())],
        peer_keys=[(v4.PAIRING_TAG_ENCRYPTION, b_enc.public_key_x963())],
    )
    # Adding the signing key MUST change the code (else a relay substitutes it freely).
    assert full != enc_only
    # Substituting one signing key changes the code.
    other_sig = v4.generate_signing_key()
    assert full != v4.relay_safety_code_v4(
        self_keys=_keyset(a_enc, other_sig), peer_keys=_keyset(b_enc, b_sig)
    )


# ---------------------------------------------------------------------------
# Key-id selectors + authenticated rotation
# ---------------------------------------------------------------------------


def test_key_id_is_stable_128_bit_selector():
    enc = relay_e2ee.generate_private_key()
    kid = v4.relay_key_id(enc.public_key_x963())
    assert len(kid) == 32 and kid == v4.relay_key_id(enc.public_key_x963())
    assert kid != v4.relay_key_id(relay_e2ee.generate_private_key().public_key_x963())


def _rotation(identity_sig, old_enc, new_enc, **over):
    kw = dict(
        uid="u", client_id="c", from_epoch=0, to_epoch=1,
        old_enc_x963=old_enc.public_key_x963(), new_enc_x963=new_enc.public_key_x963(),
        not_before_ms=1000, not_after_ms=2000, rotation_nonce=b"\x11" * 32,
    )
    kw.update(over)
    body = v4.build_rotation_signed_body(**kw)
    return body, identity_sig.sign(body)


def test_rotation_event_round_trip():
    sig = v4.generate_signing_key()
    old_enc, new_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    body, signature = _rotation(sig, old_enc, new_enc)
    got = v4.verify_rotation_event(
        body, signature, pinned_identity_verify_key=sig.public_key_base64(),
        expected_uid="u", expected_client_id="c", current_epoch=0, now_ms=1500,
    )
    assert got == new_enc.public_key_x963()


def test_rotation_event_rejects_replay_window_signer_channel():
    sig = v4.generate_signing_key()
    old_enc, new_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    body, signature = _rotation(sig, old_enc, new_enc)
    base = dict(
        pinned_identity_verify_key=sig.public_key_base64(),
        expected_uid="u", expected_client_id="c", current_epoch=0, now_ms=1500,
    )
    # replayed (already advanced past epoch 0)
    with pytest.raises(v4.RelayV4RotationError):
        v4.verify_rotation_event(body, signature, **{**base, "current_epoch": 1})
    # outside validity window
    with pytest.raises(v4.RelayV4RotationError):
        v4.verify_rotation_event(body, signature, **{**base, "now_ms": 9999})
    # wrong channel
    with pytest.raises(v4.RelayV4RotationError):
        v4.verify_rotation_event(body, signature, **{**base, "expected_uid": "other"})
    # wrong signer (not the pinned identity)
    with pytest.raises(v4.RelayV4SignatureError):
        v4.verify_rotation_event(
            body, signature, **{**base, "pinned_identity_verify_key": v4.generate_signing_key().public_key_base64()}
        )


def test_rotation_body_requires_monotonic_epoch():
    sig = v4.generate_signing_key()
    old_enc, new_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    with pytest.raises(v4.RelayV4RotationError):
        v4.build_rotation_signed_body(
            uid="u", client_id="c", from_epoch=0, to_epoch=2,  # skip
            old_enc_x963=old_enc.public_key_x963(), new_enc_x963=new_enc.public_key_x963(),
            not_before_ms=1, not_after_ms=2, rotation_nonce=b"\x11" * 32,
        )


def test_rotation_rejects_before_validity_window():
    sig = v4.generate_signing_key()
    old_enc, new_enc = relay_e2ee.generate_private_key(), relay_e2ee.generate_private_key()
    body, signature = _rotation(sig, old_enc, new_enc)  # window [1000, 2000]
    with pytest.raises(v4.RelayV4RotationError):
        v4.verify_rotation_event(
            body, signature, pinned_identity_verify_key=sig.public_key_base64(),
            expected_uid="u", expected_client_id="c", current_epoch=0, now_ms=500,  # before window
        )


def test_rotation_key_id_is_selector_only_not_authoritative():
    """A signed body whose embedded successor key-id does NOT match the carried
    key is rejected — the key-id is a selector, never trusted to introduce a key."""
    sig = v4.generate_signing_key()
    old_enc = relay_e2ee.generate_private_key()
    real_new = relay_e2ee.generate_private_key()
    decoy = relay_e2ee.generate_private_key()
    # Hand-build a body whose carried new_enc is `real_new` but with `decoy`'s key-id.
    body = (
        v4._ROTATION_LABEL
        + v4._lp(b"u") + v4._lp(b"c")
        + (0).to_bytes(8, "big") + (1).to_bytes(8, "big")
        + v4._lp(v4.relay_key_id(old_enc.public_key_x963()).encode("ascii"))
        + v4._lp(v4.relay_key_id(decoy.public_key_x963()).encode("ascii"))  # MISMATCH
        + v4._lp(real_new.public_key_x963())
        + (1000).to_bytes(8, "big") + (2000).to_bytes(8, "big")
        + v4._lp(b"\x11" * 32)
    )
    signature = sig.sign(body)  # validly signed by the pinned identity
    with pytest.raises(v4.RelayV4RotationError):
        v4.verify_rotation_event(
            body, signature, pinned_identity_verify_key=sig.public_key_base64(),
            expected_uid="u", expected_client_id="c", current_epoch=0, now_ms=1500,
        )
