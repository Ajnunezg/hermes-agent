"""v5 hybrid-KEM relay crypto tests."""

from __future__ import annotations

import base64

import pytest

try:
    from gateway.crypto import relay_e2ee_v4 as v4
    from gateway.crypto import relay_e2ee_v5 as v5

    RELAY_V5_AVAILABLE = v5.is_supported()
except ImportError:  # pragma: no cover
    v4 = None
    v5 = None
    RELAY_V5_AVAILABLE = False


requires_v5 = pytest.mark.skipif(
    not RELAY_V5_AVAILABLE,
    reason="cryptography HPKE MLKEM768_X25519 unavailable",
)


def _keys():
    return {
        "agent_kem": v5.generate_kem_private_key(),
        "phone_kem": v5.generate_kem_private_key(),
        "agent_sig": v4.generate_signing_key(),
        "phone_sig": v4.generate_signing_key(),
    }


@requires_v5
def test_xwing_draft_10_deterministic_public_key_kat():
    seed = bytes.fromhex("ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9")
    expected_public = bytes.fromhex(
        "36244278824f77c621c660892c1c3886a9560caa52a97c461fd3958a598e749bbc8c7798ac8870bac7318ac2b863000c"
        "a3b0bdcbbc1ccfcb1a30875df9a76976763247083e646ccb2499a4e4f0c9f4125378ba3da1999538b86f99f2328332c1"
        "77d1192b849413e65510128973f679d23253850bb6c347ba7ca81b5e6ac4c574565c731740b3cd8c9756caac39fba7ac"
        "422acc60c6c1a645b94e3b6d21485ebad9c4fe5bb4ea0853670c5246652bff65ce8381cb473c40c1a0cd06b54dcec118"
        "72b351397c0eaf995bebdb6573000cbe2496600ba76c8cb023ec260f0571e3ec12a9c82d9db3c57b3a99e8701f78db4f"
        "abc1cc58b1bae02745073a81fc8045439ba3b885581a283a1ba64e103610aabb4ddfe9959e7241011b2638b56ba6a982"
        "ef610c514a57212555db9a98fb6bcf0e91660ec15dfa66a67408596e9ccb97489a09a073ffd1a0a7ebbe71aa5ff793cb"
        "91964160703b4b6c9c5390842c2c905d4a9f88111fed57874ba9b03cf611e70486edf539767c7485189d5f1b08e32a27"
        "4dc24a39c918fd2a4dfa946a8c897486f2c974031b2804aabc81749db430b85311372a3b8478868200b40e043f7bf4a1"
        "c3a08b0771b431e342ee277410bca034a0c77086c8f702b3aed2b4108bbd3af471633373a1ac74b128b148d1b9412aa6"
        "6948cac6dc6614681fda02ca86675d2a756003c49c50f06e13c63ce4bc9f321c860b202ee931834930011f485c9af86b"
        "9f642f0c353ad305c66996b9a136b753973929495f0d8048db75529edcb4935904797ac66605490f66329c3bb36b8573"
        "a3e00f817b3082162ff106674d11b261baae0506cde7e69fdce93c6c7b59b9d4c759758acf287c2e4c4bfab5170a9236"
        "daf21bdb6005e92464ee8863f845cf37978ef19969264a516fe992c93b5f7ae7cb6718ac69257d630379e4aac6029cb9"
        "06f98d91c92d118c36a6d16115d4c8f16066078badd161a65ba51e0252bc358c67cd2c4beab2537e42956e08a39cfccf"
        "0cd875b5499ee952c83a162c68084f6d35cf92f71ec66baec74ab87e2243160b64df54afb5a07f78ec0f5c5759e5a432"
        "2bca2643425748a1a97c62108510c44fd9089c5a7c14e57b1b77532800013027cff91922d7c935b4202bb507aa47598a"
        "6a5a030117210d4c49c174700550ad6f82ad40e965598b86bc575448eb19d70380d465c1f870824c026d74a2522a799b"
        "7b122d06c83aa64c0974635897261433914fdfb14106c230425a83dc8467ad8234f086c72a47418be9cfb582b1dcfa3d"
        "9aa45299b79fff265356d8286a1ca2f3c2184b2a70d15289e5b202d03b64c735a867b1154c55533ff61d6c2962770118"
        "48143bc85a4b823040ae025a29293ab77747d85310078682e0ba0ac236548d905a79494324574d417c7a3457bd5fb525"
        "3c4876679034ae844d0d05010fec722db5621e3a67a2d58e2ff33b432269169b51f9dcc095b8406dc1864cf0aeb6a213"
        "2661a38d641877594b3c51892b9364d25c63d637140a2018d10931b0daa5a2f2a405017688c991e586b522f94b1132bc"
        "7e87a63246475816c8be9c62b731691ab912eb656ce2619225663364701a014b7d0337212caa2ecc731f34438289e0ca"
        "4590a276802d980056b5d0d316cae2ecfea6d86696a9f161aa90ad47eaad8cadd31ae3cbc1c013747dfee80fb35b5299"
        "f555dcc2b787ea4f6f16ffdf66952461"
    )
    private_key = v5.RelayKemPrivateKey.from_raw(seed)
    assert private_key.public_key_bytes() == expected_public
    assert private_key.public_key().key_id() == v5.kem_key_id(expected_public)


@requires_v5
def test_v5_signed_round_trip():
    k = _keys()
    env = v5.seal_signed_v5(
        b"hello v5",
        recipient_kem_public=k["agent_kem"].public_key(),
        recipient_verify_key=k["agent_sig"].public_key_base64(),
        sender_signing_key=k["phone_sig"],
        key_aad=b"key-aad",
        payload_aad=b"payload-aad",
    )
    assert env.relay_key_version == 5
    assert env.relay_encryption == v5.RELAY_ENCRYPTION_V5
    assert v5.open_signed_v5(
        env,
        recipient_kem_private=k["agent_kem"],
        recipient_verify_key=k["agent_sig"].public_key_base64(),
        pinned_sender_verify_key=k["phone_sig"].public_key_base64(),
        key_aad=b"key-aad",
        payload_aad=b"payload-aad",
    ) == b"hello v5"


@requires_v5
def test_v5_wire_sizes_and_markers():
    k = _keys()
    wrap = v5.wrap_symmetric_key_v5(b"k" * 32, k["agent_kem"].public_key(), b"aad")
    assert wrap.relay_key_version == 5
    assert wrap.relay_encryption == v5.RELAY_ENCRYPTION_V5
    assert len(base64.b64decode(wrap.enc)) == 1120
    assert len(base64.b64decode(wrap.wrapped_key)) == 48
    assert len(k["agent_kem"].public_key_bytes()) == 1216


@requires_v5
def test_v5_recipient_kem_key_holder_cannot_forge_without_signing_key():
    k = _keys()
    attacker_sig = v4.generate_signing_key()
    env = v5.seal_signed_v5(
        b"forged",
        recipient_kem_public=k["agent_kem"].public_key(),
        recipient_verify_key=k["agent_sig"].public_key_base64(),
        sender_signing_key=attacker_sig,
        key_aad=b"key-aad",
        payload_aad=b"payload-aad",
    )
    with pytest.raises(v5.RelayV5SignatureError):
        v5.open_signed_v5(
            env,
            recipient_kem_private=k["agent_kem"],
            recipient_verify_key=k["agent_sig"].public_key_base64(),
            pinned_sender_verify_key=k["phone_sig"].public_key_base64(),
            key_aad=b"key-aad",
            payload_aad=b"payload-aad",
        )


@requires_v5
@pytest.mark.parametrize("field", ["enc", "wrappedKey", "payloadCiphertext", "senderSig"])
def test_v5_tamper_matrix_rejected(field):
    k = _keys()
    env = v5.seal_signed_v5(
        b"tamper me",
        recipient_kem_public=k["agent_kem"].public_key(),
        recipient_verify_key=k["agent_sig"].public_key_base64(),
        sender_signing_key=k["phone_sig"],
        key_aad=b"key-aad",
        payload_aad=b"payload-aad",
    )
    wire = {
        "enc": env.enc,
        "wrappedKey": env.wrapped_key,
        "payloadCiphertext": env.payload_ciphertext,
        "senderSig": env.sender_sig,
    }
    raw = bytearray(base64.b64decode(wire[field]))
    raw[0] ^= 0x01
    wire[field] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(Exception):
        v5.open_signed_v5(
            wire,
            recipient_kem_private=k["agent_kem"],
            recipient_verify_key=k["agent_sig"].public_key_base64(),
            pinned_sender_verify_key=k["phone_sig"].public_key_base64(),
            key_aad=b"key-aad",
            payload_aad=b"payload-aad",
        )


@requires_v5
def test_v5_transcript_is_domain_separated_from_v4():
    k = _keys()
    env = v5.seal_signed_v5(
        b"domain separated",
        recipient_kem_public=k["agent_kem"].public_key(),
        recipient_verify_key=k["agent_sig"].public_key_base64(),
        sender_signing_key=k["phone_sig"],
        key_aad=b"key-aad",
        payload_aad=b"payload-aad",
    )
    with pytest.raises(v5.RelayV5SignatureError):
        # Same envelope, wrong pinned sender signing key. This catches accidental
        # transcript reuse that does not bind the v5 sender verification key.
        v5.open_signed_v5(
            env,
            recipient_kem_private=k["agent_kem"],
            recipient_verify_key=k["agent_sig"].public_key_base64(),
            pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
            key_aad=b"key-aad",
            payload_aad=b"payload-aad",
        )


@requires_v5
def test_v5_safety_code_changes_when_kem_key_changes():
    a_enc = b"a" * 65
    b_enc = b"b" * 65
    a_sig = b"c" * 32
    b_sig = b"d" * 32
    a_kem = v5.generate_kem_private_key().public_key_bytes()
    b_kem = v5.generate_kem_private_key().public_key_bytes()
    other_b_kem = v5.generate_kem_private_key().public_key_bytes()
    code = v4.relay_safety_code_v4(
        self_keys=[
            (v4.PAIRING_TAG_ENCRYPTION, a_enc),
            (v4.PAIRING_TAG_SIGNING, a_sig),
            (v4.PAIRING_TAG_KEM, a_kem),
        ],
        peer_keys=[
            (v4.PAIRING_TAG_ENCRYPTION, b_enc),
            (v4.PAIRING_TAG_SIGNING, b_sig),
            (v4.PAIRING_TAG_KEM, b_kem),
        ],
    )
    changed = v4.relay_safety_code_v4(
        self_keys=[
            (v4.PAIRING_TAG_ENCRYPTION, a_enc),
            (v4.PAIRING_TAG_SIGNING, a_sig),
            (v4.PAIRING_TAG_KEM, a_kem),
        ],
        peer_keys=[
            (v4.PAIRING_TAG_ENCRYPTION, b_enc),
            (v4.PAIRING_TAG_SIGNING, b_sig),
            (v4.PAIRING_TAG_KEM, other_b_kem),
        ],
    )
    assert code != changed
