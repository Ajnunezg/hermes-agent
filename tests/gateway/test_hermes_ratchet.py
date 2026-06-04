"""Focused tests for the Python HermesRatchet v1 mirror."""

from __future__ import annotations

import base64
import hmac
from hashlib import sha256

import pytest

pytest.importorskip("cryptography")

from gateway.crypto import hermes_ratchet as ratchet  # noqa: E402


def _fixed_pair(scalar: int) -> ratchet.HermesRatchetKeyPair:
    private = scalar.to_bytes(32, "big")
    key = ratchet._private_key_from_raw(private)
    return ratchet.HermesRatchetKeyPair(
        private_key_base64=base64.b64encode(private).decode("ascii"),
        public_key_base64=base64.b64encode(ratchet._public_key_x963(key.public_key())).decode("ascii"),
    )


def _states(max_skip: int = ratchet.DEFAULT_MAX_SKIP):
    shared = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    initiator_initial = _fixed_pair(3)
    responder_initial = _fixed_pair(5)
    initiator = ratchet.initiator_state(
        session_id="session-alpha",
        local_device_id="agent-device",
        remote_device_id="phone-device",
        shared_secret=shared,
        remote_initial_ratchet_public_key_base64=responder_initial.public_key_base64,
        local_initial_ratchet_key_pair=initiator_initial,
        max_skip=max_skip,
    )
    responder = ratchet.responder_state(
        session_id="session-alpha",
        local_device_id="phone-device",
        remote_device_id="agent-device",
        shared_secret=shared,
        local_initial_ratchet_key_pair=responder_initial,
        max_skip=max_skip,
    )
    return initiator, responder


def test_known_aad_and_initial_kdf_vector(monkeypatch):
    monkeypatch.setattr(
        ratchet,
        "_random_bytes",
        lambda count: bytes.fromhex("000102030405060708090a0b") if count == 12 else b"\x00" * count,
    )
    initiator, _ = _states()
    envelope = ratchet.encrypt(
        b"hello from python",
        initiator,
        associated_data=b"gateway-message:session-alpha",
    )

    assert initiator.root_key_base64 == "kRRkcvhOvnCbQllS0YhJ6o3JesOS8deAaGWc2lRLizc="
    assert initiator.sending_chain_key_base64 == "yIl48A/RFS5oRS6PiDlDWZt+m8+NNjoV5Mfrpc5+w0s="
    assert envelope.header.to_wire() == {
        "version": 1,
        "algorithm": ratchet.ALGORITHM,
        "sessionID": "session-alpha",
        "senderDeviceID": "agent-device",
        "receiverDeviceID": "phone-device",
        "ratchetPublicKeyBase64": _fixed_pair(3).public_key_base64,
        "previousChainLength": 0,
        "messageNumber": 0,
        "epoch": 0,
    }
    assert ratchet.envelope_aad(
        envelope.header,
        b"gateway-message:session-alpha",
    ).hex() == (
        "4f70656e4275726e4261722d4865726d6573526174636865742d76312d414144000000000000001d"
        "676174657761792d6d6573736167653a73657373696f6e2d616c70686100000000000000334f7065"
        "6e4275726e4261722d4865726d6573526174636865742d76312d503235362d484b44465348413235"
        "362d41455347434d000000000000000d73657373696f6e2d616c706861000000000000000c616765"
        "6e742d646576696365000000000000000c70686f6e652d6465766963650000000000000058424637"
        "4c354e476d4d777045795066766c52314c3857586d7872636837363270686674425a687647352f31"
        "73687a526b44456d592f3334335377624f476d5369374e677173445934543767396d6e6d784a364a"
        "395544493d0000000000000001000000000000000000000000000000000000000000000000"
    )
    assert envelope.ciphertext_base64 == "AAECAwQFBgcICQoLtJG1Ei/8I6FXnVOkbdEygdSRtj69G1Aais9OzfKL9Vhx"


def test_aad_byte_format_uses_swift_length_prefixes_and_u64_be():
    header = ratchet.HermesRatchetHeader(
        version=1,
        algorithm=ratchet.ALGORITHM,
        session_id="sid",
        sender_device_id="sender",
        receiver_device_id="receiver",
        ratchet_public_key_base64="pub",
        previous_chain_length=2,
        message_number=3,
        epoch=4,
    )
    expected = bytearray(b"OpenBurnBar-HermesRatchet-v1-AAD")
    for part in (
        b"context",
        ratchet.ALGORITHM.encode("utf-8"),
        b"sid",
        b"sender",
        b"receiver",
        b"pub",
    ):
        expected.extend(len(part).to_bytes(8, "big"))
        expected.extend(part)
    for number in (1, 2, 3, 4):
        expected.extend(number.to_bytes(8, "big"))

    assert ratchet.envelope_aad(header, b"context") == bytes(expected)


def test_chain_kdf_labels_match_swift_literals():
    chain_key = bytes(range(32))
    next_chain, message_key = ratchet._chain_kdf(chain_key)
    assert next_chain == hmac.new(
        chain_key,
        b"OpenBurnBar-HermesRatchet-v1-chain",
        sha256,
    ).digest()
    assert message_key == hmac.new(
        chain_key,
        b"OpenBurnBar-HermesRatchet-v1-message",
        sha256,
    ).digest()


def test_round_trip_and_reply_perform_dh_ratchet():
    initiator, responder = _states()
    outbound = ratchet.encrypt(b"hello", initiator, associated_data=b"ad-1")

    assert ratchet.decrypt(outbound, responder, associated_data=b"ad-1") == b"hello"
    assert responder.epoch == 1
    assert responder.sending_chain_key_base64 is not None
    assert responder.receiving_chain_key_base64 is not None

    reply = ratchet.encrypt(b"reply", responder, associated_data=b"ad-2")
    assert ratchet.decrypt(reply, initiator, associated_data=b"ad-2") == b"reply"
    assert initiator.epoch == 1


def test_out_of_order_receive_uses_bounded_skipped_keys():
    initiator, responder = _states()
    first = ratchet.encrypt(b"one", initiator)
    second = ratchet.encrypt(b"two", initiator)
    third = ratchet.encrypt(b"three", initiator)

    assert ratchet.decrypt(third, responder) == b"three"
    assert len(responder.skipped_message_keys) == 2
    assert ratchet.decrypt(first, responder) == b"one"
    assert ratchet.decrypt(second, responder) == b"two"
    assert responder.skipped_message_keys == {}


def test_associated_data_tamper_fails_authentication():
    initiator, responder = _states()
    envelope = ratchet.encrypt(b"sealed", initiator, associated_data=b"right-ad")

    with pytest.raises(ratchet.AuthenticationFailedError):
        ratchet.decrypt(envelope, responder, associated_data=b"wrong-ad")


def test_replay_after_successful_open_fails():
    initiator, responder = _states()
    envelope = ratchet.encrypt(b"single-use", initiator)

    assert ratchet.decrypt(envelope, responder) == b"single-use"
    with pytest.raises(ratchet.AuthenticationFailedError):
        ratchet.decrypt(envelope, responder)


def test_skip_limit_prevents_unbounded_skipped_key_storage():
    initiator, responder = _states(max_skip=1)
    ratchet.encrypt(b"zero", initiator)
    ratchet.encrypt(b"one", initiator)
    third = ratchet.encrypt(b"two", initiator)

    with pytest.raises(ratchet.TooManySkippedKeysError):
        ratchet.decrypt(third, responder)


def test_header_tamper_fails_before_decrypt():
    initiator, responder = _states()
    envelope = ratchet.encrypt(b"sealed", initiator)
    tampered = ratchet.HermesRatchetEnvelope(
        header=ratchet.HermesRatchetHeader(
            session_id=envelope.header.session_id,
            sender_device_id=envelope.header.sender_device_id,
            receiver_device_id="attacker-device",
            ratchet_public_key_base64=envelope.header.ratchet_public_key_base64,
            previous_chain_length=envelope.header.previous_chain_length,
            message_number=envelope.header.message_number,
            epoch=envelope.header.epoch,
        ),
        ciphertext_base64=envelope.ciphertext_base64,
    )

    with pytest.raises(ratchet.InvalidEnvelopeError):
        ratchet.decrypt(tampered, responder)


def test_wire_codable_names_round_trip():
    initiator, _ = _states()
    encoded = initiator.to_wire()
    decoded = ratchet.HermesRatchetSessionState.from_wire(encoded)
    assert decoded.to_wire() == encoded

    envelope = ratchet.encrypt(b"wire", initiator, associated_data=b"ad")
    assert ratchet.HermesRatchetEnvelope.from_wire(envelope.to_wire()).to_wire() == envelope.to_wire()
