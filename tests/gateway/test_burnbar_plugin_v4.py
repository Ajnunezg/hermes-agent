"""v4 (Ed25519 explicit auth + Padmé) end-to-end adapter integration tests.

Proves the v4 hardened wrap works through the REAL adapter send/open path: the
agent emits a v4 signed envelope only when the peer's authenticated grant pinned a
v4 signing key, the peer opens it, a phone->agent v4 frame opens through
``open_event``, a forged signature is refused, and an un-pinned-signing-key link
floors to v3. The crypto-layer proofs live in ``test_relay_e2ee_v4.py``.
"""

from __future__ import annotations

import json

import pytest

from gateway.config import PlatformConfig
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

_burnbar = load_plugin_adapter("burnbar")
BurnBarAdapter = _burnbar.BurnBarAdapter

try:
    from gateway.crypto import relay_e2ee
    from gateway.crypto import relay_e2ee_v4 as v4
    from gateway.crypto import hermes_ratchet as hr

    RELAY_CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    relay_e2ee = None
    v4 = None
    hr = None
    RELAY_CRYPTO_AVAILABLE = False

requires_relay = pytest.mark.skipif(
    not RELAY_CRYPTO_AVAILABLE, reason="cryptography / relay_e2ee unavailable"
)

_UID = "uid-v4"
_CLIENT = "client-v4"


def _no_persist(monkeypatch):
    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "save_env_value", lambda *a, **k: None, raising=False)


def _paired_v4_adapter(monkeypatch, *, phone_enc, phone_sig, agent_enc, agent_sig, with_peer_signing=True):
    _no_persist(monkeypatch)
    monkeypatch.setenv("BURNBAR_RELAY_E2E", "1")
    monkeypatch.setenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", phone_enc.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_UID", _UID)
    monkeypatch.setenv("BURNBAR_RELAY_CLIENT_ID", _CLIENT)
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEY_VERSION", "4")
    monkeypatch.setenv("BURNBAR_RELAY_SIGNING_KEY", agent_sig.raw_base64())
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V4", raising=False)
    if with_peer_signing:
        monkeypatch.setenv("BURNBAR_RELAY_PEER_SIGNING_KEY", phone_sig.public_key_base64())
    else:
        monkeypatch.delenv("BURNBAR_RELAY_PEER_SIGNING_KEY", raising=False)
    monkeypatch.setattr(
        relay_e2ee.AgentRelayIdentity, "load_or_create",
        classmethod(lambda cls, **kw: relay_e2ee.AgentRelayIdentity(agent_enc)),
    )
    cfg = PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": "burnbar:home"})
    return BurnBarAdapter(cfg)


def _phone_to_agent_v4_event(*, agent_enc, agent_sig, phone_enc, phone_sig, event_id, payload):
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    env = v4.seal_signed_v4(
        json.dumps(payload).encode("utf-8"),
        recipient_enc_public=agent_enc.public_key_base64(),
        recipient_verify_key=agent_sig.public_key_base64(),
        sender_enc_private=phone_enc, sender_signing_key=phone_sig,
        key_aad=key_aad, payload_aad=payload_aad,
    )
    return {
        "id": event_id, "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": env.payload_ciphertext, "wrappedKey": env.wrapped_key,
            "enc": env.enc, "senderSig": env.sender_sig,
            "relayEncryption": env.relay_encryption, "relayKeyVersion": 4, "eventId": event_id,
            "senderPublicKey": phone_enc.public_key_base64(),
            "senderSigningKey": phone_sig.public_key_base64(),
        },
    }


def _keys():
    return dict(
        agent_enc=relay_e2ee.generate_private_key(), phone_enc=relay_e2ee.generate_private_key(),
        agent_sig=v4.generate_signing_key(), phone_sig=v4.generate_signing_key(),
    )


@requires_relay
def test_seal_message_emits_v4_and_peer_opens(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="hpke v4 secret")
    assert env["relayKeyVersion"] == 4
    assert env["relayEncryption"] == v4.RELAY_ENCRYPTION_V4
    assert env["enc"] and env["senderSig"]
    assert "text" not in env
    # The peer opens with the v4 opener, binding the agent's pinned enc+signing keys.
    pt = v4.open_signed_v4(
        {"enc": env["enc"], "wrappedKey": env["wrappedKey"],
         "payloadCiphertext": env["payloadCiphertext"], "senderSig": env["senderSig"]},
        recipient_enc_private=k["phone_enc"], recipient_verify_key=k["phone_sig"].public_key_base64(),
        pinned_sender_enc_public=k["agent_enc"].public_key_base64(),
        pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
        key_aad=_burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"]),
        payload_aad=_burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"]),
    )
    assert json.loads(pt) == {"text": "hpke v4 secret", "destinationId": "burnbar:home"}


@requires_relay
def test_open_event_opens_v4_frame(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    raw = _phone_to_agent_v4_event(event_id="evt-v4", payload={"text": "hi from phone"}, **k)
    assert adapter._sealer.open_event(raw) == {"text": "hi from phone"}


@requires_relay
def test_open_event_refuses_v4_with_forged_signature(monkeypatch):
    import base64

    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    raw = _phone_to_agent_v4_event(event_id="evt-forge", payload={"text": "x"}, **k)
    bad = bytearray(base64.b64decode(raw["relayEnvelope"]["senderSig"]))
    bad[0] ^= 0x01
    raw["relayEnvelope"]["senderSig"] = base64.b64encode(bytes(bad)).decode()
    with pytest.raises(v4.RelayV4SignatureError):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v4_from_wrong_signer(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    attacker_sig = v4.generate_signing_key()
    # A frame validly signed by an attacker (not the pinned phone signing key).
    raw = _phone_to_agent_v4_event(
        event_id="evt-att", payload={"text": "forged"},
        agent_enc=k["agent_enc"], agent_sig=k["agent_sig"],
        phone_enc=k["phone_enc"], phone_sig=attacker_sig,
    )
    with pytest.raises(v4.RelayV4SignatureError):
        adapter._sealer.open_event(raw)


@requires_relay
def test_open_event_refuses_v4_without_marker_or_enc(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    raw = _phone_to_agent_v4_event(event_id="evt-strip", payload={"text": "x"}, **k)
    stripped = json.loads(json.dumps(raw))
    stripped["relayEnvelope"].pop("enc")
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(stripped)
    raw["relayEnvelope"]["relayEncryption"] = "p256-hkdf-sha256-aesgcm"
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
def test_floors_to_v3_without_pinned_peer_signing_key(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, with_peer_signing=False, **k)
    assert adapter._peer_relay_key_version_for("burnbar:home") == 3
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="v3 fallback")
    assert env["relayKeyVersion"] == 3 and "senderSig" not in env


@requires_relay
def test_ratchet_chat_lane_round_trip(monkeypatch, tmp_path):
    """With the ratchet opt-in flag, the chat message lane runs through the Double
    Ratchet (forward secrecy + PCS) end-to-end through the adapter, both directions."""
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json")
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    assert adapter._can_ratchet("burnbar:home")
    # The phone is the INITIATOR (sends first); the agent is the RESPONDER (replies).
    phone_pair = hr.HermesRatchetKeyPair(
        private_key_base64=k["phone_enc"].raw_base64(),
        public_key_base64=k["phone_enc"].public_key_base64(),
    )
    phone = hr.bootstrap_session(
        role=hr.HermesRatchetRole.INITIATOR, uid=_UID, client_id=_CLIENT,
        local_ratchet_key_pair=phone_pair, peer_ratchet_public_key_base64=k["agent_enc"].public_key_base64(),
    )
    # Before receiving, the agent (responder) has no sending chain -> v4 signed fallback.
    first = adapter._sealer.seal_message(destination_id="burnbar:home", text="agent-first")
    assert first["relayKeyVersion"] == 4 and "ratchetEnvelope" not in first
    # phone -> agent (initiator's first message), opened through open_event's ratchet path.
    pe = hr.encrypt(json.dumps({"text": "hi from phone"}).encode(), phone)
    assert adapter._sealer.open_event(
        {"id": "e1", "destinationId": "burnbar:home", "ratchetEnvelope": pe.to_wire()}
    ) == {"text": "hi from phone"}
    # Now the agent has a sending chain -> its reply goes through the ratchet.
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="ratcheted hi")
    assert "ratchetEnvelope" in env and "wrappedKey" not in env
    assert json.loads(
        hr.decrypt(hr.HermesRatchetEnvelope.from_wire(env["ratchetEnvelope"]), phone).decode()
    ) == {"text": "ratcheted hi", "destinationId": "burnbar:home"}
    # Several alternations advance the DH ratchet (forward secrecy + PCS).
    for i in range(3):
        pe2 = hr.encrypt(json.dumps({"text": f"p{i}"}).encode(), phone)
        assert adapter._sealer.open_event(
            {"id": f"e{i}", "destinationId": "burnbar:home", "ratchetEnvelope": pe2.to_wire()}
        ) == {"text": f"p{i}"}
        e = adapter._sealer.seal_message(destination_id="burnbar:home", text=f"a{i}")
        assert json.loads(
            hr.decrypt(hr.HermesRatchetEnvelope.from_wire(e["ratchetEnvelope"]), phone).decode()
        )["text"] == f"a{i}"


@requires_relay
def test_ratchet_off_by_default_uses_v4_signed(monkeypatch, tmp_path):
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json")
    monkeypatch.delenv("BURNBAR_RELAY_RATCHET", raising=False)
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    assert not adapter._can_ratchet("burnbar:home")
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="signed not ratcheted")
    assert env["relayKeyVersion"] == 4 and "ratchetEnvelope" not in env


@requires_relay
def test_model_switch_emits_and_opens_v4(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    sw = adapter._sealer.seal_model_switch(destination_id="burnbar:home", model_id="claude-opus-4-8")
    assert sw["relayKeyVersion"] == 4 and sw["senderSig"]
    # round-trip a phone->agent v4 model_switch through open_model_switch
    raw = _phone_to_agent_v4_event(
        event_id="evt-sw",
        payload={"kind": "model_switch", "modelId": "claude-opus-4-8", "destinationId": "burnbar:home"},
        **k,
    )
    opened = adapter._sealer.open_model_switch(raw)
    assert opened["kind"] == "model_switch" and opened["modelId"] == "claude-opus-4-8"
