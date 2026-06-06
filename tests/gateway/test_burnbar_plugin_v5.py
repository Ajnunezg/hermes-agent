"""v5 hybrid-KEM adapter integration tests through the production receive path."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from gateway.config import PlatformConfig
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

_burnbar = load_plugin_adapter("burnbar")
BurnBarAdapter = _burnbar.BurnBarAdapter

try:
    from gateway.crypto import hermes_ratchet as hr
    from gateway.crypto import relay_e2ee
    from gateway.crypto import relay_e2ee_v4 as v4
    from gateway.crypto import relay_e2ee_v5 as v5

    RELAY_V5_AVAILABLE = v5.is_supported()
except ImportError:  # pragma: no cover
    hr = None
    relay_e2ee = None
    v4 = None
    v5 = None
    RELAY_V5_AVAILABLE = False


requires_v5 = pytest.mark.skipif(
    not RELAY_V5_AVAILABLE,
    reason="cryptography HPKE MLKEM768_X25519 unavailable",
)

_UID = "uid-v5"
_CLIENT = "client-v5"
_FIXTURES = Path(__file__).with_name("fixtures")


@pytest.fixture(autouse=True)
def _isolate_state_files(monkeypatch, tmp_path):
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json", raising=False)
    monkeypatch.setattr(_burnbar, "REPLAY_LEDGER_FILE", tmp_path / "ledger.json", raising=False)
    monkeypatch.setattr(_burnbar, "BURNBAR_E2EE_STATE_FILE", tmp_path / "e2ee.json", raising=False)
    monkeypatch.setattr(_burnbar, "CURSOR_FILE", tmp_path / "cursor.json", raising=False)
    (tmp_path / "ledger.json").write_text("{}")


def _no_persist(monkeypatch):
    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "save_env_value", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(_cfg, "save_env_values", lambda *a, **k: None, raising=False)


def _capture(adapter):
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    return received


def _keys():
    return {
        "agent_enc": relay_e2ee.generate_private_key(),
        "phone_enc": relay_e2ee.generate_private_key(),
        "agent_sig": v4.generate_signing_key(),
        "phone_sig": v4.generate_signing_key(),
        "agent_kem": v5.generate_kem_private_key(),
        "phone_kem": v5.generate_kem_private_key(),
    }


def _paired_v5_adapter(monkeypatch, *, agent_enc, phone_enc, agent_sig, phone_sig, agent_kem, phone_kem):
    _no_persist(monkeypatch)
    monkeypatch.setenv("BURNBAR_RELAY_E2E", "1")
    monkeypatch.setenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", phone_enc.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_UID", _UID)
    monkeypatch.setenv("BURNBAR_RELAY_CLIENT_ID", _CLIENT)
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEY_VERSION", "5")
    monkeypatch.setenv("BURNBAR_RELAY_SIGNING_KEY", agent_sig.raw_base64())
    monkeypatch.setenv("BURNBAR_RELAY_PEER_SIGNING_KEY", phone_sig.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEM_PUBLIC_KEY", phone_kem.public_key_base64())
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V4", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V5", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_RATCHET", raising=False)
    monkeypatch.setattr(
        relay_e2ee.AgentRelayIdentity,
        "load_or_create",
        classmethod(lambda cls, **kw: relay_e2ee.AgentRelayIdentity(agent_enc)),
    )
    monkeypatch.setattr(
        v5.AgentKemIdentity,
        "load_or_create",
        classmethod(lambda cls, **kw: v5.AgentKemIdentity(agent_kem)),
    )
    cfg = PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": "burnbar:home"})
    return BurnBarAdapter(cfg)


def _v5_pinned_adapter_without_local_kem(
    monkeypatch,
    *,
    agent_enc,
    phone_enc,
    agent_sig,
    phone_sig,
    phone_kem,
    disable_v5: bool = False,
    **_ignored,
):
    _no_persist(monkeypatch)
    monkeypatch.setenv("BURNBAR_RELAY_E2E", "1")
    monkeypatch.setenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", phone_enc.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_UID", _UID)
    monkeypatch.setenv("BURNBAR_RELAY_CLIENT_ID", _CLIENT)
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEY_VERSION", "5")
    monkeypatch.setenv("BURNBAR_RELAY_SIGNING_KEY", agent_sig.raw_base64())
    monkeypatch.setenv("BURNBAR_RELAY_PEER_SIGNING_KEY", phone_sig.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEM_PUBLIC_KEY", phone_kem.public_key_base64())
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V4", raising=False)
    if disable_v5:
        monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_HPKE_V5", "1")
    else:
        monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V5", raising=False)
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_RATCHET", raising=False)
    monkeypatch.setattr(
        relay_e2ee.AgentRelayIdentity,
        "load_or_create",
        classmethod(lambda cls, **kw: relay_e2ee.AgentRelayIdentity(agent_enc)),
    )
    monkeypatch.setattr(
        v5.AgentKemIdentity,
        "load_or_create",
        classmethod(lambda cls, **kw: (_ for _ in ()).throw(RuntimeError("missing local KEM seed"))),
    )
    cfg = PlatformConfig(enabled=True, extra={"access_token": "tok", "home_channel": "burnbar:home"})
    return BurnBarAdapter(cfg)


def _phone_to_agent_v5_event(*, agent_kem, agent_sig, phone_sig, event_id, payload, **_ignored):
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    env = v5.seal_signed_v5(
        json.dumps(payload).encode("utf-8"),
        recipient_kem_public=agent_kem.public_key(),
        recipient_verify_key=agent_sig.public_key_base64(),
        sender_signing_key=phone_sig,
        key_aad=key_aad,
        payload_aad=payload_aad,
    )
    return {
        "id": event_id,
        "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": env.payload_ciphertext,
            "wrappedKey": env.wrapped_key,
            "enc": env.enc,
            "senderSig": env.sender_sig,
            "relayEncryption": env.relay_encryption,
            "relayKeyVersion": 5,
            "eventId": event_id,
            "senderSigningKey": phone_sig.public_key_base64(),
        },
    }


def _phone_to_agent_v4_event(*, agent_enc, agent_sig, phone_enc, phone_sig, event_id, payload, **_ignored):
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    env = v4.seal_signed_v4(
        json.dumps(payload).encode("utf-8"),
        recipient_enc_public=agent_enc.public_key_base64(),
        recipient_verify_key=agent_sig.public_key_base64(),
        sender_enc_private=phone_enc,
        sender_signing_key=phone_sig,
        key_aad=key_aad,
        payload_aad=payload_aad,
    )
    return {
        "id": event_id,
        "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": env.payload_ciphertext,
            "wrappedKey": env.wrapped_key,
            "enc": env.enc,
            "senderSig": env.sender_sig,
            "relayEncryption": env.relay_encryption,
            "relayKeyVersion": 4,
            "eventId": event_id,
            "senderPublicKey": phone_enc.public_key_base64(),
            "senderSigningKey": phone_sig.public_key_base64(),
        },
    }


def _signed_ratchet_init_v2(adapter, k, *, event_id="ratchet-init-v2", replay_counter=1):
    agent_pair = adapter._ensure_ratchet_init_key_pair()
    agent_kem = adapter._ensure_ratchet_init_kem_key_pair()
    assert agent_pair is not None and agent_kem is not None
    phone_pair = hr.generate_key_pair()
    kem_shared, kem_ct = v5.xwing_encapsulate(agent_kem.public_key())
    kem_ct_b64 = base64.b64encode(kem_ct).decode("ascii")
    session_id = hr.derive_session_id(
        uid=_UID,
        client_id=_CLIENT,
        agent_ratchet_public_key_base64=agent_pair.public_key_base64,
        peer_ratchet_public_key_base64=phone_pair.public_key_base64,
    )
    initiator_device = hr.derive_device_id(phone_pair.public_key_base64)
    responder_device = hr.derive_device_id(agent_pair.public_key_base64)
    transcript = hr.ratchet_init_v2_transcript(
        uid=_UID,
        client_id=_CLIENT,
        destination_id="burnbar:home",
        session_id=session_id,
        initiator_ratchet_public_key_base64=phone_pair.public_key_base64,
        responder_ratchet_public_key_base64=agent_pair.public_key_base64,
        initiator_device_id=initiator_device,
        responder_device_id=responder_device,
        responder_kem_public_key_base64=agent_kem.public_key_base64(),
        responder_kem_key_id=agent_kem.key_id(),
        kem_ciphertext_base64=kem_ct_b64,
        replay_counter=replay_counter,
    )
    root = hr.derive_ratchet_init_v2_root(kem_shared, transcript)
    root_mac = hr.ratchet_init_v2_root_confirm_mac(root, transcript)
    payload = {
        "kind": _burnbar.RATCHET_INIT_KIND,
        "ratchetInitVersion": 2,
        "algorithm": hr.RATCHET_INIT_ALGORITHM_V2,
        "uid": _UID,
        "clientId": _CLIENT,
        "destinationId": "burnbar:home",
        "sessionID": session_id,
        "initiatorRatchetPublicKeyBase64": phone_pair.public_key_base64,
        "responderRatchetPublicKeyBase64": agent_pair.public_key_base64,
        "initiatorDeviceID": initiator_device,
        "responderDeviceID": responder_device,
        "responderKemPublicKeyBase64": agent_kem.public_key_base64(),
        "responderKemKeyID": agent_kem.key_id(),
        "kemCiphertextBase64": kem_ct_b64,
        "rootConfirmMacBase64": base64.b64encode(root_mac).decode("ascii"),
        "replayCounter": replay_counter,
    }
    phone = hr.initiator_state(
        session_id=session_id,
        local_device_id=initiator_device,
        remote_device_id=responder_device,
        shared_secret=root,
        remote_initial_ratchet_public_key_base64=agent_pair.public_key_base64,
        local_initial_ratchet_key_pair=phone_pair,
    )
    raw = _phone_to_agent_v5_event(event_id=event_id, payload=payload, **k)
    return raw, phone, payload


def _phone_ratchet_frame(phone, payload, event_id):
    env = hr.encrypt(v4.padme_pad(json.dumps(payload).encode("utf-8")), phone)
    return {"id": event_id, "destinationId": "burnbar:home", "ratchetEnvelope": env.to_wire()}


@requires_v5
def test_ratchet_init_v2_parity_vector():
    vector = json.loads((_FIXTURES / "hermes_ratchet_init_v2.json").read_text(encoding="utf-8"))
    agent_pair = hr.HermesRatchetKeyPair.from_wire(vector["agentRatchetInitKeyPair"])
    phone_pair = hr.HermesRatchetKeyPair.from_wire(vector["phoneRatchetInitKeyPair"])
    agent_kem = v5.RelayKemPrivateKey.from_base64(vector["agentRatchetInitKemPrivateSeedBase64"])
    payload = vector["expectedPayload"]
    assert payload["responderRatchetPublicKeyBase64"] == agent_pair.public_key_base64
    assert payload["initiatorRatchetPublicKeyBase64"] == phone_pair.public_key_base64
    assert payload["responderKemPublicKeyBase64"] == agent_kem.public_key_base64()
    assert payload["responderKemKeyID"] == agent_kem.key_id()
    kem_ct = base64.b64decode(payload["kemCiphertextBase64"], validate=True)
    kem_shared = v5.xwing_decapsulate(agent_kem, kem_ct)
    assert base64.b64encode(hashlib.sha256(kem_shared).digest()).decode("ascii") == vector["kemSharedSecretSha256Base64"]
    transcript = hr.ratchet_init_v2_transcript(
        uid=vector["uid"],
        client_id=vector["clientId"],
        destination_id=vector["destinationId"],
        session_id=payload["sessionID"],
        initiator_ratchet_public_key_base64=payload["initiatorRatchetPublicKeyBase64"],
        responder_ratchet_public_key_base64=payload["responderRatchetPublicKeyBase64"],
        initiator_device_id=payload["initiatorDeviceID"],
        responder_device_id=payload["responderDeviceID"],
        responder_kem_public_key_base64=payload["responderKemPublicKeyBase64"],
        responder_kem_key_id=payload["responderKemKeyID"],
        kem_ciphertext_base64=payload["kemCiphertextBase64"],
        replay_counter=payload["replayCounter"],
    )
    root = hr.derive_ratchet_init_v2_root(kem_shared, transcript)
    assert base64.b64encode(hashlib.sha256(root).digest()).decode("ascii") == vector["rootKeySha256Base64"]
    hr.verify_ratchet_init_v2_root_confirm_mac(
        root_key=root,
        transcript=transcript,
        mac=base64.b64decode(payload["rootConfirmMacBase64"], validate=True),
    )


@requires_v5
def test_seal_message_emits_v5_and_peer_opens(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="hpke v5 secret")
    assert env["relayKeyVersion"] == 5
    assert env["relayEncryption"] == v5.RELAY_ENCRYPTION_V5
    opened = v5.open_signed_v5(
        env,
        recipient_kem_private=k["phone_kem"],
        recipient_verify_key=k["phone_sig"].public_key_base64(),
        pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
        key_aad=_burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"]),
        payload_aad=_burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"]),
    )
    assert json.loads(opened) == {
        "text": "hpke v5 secret",
        "destinationId": "burnbar:home",
        "replayCounter": 1,
    }


@requires_v5
@pytest.mark.asyncio
async def test_handle_burnbar_event_opens_v5_frame(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v5_event(
        event_id="evt-v5",
        payload={"text": "hi from v5", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert [event.text for event in received] == ["hi from v5"]


@requires_v5
@pytest.mark.asyncio
async def test_v5_link_refuses_downgraded_v4_frame(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="evt-downgrade-v4",
        payload={"text": "downgraded", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert received == []


@requires_v5
@pytest.mark.asyncio
async def test_v5_inbound_floor_does_not_silently_degrade_when_local_kem_missing(monkeypatch):
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, **k)
    assert adapter._peer_relay_key_version_for("burnbar:home") == 4
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 5
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="evt-v5-floor-no-kem",
        payload={"text": "must not downgrade", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert received == []


@requires_v5
@pytest.mark.asyncio
async def test_v5_break_glass_explicitly_lowers_inbound_floor_to_v4(monkeypatch):
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, disable_v5=True, **k)
    assert adapter._peer_relay_key_version_for("burnbar:home") == 4
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 4
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="evt-v5-break-glass-v4",
        payload={"text": "explicit v4 rollback", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert [event.text for event in received] == ["explicit v4 rollback"]


@requires_v5
@pytest.mark.asyncio
async def test_v5_json_text_is_not_reparsed_as_control(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v5_event(
        event_id="evt-json-text",
        payload={
            "text": "{\"kind\":\"model_switch\",\"modelId\":\"evil\"}",
            "destinationId": "burnbar:home",
            "replayCounter": 1,
        },
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert [event.text for event in received] == ['{"kind":"model_switch","modelId":"evil"}']


@requires_v5
@pytest.mark.asyncio
async def test_v5_ratchet_init_v2_is_default_on_and_break_glass_disables_use(monkeypatch):
    monkeypatch.delenv("BURNBAR_RELAY_RATCHET", raising=False)
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    ratchet_pub = adapter._ratchet_init_public_key_for_advertisement()
    ratchet_kem_pub, ratchet_kem_key_id = adapter._ratchet_init_kem_key_for_advertisement()
    assert ratchet_pub
    assert ratchet_kem_pub and ratchet_kem_key_id
    capability = _burnbar._gateway_relay_capability_payload(
        ratchet_pub,
        adapter._relay_kem_public_key_base64(),
        ratchet_kem_pub,
        ratchet_kem_key_id,
    )
    assert capability["supportsGatewayRatchetInit"] is True
    assert capability["gatewayRatchetInitVersion"] == 2
    assert capability["agentRatchetInitKemPublicKey"] == ratchet_kem_pub

    init_raw, _phone, _payload = _signed_ratchet_init_v2(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._can_ratchet("burnbar:home")

    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_RATCHET", "1")
    assert adapter._ratchet_init_public_key_for_advertisement() is None
    assert adapter._ratchet_init_kem_key_for_advertisement() == (None, None)
    assert not adapter._can_ratchet("burnbar:home")


@requires_v5
@pytest.mark.asyncio
async def test_v5_signed_ratchet_init_v2_enables_chat_through_full_handler(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    initial_kem_id = payload["responderKemKeyID"]
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._can_ratchet("burnbar:home")
    assert adapter._ensure_ratchet_init_kem_key_pair().key_id() != initial_kem_id

    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "hi over v5 ratchet", "destinationId": "burnbar:home"}, "rm-v5-1")
    )
    assert [event.text for event in received] == ["hi over v5 ratchet"]


@requires_v5
@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["rootKeyBase64", "rootConfirmMacBase64", "kemCiphertextBase64"])
async def test_v5_ratchet_init_v2_mutations_refused_through_handler(monkeypatch, mutation):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    _raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    payload = dict(payload)
    if mutation == "rootKeyBase64":
        payload["rootKeyBase64"] = base64.b64encode(b"x" * 32).decode("ascii")
    elif mutation == "rootConfirmMacBase64":
        mac = bytearray(base64.b64decode(payload["rootConfirmMacBase64"]))
        mac[0] ^= 1
        payload["rootConfirmMacBase64"] = base64.b64encode(bytes(mac)).decode("ascii")
    else:
        ct = bytearray(base64.b64decode(payload["kemCiphertextBase64"]))
        ct[0] ^= 1
        payload["kemCiphertextBase64"] = base64.b64encode(bytes(ct)).decode("ascii")
    raw = _phone_to_agent_v5_event(event_id=f"bad-{mutation}", payload=payload, **k)
    await adapter._handle_burnbar_event(raw)
    assert not adapter._can_ratchet("burnbar:home")
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "must not deliver", "destinationId": "burnbar:home"}, f"bad-ratchet-{mutation}")
    )
    assert received == []
