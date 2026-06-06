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


@pytest.fixture(autouse=True)
def _isolate_state_files(monkeypatch, tmp_path):
    """Redirect on-disk state files so tests never touch the real Hermes profile."""
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json", raising=False)
    monkeypatch.setattr(_burnbar, "REPLAY_LEDGER_FILE", tmp_path / "ledger.json", raising=False)
    monkeypatch.setattr(_burnbar, "BURNBAR_E2EE_STATE_FILE", tmp_path / "e2ee.json", raising=False)
    monkeypatch.setattr(_burnbar, "CURSOR_FILE", tmp_path / "cursor.json", raising=False)

    # Simulate an empty legacy ledger so that load_or_fail_closed migrates it and sets _ready=True
    (tmp_path / "ledger.json").write_text("{}")


def _no_persist(monkeypatch):
    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "save_env_value", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(_cfg, "save_env_values", lambda *a, **k: None, raising=False)


def _paired_v4_adapter(
    monkeypatch, *, phone_enc, phone_sig, agent_enc, agent_sig,
    with_peer_signing=True, disable_v4=False, peer_signing_override=None,
):
    _no_persist(monkeypatch)
    monkeypatch.setenv("BURNBAR_RELAY_E2E", "1")
    monkeypatch.setenv("BURNBAR_RELAY_PEER_PUBLIC_KEY", phone_enc.public_key_base64())
    monkeypatch.setenv("BURNBAR_RELAY_UID", _UID)
    monkeypatch.setenv("BURNBAR_RELAY_CLIENT_ID", _CLIENT)
    monkeypatch.setenv("BURNBAR_RELAY_PEER_KEY_VERSION", "4")
    monkeypatch.setenv("BURNBAR_RELAY_SIGNING_KEY", agent_sig.raw_base64())
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V3", raising=False)
    if disable_v4:
        monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_HPKE_V4", "1")
    else:
        monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_HPKE_V4", raising=False)
    if peer_signing_override is not None:
        monkeypatch.setenv("BURNBAR_RELAY_PEER_SIGNING_KEY", peer_signing_override)
    elif with_peer_signing:
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
    assert json.loads(pt) == {
        "text": "hpke v4 secret",
        "destinationId": "burnbar:home",
        "replayCounter": 1,
    }


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
def test_v4_link_refuses_downgraded_v3_frame(monkeypatch):
    """Anti-downgrade floor: on a v4-pinned link, a (validly-formed) v3-labeled
    inbound frame is refused EXPLICITLY before unwrap, not via an incidental parse
    error — a relay cannot strip the Ed25519 layer by relabeling to v3."""
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    event_id = "evt-dg"
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(json.dumps({"text": "x"}).encode(), sym, payload_aad)
    wrap = relay_e2ee.wrap_symmetric_key_v3(
        sym, k["agent_enc"].public_key_base64(), key_aad, sender_private=k["phone_enc"]
    )
    raw = {
        "id": event_id, "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": payload_ct, "wrappedKey": wrap.wrapped_key, "enc": wrap.enc,
            "relayEncryption": wrap.relay_encryption, "relayKeyVersion": 3, "eventId": event_id,
            "senderPublicKey": k["phone_enc"].public_key_base64(),
        },
    }
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.open_event(raw)


@requires_relay
def test_break_glass_v4_floors_to_v3_not_v2(monkeypatch):
    """Break-glass (v4 disabled) degrades a v4-pinned link to v3 — the next-best
    AUTHENTICATED wrap — not all the way down to v2."""
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, disable_v4=True, **k)
    assert adapter._peer_relay_key_version_default == 3  # floored to v3 at __init__, not v2
    assert adapter._peer_relay_key_version_for("burnbar:home") == 3
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="rolled back")
    assert env["relayKeyVersion"] == 3 and "senderSig" not in env


@requires_relay
def test_invalid_env_peer_signing_key_floors_to_v3(monkeypatch):
    """A present-but-invalid BURNBAR_RELAY_PEER_SIGNING_KEY is treated as absent at
    startup (the link floors to v3) rather than failing every v4 send."""
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, peer_signing_override="not~a~valid~ed25519~key", **k)
    assert adapter._peer_signing_key is None
    assert adapter._peer_relay_key_version_for("burnbar:home") == 3
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="v3 fallback")
    assert env["relayKeyVersion"] == 3 and "senderSig" not in env


@requires_relay
@pytest.mark.asyncio
async def test_ratchet_frame_refused_even_if_replay_ledger_record_fails(monkeypatch):
    """Ratchet is disabled until a signed init exists, so ledger behavior cannot
    turn a ratchet frame into a delivered plaintext event."""
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    phone = _phone_initiator(k)
    monkeypatch.setattr(adapter, "_record_event", lambda *a, **kw: False)
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "survives ledger fail", "destinationId": "burnbar:home"}, "rm-led")
    )
    assert received == []


@requires_relay
def test_floors_to_v3_without_pinned_peer_signing_key(monkeypatch):
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, with_peer_signing=False, **k)
    assert adapter._peer_relay_key_version_for("burnbar:home") == 3
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="v3 fallback")
    assert env["relayKeyVersion"] == 3 and "senderSig" not in env


def _phone_initiator(k):
    pair = hr.HermesRatchetKeyPair(
        private_key_base64=k["phone_enc"].raw_base64(),
        public_key_base64=k["phone_enc"].public_key_base64(),
    )
    return hr.bootstrap_session(
        role=hr.HermesRatchetRole.INITIATOR, uid=_UID, client_id=_CLIENT,
        local_ratchet_key_pair=pair, peer_ratchet_public_key_base64=k["agent_enc"].public_key_base64(),
    )


def _phone_ratchet_frame(phone, payload, event_id):
    pe = hr.encrypt(v4.padme_pad(json.dumps(payload).encode()), phone)
    return {"id": event_id, "destinationId": "burnbar:home", "ratchetEnvelope": pe.to_wire()}


def _recipient_static_kci_forged_ratchet_frame(k, payload, event_id):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    agent_pub = k["agent_enc"].public_key_base64()
    phone_pub = k["phone_enc"].public_key_base64()
    session_id = hr.derive_session_id(
        uid=_UID,
        client_id=_CLIENT,
        agent_ratchet_public_key_base64=agent_pub,
        peer_ratchet_public_key_base64=phone_pub,
    )
    dh = hr._shared_secret_bytes(
        hr._private_key_from_base64(k["agent_enc"].raw_base64()),
        hr._public_key_from_base64(phone_pub),
    )
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=hr._BOOTSTRAP_INFO + b"|" + session_id.encode("ascii"),
    ).derive(dh)
    forged_phone = hr.initiator_state(
        session_id=session_id,
        local_device_id=hr.derive_device_id(phone_pub),
        remote_device_id=hr.derive_device_id(agent_pub),
        shared_secret=shared_secret,
        remote_initial_ratchet_public_key_base64=agent_pub,
        local_initial_ratchet_key_pair=hr.generate_key_pair(),
    )
    return _phone_ratchet_frame(forged_phone, payload, event_id)


@requires_relay
@pytest.mark.asyncio
async def test_recipient_static_kci_cannot_forge_ratchet_through_handler(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    await adapter._handle_burnbar_event(
        _recipient_static_kci_forged_ratchet_frame(
            k,
            {"text": "forged by recipient static key", "destinationId": "burnbar:home"},
            "kci-ratchet-forge",
        )
    )
    assert received == []


# --- FULL-PATTH receive tests: drive the production _handle_burnbar_event ----
@requires_relay
@pytest.mark.asyncio
async def test_ratchet_chat_refused_through_full_handler(monkeypatch):
    """Ratchet frames are refused through the real handler until signed init ships."""
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    phone = _phone_initiator(k)
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "hi over ratchet", "destinationId": "burnbar:home"}, "rm1")
    )
    assert received == []


@requires_relay
@pytest.mark.asyncio
async def test_ratchet_out_of_order_refused_through_handler(monkeypatch):
    """Out-of-order ratchet frames are still refused while the lane is disabled."""
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    phone = _phone_initiator(k)
    f0 = _phone_ratchet_frame(phone, {"text": "m0", "destinationId": "burnbar:home"}, "rm0")
    f1 = _phone_ratchet_frame(phone, {"text": "m1", "destinationId": "burnbar:home"}, "rm1")
    await adapter._handle_burnbar_event(f1)  # deliver the LATER one first
    await adapter._handle_burnbar_event(f0)  # then the earlier one (skipped key)
    assert received == []


@requires_relay
@pytest.mark.asyncio
async def test_control_kind_refused_on_ratchet_lane(monkeypatch):
    """A control kind (model_switch) smuggled onto the ratchet chat lane is REFUSED
    (control plane must use the v4 signed lane with the counter gate)."""
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    phone = _phone_initiator(k)
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(
            phone, {"kind": "model_switch", "modelId": "evil/model", "destinationId": "burnbar:home"}, "rm-ctl"
        )
    )
    assert received == []  # refused, no model switch applied


@requires_relay
@pytest.mark.asyncio
async def test_ratchet_refuses_rebootstrap_after_session_loss(monkeypatch):
    """Deterministic rebootstrap is unreachable while the ratchet lane is disabled."""
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    phone = _phone_initiator(k)
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "first", "destinationId": "burnbar:home"}, "r-a")
    )
    assert received == []
    adapter._ratchet_sessions.clear()
    adapter._ratchet_sessions_loaded = False
    if _burnbar.RATCHET_SESSION_FILE.exists():
        _burnbar.RATCHET_SESSION_FILE.unlink()
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "replayed-or-new", "destinationId": "burnbar:home"}, "r-b")
    )
    assert received == []


@requires_relay
@pytest.mark.asyncio
async def test_v4_signed_control_through_full_handler(monkeypatch):
    """A v4-signed model_switch WITH a replayCounter is applied through the real
    handler (the signed lane still passes the counter gate after the ratchet
    exemption)."""
    monkeypatch.delenv("BURNBAR_RELAY_RATCHET", raising=False)
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    event_id = "ms1"
    payload = {"kind": "model_switch", "modelId": "claude-opus-4-8", "destinationId": "burnbar:home", "replayCounter": 1}
    raw = _phone_to_agent_v4_event(event_id=event_id, payload=payload, **k)
    await adapter._handle_burnbar_event(raw)
    assert received and received[0].text == "/model claude-opus-4-8"


@requires_relay
@pytest.mark.asyncio
async def test_v4_signed_json_text_is_not_reparsed_as_control(monkeypatch):
    """A v4-signed chat payload needs an explicit kind field to become control."""
    monkeypatch.delenv("BURNBAR_RELAY_RATCHET", raising=False)
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    adapter._publish_runtime_status = lambda *a, **kw: pytest.fail("model switch should not run")
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    chat_text = '{"kind":"model_switch","modelId":"evil/model"}'
    raw = _phone_to_agent_v4_event(
        event_id="json-text-v4",
        payload={"text": chat_text, "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert received and received[0].text == chat_text


@requires_relay
def test_ratchet_env_uses_v4_signed_until_signed_init(monkeypatch, tmp_path):
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json")
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    assert not adapter._can_ratchet("burnbar:home")
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="signed not ratcheted")
    assert env["relayKeyVersion"] == 4 and env["senderSig"]
    assert "ratchetEnvelope" not in env
    opened = v4.open_signed_v4(
        {
            "enc": env["enc"],
            "wrappedKey": env["wrappedKey"],
            "payloadCiphertext": env["payloadCiphertext"],
            "senderSig": env["senderSig"],
        },
        recipient_enc_private=k["phone_enc"],
        recipient_verify_key=k["phone_sig"].public_key_base64(),
        pinned_sender_enc_public=k["agent_enc"].public_key_base64(),
        pinned_sender_verify_key=k["agent_sig"].public_key_base64(),
        key_aad=_burnbar._gateway_message_key_aad(_UID, _CLIENT, env["messageId"]),
        payload_aad=_burnbar._gateway_message_aad(_UID, _CLIENT, env["messageId"]),
    )
    assert json.loads(opened) == {
        "text": "signed not ratcheted",
        "destinationId": "burnbar:home",
        "replayCounter": 1,
    }


@requires_relay
def test_key_rotation_swaps_pinned_peer_key(monkeypatch):
    """An authenticated key_rotation event (signed by the pinned peer identity key)
    swaps the pinned peer encryption key and advances the epoch; a replay and a
    wrong-signer event are rejected."""
    import base64
    import time

    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    assert adapter._peer_relay_key_epoch == 0
    old_pin = adapter._peer_public_key
    new_enc = relay_e2ee.generate_private_key()
    now = int(time.time() * 1000)

    def _event(from_epoch, to_epoch, old_enc, new_enc_priv, signer, nonce):
        body = v4.build_rotation_signed_body(
            uid=_UID, client_id=_CLIENT, from_epoch=from_epoch, to_epoch=to_epoch,
            old_enc_x963=old_enc, new_enc_x963=new_enc_priv.public_key_x963(),
            not_before_ms=now - 1000, not_after_ms=now + 60000, rotation_nonce=nonce,
        )
        return {
            "kind": "key_rotation", "destinationId": "burnbar:home",
            "signedBody": base64.b64encode(body).decode(),
            "signature": base64.b64encode(signer.sign(body)).decode(),
        }

    # valid rotation signed by the pinned peer identity key
    assert adapter._handle_sealed_key_rotation(
        _event(0, 1, k["phone_enc"].public_key_x963(), new_enc, k["phone_sig"], b"\x22" * 32)
    )
    assert adapter._peer_public_key == new_enc.public_key_base64()
    assert adapter._peer_public_key != old_pin and adapter._peer_relay_key_epoch == 1

    # replay of the same epoch -> rejected (no change)
    assert not adapter._handle_sealed_key_rotation(
        _event(0, 1, k["phone_enc"].public_key_x963(), new_enc, k["phone_sig"], b"\x22" * 32)
    )
    assert adapter._peer_relay_key_epoch == 1

    # next epoch but signed by an ATTACKER (not the pinned identity) -> rejected
    attacker = v4.generate_signing_key()
    assert not adapter._handle_sealed_key_rotation(
        _event(1, 2, new_enc.public_key_x963(), relay_e2ee.generate_private_key(), attacker, b"\x33" * 32)
    )
    assert adapter._peer_relay_key_epoch == 1
    assert adapter._peer_public_key == new_enc.public_key_base64()


@requires_relay
def test_key_rotation_persist_failure_does_not_advance_pin_or_epoch(monkeypatch):
    import base64
    import time

    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    old_pin = adapter._peer_public_key
    new_enc = relay_e2ee.generate_private_key()
    now = int(time.time() * 1000)
    body = v4.build_rotation_signed_body(
        uid=_UID,
        client_id=_CLIENT,
        from_epoch=0,
        to_epoch=1,
        old_enc_x963=k["phone_enc"].public_key_x963(),
        new_enc_x963=new_enc.public_key_x963(),
        not_before_ms=now - 1000,
        not_after_ms=now + 60000,
        rotation_nonce=b"\x44" * 32,
    )
    monkeypatch.setattr(
        adapter,
        "_persist_peer_key_rotation",
        lambda *a, **kw: False,
    )

    assert not adapter._handle_sealed_key_rotation(
        {
            "kind": "key_rotation",
            "destinationId": "burnbar:home",
            "signedBody": base64.b64encode(body).decode(),
            "signature": base64.b64encode(k["phone_sig"].sign(body)).decode(),
        }
    )
    assert adapter._peer_public_key == old_pin
    assert adapter._peer_relay_key_epoch == 0


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
