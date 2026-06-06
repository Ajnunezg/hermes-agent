"""ADVERSARIAL AUDIT repros for the v4-signed ratchet_init lane.

These are HOSTILE follow-up repros for RATCHET_INIT_ADVERSARIAL_AUDIT_HANDOFF.md.
They go beyond the shipped regression tests: they probe the downgrade floor for a
ratchet_init payload, the per-field handshake binding in the handler in isolation,
init replay against an advanced session, re-init after session-file loss, malformed
key material, the missing-replayCounter gate, and the (un)enforcement of the
recorded ratchet receive high-water.

Run: pytest tests/gateway/test_audit_adversarial.py -q
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

# Reuse the shipped v4 test harness verbatim.
from tests.gateway.test_burnbar_plugin_v4 import (
    _burnbar,
    relay_e2ee,
    v4,
    hr,
    _UID,
    _CLIENT,
    _keys,
    _paired_v4_adapter,
    _signed_ratchet_init,
    _phone_ratchet_frame,
    _phone_to_agent_v4_event,
    RELAY_CRYPTO_AVAILABLE,
)

requires_relay = pytest.mark.skipif(
    not RELAY_CRYPTO_AVAILABLE, reason="cryptography / relay_e2ee unavailable"
)


@pytest.fixture(autouse=True)
def _isolate_state_files(monkeypatch, tmp_path):
    monkeypatch.setattr(_burnbar, "RATCHET_SESSION_FILE", tmp_path / "ratchet.json", raising=False)
    monkeypatch.setattr(_burnbar, "REPLAY_LEDGER_FILE", tmp_path / "ledger.json", raising=False)
    monkeypatch.setattr(_burnbar, "BURNBAR_E2EE_STATE_FILE", tmp_path / "e2ee.json", raising=False)
    monkeypatch.setattr(_burnbar, "CURSOR_FILE", tmp_path / "cursor.json", raising=False)
    (tmp_path / "ledger.json").write_text("{}")


def _capture(adapter):
    received = []

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    return received


# ── Claim 1: a recipient-static-key holder cannot enable the ratchet via a
# downgraded (non-v4) wrap. A v3/v2-wrapped ratchet_init MUST be refused on a
# v4-pinned link (the signed lane is mandatory). ──────────────────────────────
@requires_relay
@pytest.mark.asyncio
async def test_v3_wrapped_ratchet_init_refused_on_v4_link(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    # Build a STRUCTURALLY-VALID ratchet_init payload (correct responder key, ids).
    _v4_raw, _phone, payload = _signed_ratchet_init(adapter, k)
    # Now deliver that exact payload via a v3 HPKE wrap (no Ed25519 signature),
    # authenticated as from the pinned phone enc key — i.e. a relay stripping the
    # v4 layer. The v4-pinned downgrade floor must refuse it before the handler.
    event_id = "v3-init"
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(json.dumps(payload).encode(), sym, payload_aad)
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
    await adapter._handle_burnbar_event(raw)
    assert adapter._ratchet_session("burnbar:home") is None
    assert not adapter._can_ratchet("burnbar:home")
    assert received == []


@requires_relay
@pytest.mark.asyncio
async def test_v2_wrapped_ratchet_init_refused_on_v4_link(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    _v4_raw, _phone, payload = _signed_ratchet_init(adapter, k)
    event_id = "v2-init"
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    sym = relay_e2ee.generate_symmetric_key()
    payload_ct = relay_e2ee.seal_to_base64(json.dumps(payload).encode(), sym, payload_aad)
    wrapped = relay_e2ee.wrap_symmetric_key(
        sym, k["agent_enc"].public_key_base64(), key_aad, sender_private=k["phone_enc"]
    )
    raw = {
        "id": event_id, "destinationId": "burnbar:home",
        "relayEnvelope": {
            "payloadCiphertext": payload_ct, "wrappedKey": wrapped,
            "relayEncryption": _burnbar.RELAY_ENCRYPTION, "relayKeyVersion": 2, "eventId": event_id,
            "senderPublicKey": k["phone_enc"].public_key_base64(),
        },
    }
    await adapter._handle_burnbar_event(raw)
    assert adapter._ratchet_session("burnbar:home") is None
    assert received == []


# ── Claim 3: the handler binds the FULL handshake. Probe each field in isolation
# by calling the handler directly with a single mutated field. (No baseline commit
# first, so each refusal is the binding check firing, not an existing-session
# guard.) ─────────────────────────────────────────────────────────────────────
@requires_relay
def test_handler_binds_every_handshake_field(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    _raw, _phone, base_payload = _signed_ratchet_init(adapter, k)

    def mutate(**overrides):
        p = copy.deepcopy(base_payload)
        p.update(overrides)
        return p

    wrong_pair = hr.generate_key_pair()
    cases = {
        "algorithm": mutate(algorithm="OpenBurnBar-Evil-v9"),
        "ratchetInitVersion": mutate(ratchetInitVersion=2),
        "uid": mutate(uid="not-the-uid"),
        "clientId": mutate(clientId="not-the-client"),
        "responderRatchetPublicKeyBase64": mutate(
            responderRatchetPublicKeyBase64=wrong_pair.public_key_base64
        ),
        "sessionID": mutate(sessionID="0" * 64),
        "initiatorDeviceID": mutate(initiatorDeviceID="0" * 32),
        "responderDeviceID": mutate(responderDeviceID="0" * 32),
        "rootKey_short": mutate(rootKeyBase64=base64.b64encode(b"\x01" * 16).decode()),
        "rootKey_zero": mutate(rootKeyBase64=base64.b64encode(b"\x00" * 32).decode()),
        "rootKey_malformed": mutate(rootKeyBase64="!!!not-base64!!!"),
        "initiator_noncanonical": mutate(initiatorRatchetPublicKeyBase64=base64.b64encode(b"\x04" * 10).decode()),
        "initiator_equals_responder": mutate(
            initiatorRatchetPublicKeyBase64=base_payload["responderRatchetPublicKeyBase64"]
        ),
    }
    for name, payload in cases.items():
        assert adapter._handle_sealed_ratchet_init(payload) is False, f"{name} should be refused"
        assert adapter._ratchet_session("burnbar:home") is None, f"{name} left a session"

    # The pristine baseline must still establish (proves the mutations failed for
    # the field under test, not a structural defect in the harness).
    assert adapter._handle_sealed_ratchet_init(base_payload) is True
    assert adapter._ratchet_session("burnbar:home") is not None


# ── Claim 3/4: a signed init with NO authenticated replayCounter is refused by
# the dispatch gate (controls must pass the counter gate). ────────────────────
@requires_relay
@pytest.mark.asyncio
async def test_ratchet_init_without_replay_counter_refused(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    _raw, _phone, payload = _signed_ratchet_init(adapter, k)
    payload.pop("replayCounter", None)
    raw = _phone_to_agent_v4_event(event_id="init-no-counter", payload=payload, **k)
    await adapter._handle_burnbar_event(raw)
    assert adapter._ratchet_session("burnbar:home") is None
    assert received == []


# ── Claim 5: replaying the signed init against an ALREADY-ADVANCED session must
# not rewind it; a captured old ratchet frame must not re-deliver. ────────────
@requires_relay
@pytest.mark.asyncio
async def test_init_replay_does_not_rewind_advanced_session(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._can_ratchet("burnbar:home")
    # Phone sends two frames; capture the FIRST wire frame for replay.
    f0 = _phone_ratchet_frame(phone, {"text": "m0", "destinationId": "burnbar:home"}, "rm0")
    f0_replay = copy.deepcopy(f0)
    await adapter._handle_burnbar_event(f0)
    f1 = _phone_ratchet_frame(phone, {"text": "m1", "destinationId": "burnbar:home"}, "rm1")
    await adapter._handle_burnbar_event(f1)
    assert [e.text for e in received] == ["m0", "m1"]
    advanced = adapter._ratchet_session("burnbar:home").receive_message_number

    # 1) Replay the SAME signed init (same replayCounter) -> dropped by the gate,
    #    session unchanged.
    await adapter._handle_burnbar_event(copy.deepcopy(init_raw))
    assert adapter._ratchet_session("burnbar:home").receive_message_number == advanced

    # 2) Replay the captured old frame m0 -> its message key is consumed; refused.
    await adapter._handle_burnbar_event(f0_replay)
    assert [e.text for e in received] == ["m0", "m1"]


# ── Claim 5: after the session FILE is lost (lineage intact in the separate state
# store), a fresh signed init with the same keys is refused (no rebootstrap), and
# a captured old frame cannot re-deliver. ─────────────────────────────────────
@requires_relay
@pytest.mark.asyncio
async def test_reinit_after_session_file_loss_is_refused(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    f0 = _phone_ratchet_frame(phone, {"text": "m0", "destinationId": "burnbar:home"}, "rm0")
    f0_replay = copy.deepcopy(f0)
    await adapter._handle_burnbar_event(f0)
    assert [e.text for e in received] == ["m0"]

    # Lose ONLY the ratchet session file + in-memory cache (lineage survives).
    adapter._ratchet_sessions.clear()
    adapter._ratchet_sessions_loaded = False
    if _burnbar.RATCHET_SESSION_FILE.exists():
        _burnbar.RATCHET_SESSION_FILE.unlink()
    assert adapter._e2ee_state.ratchet_lineage_exists(payload["sessionID"])

    # (a) An EXACT replay of the original signed init (same sessionID/keys/counter)
    #     is dropped by the monotonic counter gate -> no session, no redelivery.
    await adapter._handle_burnbar_event(copy.deepcopy(init_raw))
    assert adapter._ratchet_session("burnbar:home") is None
    await adapter._handle_burnbar_event(f0_replay)
    assert [e.text for e in received] == ["m0"]

    # (b) Bypass the counter gate and call the handler directly with the ORIGINAL
    #     payload (same sessionID). The lineage marker in the SEPARATE state store
    #     must refuse re-creating the lost session -> no deterministic rebootstrap.
    assert adapter._handle_sealed_ratchet_init(copy.deepcopy(payload)) is False
    assert adapter._ratchet_session("burnbar:home") is None
    await adapter._handle_burnbar_event(copy.deepcopy(f0_replay))
    assert [e.text for e in received] == ["m0"], "old frame must not re-deliver after session loss"


# ── Claim 6: parity vector reconstructs deterministically from the fixture keys. ─
@requires_relay
def test_parity_vector_reconstructs_from_keys():
    from pathlib import Path
    vector = json.loads(
        (Path(_burnbar.__file__).parent.parent.parent / "tests" / "gateway" / "fixtures"
         / "hermes_ratchet_init_v1.json").read_text(encoding="utf-8")
        if False else
        (Path(__file__).with_name("fixtures") / "hermes_ratchet_init_v1.json").read_text(encoding="utf-8")
    )
    agent = hr.HermesRatchetKeyPair.from_wire(vector["agentRatchetInitKeyPair"])
    phone = hr.HermesRatchetKeyPair.from_wire(vector["phoneRatchetInitKeyPair"])
    hr.validate_key_pair(agent)
    hr.validate_key_pair(phone)
    exp = vector["expectedPayload"]
    assert hr.derive_session_id(
        uid=vector["uid"], client_id=vector["clientId"],
        agent_ratchet_public_key_base64=agent.public_key_base64,
        peer_ratchet_public_key_base64=phone.public_key_base64,
    ) == exp["sessionID"]
    assert hr.derive_device_id(agent.public_key_base64) == exp["responderDeviceID"]
    assert hr.derive_device_id(phone.public_key_base64) == exp["initiatorDeviceID"]
    # root key is the canonical 0..31 ramp
    assert base64.b64decode(vector["rootKeyBase64"]) == bytes(range(32))


# ── Latent-defense probe: is the recorded ratchet receive high-water ENFORCED? ─
# A session-state rollback rewinds the receive chain; the recorded high-water is
# the intended detector. This documents whether it is consulted on the read path.
@requires_relay
@pytest.mark.asyncio
async def test_receive_high_water_enforced_after_session_rollback(monkeypatch):
    monkeypatch.setenv("BURNBAR_RELAY_RATCHET", "1")
    k = _keys()
    adapter = _paired_v4_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    sid = payload["sessionID"]

    f0 = _phone_ratchet_frame(phone, {"text": "m0", "destinationId": "burnbar:home"}, "rm0")
    snapshot = copy.deepcopy(adapter._ratchet_session("burnbar:home"))  # pre-m0 (recv #0)
    await adapter._handle_burnbar_event(f0)
    assert [e.text for e in received] == ["m0"]
    hw = adapter._e2ee_state.get_ratchet_receive_high_water(sid)
    assert hw >= 1  # the high-water WAS recorded

    # Roll the in-memory + on-disk session back to the pre-m0 snapshot and replay m0.
    adapter._ratchet_sessions["burnbar:home"] = copy.deepcopy(snapshot)
    adapter._save_ratchet_sessions()
    # m0 was the FIRST frame off `phone`; rebuild an identical wire frame by
    # re-deriving from a phone snapshot is not possible (phone advanced), so reuse
    # the captured wire bytes:
    await adapter._handle_burnbar_event({
        "id": "rm0-replay", "destinationId": "burnbar:home",
        "ratchetEnvelope": f0["ratchetEnvelope"],
    })
    assert [e.text for e in received] == ["m0"]
    assert not adapter._can_ratchet("burnbar:home")
