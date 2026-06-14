"""V5 Adversarial Audit Handoff – gap-fill hostile tests.

Implements the hostile repro scenarios from V5_ADVERSARIAL_AUDIT_HANDOFF.md
that are NOT already covered by test_v5_adversarial_probe.py or the shipped
regression suites (test_burnbar_plugin_v5.py, test_audit_adversarial.py).

Specific gaps addressed:
 - Claim 3 / Audit bullet 4: v5-pinned adapter with MISSING local KEM seed
   receiving a valid v4 frame must fail-CLOSED (not silently degrade) unless
   BURNBAR_DISABLE_GATEWAY_HPKE_V5=1 was set before startup.
 - Claim 4: ratchet_init v2 refuses a payload that contains a transmitted
   rootKeyBase64 (the root is derived from KEM only, never sent).
 - Audit bullet 5 (standalone): v2 init with wrong responderKemKeyID is refused.
 - Claim 8 (standalone): BURNBAR_DISABLE_GATEWAY_RATCHET=1 stops capability
   advertisement AND prevents established session use.
 - Restored old ratchet session file after durable high-water advances.

Run:
    pytest tests/gateway/test_adversarial_v5_handoff.py -q
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

# Re-use helpers from the shipped v5 test harness verbatim.
from tests.gateway.test_burnbar_plugin_v5 import (
    _burnbar,
    relay_e2ee,
    v4,
    v5,
    hr,
    _UID,
    _CLIENT,
    _keys,
    _paired_v5_adapter,
    _v5_pinned_adapter_without_local_kem,
    _phone_to_agent_v4_event,
    _signed_ratchet_init_v2,
    _phone_ratchet_frame,
    RELAY_V5_AVAILABLE,
)

requires_v5 = pytest.mark.skipif(
    not RELAY_V5_AVAILABLE, reason="cryptography HPKE MLKEM768_X25519 unavailable"
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

    async def cap(event):
        received.append(event)

    adapter.handle_message = cap
    return received


# ══════════════════════════════════════════════════════════════════════════════
# Claim 3 / Audit §"v5-pinned adapter with missing local KEM seed"
# ══════════════════════════════════════════════════════════════════════════════

@requires_v5
@pytest.mark.asyncio
async def test_missing_local_kem_seed_refuses_v4_frame_fail_closed(monkeypatch):
    """When local KEM material is absent and BURNBAR_DISABLE_GATEWAY_HPKE_V5 is
    NOT set, the inbound version floor stays at v5. A v4 frame must be refused
    (fail closed, not silently degraded to v4)."""
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, **k)
    # The adapter cannot seal v5 (no local KEM seed), so effective send version
    # falls to v4, BUT the inbound FLOOR must remain at v5.
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 5
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="no-kem-seed-v4",
        payload={"text": "should be refused", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert received == [], (
        "Missing local KEM seed must NOT silently lower the inbound floor; "
        "a v4 frame must be refused on a v5-pinned link"
    )


@requires_v5
@pytest.mark.asyncio
async def test_missing_local_kem_seed_with_break_glass_allows_v4_frame(monkeypatch):
    """BURNBAR_DISABLE_GATEWAY_HPKE_V5=1 is the explicit break-glass. It lowers
    the effective floor to v4 even when the local KEM seed is absent."""
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, disable_v5=True, **k)
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 4
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="break-glass-v4-ok",
        payload={"text": "break glass works", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    await adapter._handle_burnbar_event(raw)
    assert [e.text for e in received] == ["break glass works"], (
        "BURNBAR_DISABLE_GATEWAY_HPKE_V5=1 must explicitly lower the floor to v4"
    )


# ══════════════════════════════════════════════════════════════════════════════
# Claim 4: ratchet_init v2 refuses a transmitted rootKeyBase64
# ══════════════════════════════════════════════════════════════════════════════

@requires_v5
@pytest.mark.asyncio
async def test_v2_init_transmitted_root_key_refused_through_full_handler(monkeypatch):
    """A v2 ratchet_init payload that contains a rootKeyBase64 field (ANY value)
    must be refused by the handler. The root must be derived from the KEM
    decapsulation alone; transmitting it is forbidden to prevent the relay from
    controlling the shared secret."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw, _phone, payload = _signed_ratchet_init_v2(adapter, k)

    # Inject a rootKeyBase64 into the payload and re-seal through the v5 lane.
    from tests.gateway.test_burnbar_plugin_v5 import _phone_to_agent_v5_event
    payload_with_root = dict(payload)
    payload_with_root["rootKeyBase64"] = base64.b64encode(b"A" * 32).decode("ascii")
    raw_with_root = _phone_to_agent_v5_event(
        event_id="v2-transmitted-root", payload=payload_with_root, **k
    )
    await adapter._handle_burnbar_event(raw_with_root)
    assert not adapter._can_ratchet("burnbar:home"), (
        "v2 init with a transmitted rootKeyBase64 must be refused"
    )
    assert received == []


@requires_v5
def test_v2_init_handler_direct_transmitted_root_refused(monkeypatch):
    """Direct probe of _handle_sealed_ratchet_init_v2: presence of rootKeyBase64
    (even a valid 32-byte random key) triggers the early refusal gate."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    _raw, _phone, payload = _signed_ratchet_init_v2(adapter, k)
    payload_with_root = dict(payload)
    payload_with_root["rootKeyBase64"] = base64.b64encode(b"\xFF" * 32).decode("ascii")
    result = adapter._handle_sealed_ratchet_init_v2(payload_with_root, "burnbar:home")
    assert result is False, "rootKeyBase64 in v2 payload must be immediately refused"
    assert adapter._ratchet_session("burnbar:home") is None


# ══════════════════════════════════════════════════════════════════════════════
# Audit §bullet 5: v2 init with wrong responderKemKeyID refused
# (tested standalone through the full signed handler path)
# ══════════════════════════════════════════════════════════════════════════════

@requires_v5
@pytest.mark.asyncio
async def test_v2_init_wrong_responder_kem_key_id_refused_full_path(monkeypatch):
    """A v2 init whose responderKemKeyID does not match the adapter's advertised
    KEM key must be refused, regardless of whether every other field is correct."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    _raw, _phone, payload = _signed_ratchet_init_v2(adapter, k)

    from tests.gateway.test_burnbar_plugin_v5 import _phone_to_agent_v5_event
    payload_bad_kid = dict(payload)
    payload_bad_kid["responderKemKeyID"] = "0" * 32  # does not match advertised key id
    raw_bad = _phone_to_agent_v5_event(event_id="v2-bad-kem-kid", payload=payload_bad_kid, **k)
    await adapter._handle_burnbar_event(raw_bad)
    assert not adapter._can_ratchet("burnbar:home"), (
        "Wrong responderKemKeyID must prevent session creation"
    )
    assert received == []


# ══════════════════════════════════════════════════════════════════════════════
# Claim 8: BURNBAR_DISABLE_GATEWAY_RATCHET=1 stops advertisement AND session use
# ══════════════════════════════════════════════════════════════════════════════

@requires_v5
def test_ratchet_disabled_kills_advertisement(monkeypatch):
    """BURNBAR_DISABLE_GATEWAY_RATCHET=1 must zero out the advertised ratchet
    init public key AND the KEM key so the phone cannot see a usable ratchet lane."""
    k = _keys()
    monkeypatch.delenv("BURNBAR_DISABLE_GATEWAY_RATCHET", raising=False)
    adapter = _paired_v5_adapter(monkeypatch, **k)
    # Before disabling: both advertisements are live.
    assert adapter._ratchet_init_public_key_for_advertisement() is not None
    pub, kid = adapter._ratchet_init_kem_key_for_advertisement()
    assert pub is not None and kid is not None

    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_RATCHET", "1")
    assert adapter._ratchet_init_public_key_for_advertisement() is None
    pub2, kid2 = adapter._ratchet_init_kem_key_for_advertisement()
    assert pub2 is None and kid2 is None


@requires_v5
@pytest.mark.asyncio
async def test_ratchet_disabled_mid_session_prevents_use(monkeypatch):
    """An established v2 ratchet session becomes unusable after
    BURNBAR_DISABLE_GATEWAY_RATCHET=1 is toggled on mid-session."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw, phone, _payload = _signed_ratchet_init_v2(adapter, k)
    await adapter._handle_burnbar_event(raw)
    assert adapter._can_ratchet("burnbar:home")

    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_RATCHET", "1")
    assert not adapter._can_ratchet("burnbar:home"), (
        "Ratchet session must be unusable after BURNBAR_DISABLE_GATEWAY_RATCHET=1"
    )
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(
            phone,
            {"text": "must not deliver", "destinationId": "burnbar:home"},
            "disabled-r1",
        )
    )
    assert received == []


@requires_v5
@pytest.mark.asyncio
async def test_ratchet_disabled_blocks_new_v2_init(monkeypatch):
    """BURNBAR_DISABLE_GATEWAY_RATCHET=1 prevents a new v2 init from establishing
    a session even if the wire frame is otherwise valid."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw, _phone, _payload = _signed_ratchet_init_v2(adapter, k)

    monkeypatch.setenv("BURNBAR_DISABLE_GATEWAY_RATCHET", "1")
    await adapter._handle_burnbar_event(raw)
    assert not adapter._can_ratchet("burnbar:home"), (
        "v2 init must not establish a session when ratchet is disabled"
    )
    assert received == []


# ══════════════════════════════════════════════════════════════════════════════
# Audit §bullet 9: restored old ratchet session file after high-water advances
# ══════════════════════════════════════════════════════════════════════════════

@requires_v5
@pytest.mark.asyncio
async def test_restored_old_v5_session_file_refused_after_high_water(monkeypatch):
    """An adversary who restores a backup of the ratchet session file (e.g. via
    snapshot rollback) after the durable high-water mark has been advanced must
    not be able to replay old frames."""
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)

    raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    await adapter._handle_burnbar_event(raw)
    sid = payload["sessionID"]

    # Snapshot session file BEFORE any frames (receive_message_number=0).
    session_file = _burnbar.RATCHET_SESSION_FILE
    pre_frame_snapshot = session_file.read_bytes()

    f0 = _phone_ratchet_frame(
        phone, {"text": "advance hw", "destinationId": "burnbar:home"}, "hw-adv-f0"
    )
    await adapter._handle_burnbar_event(f0)
    assert [e.text for e in received] == ["advance hw"]
    hw = adapter._e2ee_state.get_ratchet_receive_high_water(sid)
    assert hw >= 1, "High-water must be recorded after first message"

    # "Restore" the old session file (adversarial snapshot restore).
    session_file.write_bytes(pre_frame_snapshot)
    adapter._ratchet_sessions.clear()
    adapter._ratchet_sessions_loaded = False

    # Restored session has receive_message_number=0 < high_water → refused.
    assert not adapter._can_ratchet("burnbar:home"), (
        "Restored old ratchet session must be refused by the high-water guard"
    )

    # Replaying f0 with the rolled-back session must NOT re-deliver.
    await adapter._handle_burnbar_event({
        "id": "hw-adv-f0-replay",
        "destinationId": "burnbar:home",
        "ratchetEnvelope": f0["ratchetEnvelope"],
    })
    assert [e.text for e in received] == ["advance hw"], (
        "Old frame must not re-deliver after session restore with advanced high-water"
    )
