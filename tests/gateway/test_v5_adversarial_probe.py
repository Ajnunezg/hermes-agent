"""HOSTILE follow-up repros for V5_ADVERSARIAL_AUDIT_HANDOFF.md.

These do NOT trust the handoff or the shipped regression tests. Every claim is
reproduced through the production receive path
``BurnBarAdapter._handle_burnbar_event`` where possible. Each test is written to
*break* the v5 hybrid-KEM signed lane and the v2 PQ ratchet-init lane.

Run: pytest tests/gateway/test_v5_adversarial_probe.py -q
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

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
    _phone_to_agent_v5_event,
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

    async def capture(event):
        received.append(event)

    adapter.handle_message = capture
    return received


def _v5_event_with(*, agent_kem, agent_sig, sender_sig, recipient_kem_public, event_id, payload):
    """A v5 frame addressed to ``recipient_kem_public`` and signed by ``sender_sig``.

    Splitting recipient-KEM and signer lets us forge: a wrong signer, or a wrap
    to the wrong KEM key, while keeping every other field well-formed.
    """
    payload_aad = _burnbar._gateway_event_aad(_UID, _CLIENT, event_id)
    key_aad = _burnbar._gateway_event_key_aad(_UID, _CLIENT, event_id)
    env = v5.seal_signed_v5(
        json.dumps(payload).encode("utf-8"),
        recipient_kem_public=recipient_kem_public,
        recipient_verify_key=agent_sig.public_key_base64(),
        sender_signing_key=sender_sig,
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
            "senderSigningKey": sender_sig.public_key_base64(),
        },
    }


# ── POSITIVE CONTROLS: prove the custom harness DELIVERS/ESTABLISHES on the
# honest path, so the all-refusal negatives below are not passing vacuously. ───
@requires_v5
@pytest.mark.asyncio
async def test_control_v5_event_with_helper_delivers_when_correct(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _v5_event_with(
        agent_kem=k["agent_kem"],
        agent_sig=k["agent_sig"],
        sender_sig=k["phone_sig"],  # genuine pinned sender
        recipient_kem_public=k["agent_kem"].public_key(),  # correct recipient
        event_id="evt-control-ok",
        payload={"text": "honest", "destinationId": "burnbar:home", "replayCounter": 1},
    )
    await adapter._handle_burnbar_event(raw)
    assert [e.text for e in received] == ["honest"]


@requires_v5
@pytest.mark.asyncio
async def test_control_unmutated_v2_init_establishes(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    _capture(adapter)
    _raw, _phone, base_payload = _signed_ratchet_init_v2(adapter, k)
    # Re-seal the UN-mutated base_payload through the same path the mutation tests
    # use; it must establish a usable ratchet session.
    raw = _phone_to_agent_v5_event(event_id="v2-control-ok", payload=dict(base_payload), **k)
    await adapter._handle_burnbar_event(raw)
    assert adapter._can_ratchet("burnbar:home")


# ── Claim 1 / Claim 2: valid HPKE wrap but WRONG signature is refused. A holder
# of the recipient KEM private key (i.e. who can produce a perfectly good wrap to
# the agent) still cannot forge the pinned-peer sender identity. ───────────────
@requires_v5
@pytest.mark.asyncio
async def test_v5_valid_hpke_wrong_signature_refused(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    attacker_sig = v4.generate_signing_key()  # NOT the pinned phone signing key
    raw = _v5_event_with(
        agent_kem=k["agent_kem"],
        agent_sig=k["agent_sig"],
        sender_sig=attacker_sig,
        recipient_kem_public=k["agent_kem"].public_key(),  # correct recipient KEM
        event_id="evt-wrong-sig",
        payload={"text": "forged sender", "destinationId": "burnbar:home", "replayCounter": 1},
    )
    await adapter._handle_burnbar_event(raw)
    assert received == []


# ── Claim 2: valid pinned-peer signature but the HPKE wrap targets the WRONG
# recipient KEM key. The transcript binds the recipient KEM key, recomputed from
# the agent's own private seed, so the signature fails to verify. ──────────────
@requires_v5
@pytest.mark.asyncio
async def test_v5_valid_signature_wrong_recipient_kem_refused(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    other_kem = v5.generate_kem_private_key()  # not the agent's KEM
    raw = _v5_event_with(
        agent_kem=k["agent_kem"],
        agent_sig=k["agent_sig"],
        sender_sig=k["phone_sig"],  # genuine pinned sender
        recipient_kem_public=other_kem.public_key(),  # wrong recipient
        event_id="evt-wrong-kem",
        payload={"text": "misaddressed", "destinationId": "burnbar:home", "replayCounter": 1},
    )
    await adapter._handle_burnbar_event(raw)
    assert received == []


# ── Claim 3: a v5-pinned link refuses every relabeling of a valid v5 frame
# (down to v4/v3/v2, missing, malformed, or a bogus-high version) BEFORE unwrap. ─
@requires_v5
@pytest.mark.asyncio
@pytest.mark.parametrize("relabel", [4, 3, 2, 1, 0, 9, "abc", None, "remove"])
async def test_v5_relabeled_version_refused(monkeypatch, relabel):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v5_event(
        event_id=f"evt-relabel-{relabel}",
        payload={"text": "relabeled", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    if relabel == "remove":
        raw["relayEnvelope"].pop("relayKeyVersion", None)
    else:
        raw["relayEnvelope"]["relayKeyVersion"] = relabel
    await adapter._handle_burnbar_event(raw)
    assert received == []


# ── Claim 3: a v5 frame relabeled to v5 but carrying a non-v5 relayEncryption
# marker (or a v4 frame forced to version 5) is refused by the marker/enc-length
# checks inside the v5 opener. ────────────────────────────────────────────────
@requires_v5
@pytest.mark.asyncio
async def test_v5_wrong_encryption_marker_refused(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v5_event(
        event_id="evt-bad-marker",
        payload={"text": "x", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    raw["relayEnvelope"]["relayEncryption"] = _burnbar.GATEWAY_RELAY_ENCRYPTION_V4
    await adapter._handle_burnbar_event(raw)
    assert received == []


@requires_v5
@pytest.mark.asyncio
async def test_v4_frame_forced_to_v5_refused(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    raw = _phone_to_agent_v4_event(
        event_id="evt-v4-as-v5",
        payload={"text": "v4 as v5", "destinationId": "burnbar:home", "replayCounter": 1},
        **k,
    )
    raw["relayEnvelope"]["relayKeyVersion"] = 5
    raw["relayEnvelope"]["relayEncryption"] = _burnbar.GATEWAY_RELAY_ENCRYPTION_V5
    await adapter._handle_burnbar_event(raw)
    assert received == []


# ── Claim 6: EVERY v2 ratchet-init binding field, re-signed by the genuine phone
# (valid outer signature), is refused by the inner transcript+KEM-confirm MAC.
# This is the strongest mutation test: the relay-signature layer is intentionally
# satisfied so only the inner handshake binding can catch each tamper. ─────────
def _v2_init_field_mutations(base_payload):
    wrong_pair = hr.generate_key_pair()
    wrong_kem = v5.generate_kem_private_key()
    return {
        "destinationId": dict(base_payload, destinationId="burnbar:evil"),
        "sessionID": dict(base_payload, sessionID="0" * 64),
        "replayCounter": dict(base_payload, replayCounter=base_payload["replayCounter"] + 1),
        "initiatorRatchetPublicKeyBase64": dict(
            base_payload, initiatorRatchetPublicKeyBase64=wrong_pair.public_key_base64
        ),
        "responderRatchetPublicKeyBase64": dict(
            base_payload, responderRatchetPublicKeyBase64=wrong_pair.public_key_base64
        ),
        "initiatorDeviceID": dict(base_payload, initiatorDeviceID="0" * 32),
        "responderDeviceID": dict(base_payload, responderDeviceID="0" * 32),
        "responderKemKeyID": dict(base_payload, responderKemKeyID="0" * 32),
        "responderKemPublicKeyBase64": dict(
            base_payload, responderKemPublicKeyBase64=wrong_kem.public_key_base64()
        ),
        "algorithm": dict(base_payload, algorithm="OpenBurnBar-Evil-v9"),
    }


@requires_v5
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "destinationId",
        "sessionID",
        "replayCounter",
        "initiatorRatchetPublicKeyBase64",
        "responderRatchetPublicKeyBase64",
        "initiatorDeviceID",
        "responderDeviceID",
        "responderKemKeyID",
        "responderKemPublicKeyBase64",
        "algorithm",
    ],
)
async def test_v2_init_every_field_mutation_refused(monkeypatch, field):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    _raw, phone, base_payload = _signed_ratchet_init_v2(adapter, k)
    mutated = _v2_init_field_mutations(base_payload)[field]
    raw = _phone_to_agent_v5_event(event_id=f"v2-bad-{field}", payload=mutated, **k)
    await adapter._handle_burnbar_event(raw)
    assert not adapter._can_ratchet("burnbar:home"), f"{field} mutation established a session"
    assert adapter._ratchet_session("burnbar:home") is None
    # And a chat frame on the (non-existent) session must not deliver.
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "must not deliver", "destinationId": "burnbar:home"}, f"f-{field}")
    )
    assert received == []


# ── Claim 7: a successful v2 init consumes/rotates the advertised KEM init key,
# so the SAME init ciphertext cannot be replayed to seed a second session. ─────
@requires_v5
@pytest.mark.asyncio
async def test_v2_init_rotates_kem_key_and_blocks_replay(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    _capture(adapter)
    init_raw, _phone, payload = _signed_ratchet_init_v2(adapter, k)
    before = payload["responderKemKeyID"]
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._can_ratchet("burnbar:home")
    after = adapter._ensure_ratchet_init_kem_key_pair().key_id()
    assert after != before
    # Replaying the exact same init (same event id + counter) is a no-op: the
    # event-id/counter gate drops it and the session is unchanged.
    sid = adapter._ratchet_session_id("burnbar:home")
    await adapter._handle_burnbar_event(copy.deepcopy(init_raw))
    assert adapter._ratchet_session_id("burnbar:home") == sid
    assert adapter._ensure_ratchet_init_kem_key_pair().key_id() == after


# ── Crash/write-failure injection at the v2 session commit: a failed durable
# write leaves NO session and does NOT consume the advertised KEM key. ─────────
@requires_v5
@pytest.mark.asyncio
async def test_v2_init_commit_write_failure_is_atomic(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    kem_before = adapter._ensure_ratchet_init_kem_key_pair().key_id()
    # Fail every ratchet-state write from now on.
    monkeypatch.setattr(_burnbar, "_write_ratchet_state_file", lambda **kw: False, raising=True)
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._ratchet_session("burnbar:home") is None
    assert not adapter._can_ratchet("burnbar:home")
    # KEM key must NOT have rotated (the commit rolled back in-memory + on disk).
    assert adapter._ensure_ratchet_init_kem_key_pair().key_id() == kem_before
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "x", "destinationId": "burnbar:home"}, "f-commitfail")
    )
    assert received == []


# ── Crash injection at the lineage write: if marking the durable lineage throws
# AFTER the session commit, the session is rolled back and stays UNUSABLE (no
# replay window opens, chat falls back to the v4-signed lane). ────────────────
@requires_v5
@pytest.mark.asyncio
async def test_v2_init_lineage_write_failure_fails_closed(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init_v2(adapter, k)

    def _boom(_sid):
        raise _burnbar.BurnBarE2EEStateError("injected lineage write failure")

    monkeypatch.setattr(adapter._e2ee_state, "mark_ratchet_lineage", _boom, raising=True)
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._ratchet_session("burnbar:home") is None
    assert not adapter._can_ratchet("burnbar:home")
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(phone, {"text": "x", "destinationId": "burnbar:home"}, "f-lineagefail")
    )
    assert received == []


# ── Claim 9: a rolled-back ratchet session file (receive counter below the
# durable high-water) is refused before decrypt; the captured old frame that
# advanced the high-water cannot re-deliver. ──────────────────────────────────
@requires_v5
@pytest.mark.asyncio
async def test_v2_receive_high_water_rollback_refused(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    sid = payload["sessionID"]

    f0 = _phone_ratchet_frame(phone, {"text": "m0", "destinationId": "burnbar:home"}, "rm0")
    pre = copy.deepcopy(adapter._ratchet_session("burnbar:home"))  # receive #0
    await adapter._handle_burnbar_event(f0)
    assert [e.text for e in received] == ["m0"]
    assert adapter._e2ee_state.get_ratchet_receive_high_water(sid) >= 1

    # Roll the session (memory + disk) back to before m0, then replay m0.
    adapter._ratchet_sessions["burnbar:home"] = copy.deepcopy(pre)
    adapter._save_ratchet_sessions()
    await adapter._handle_burnbar_event(
        {"id": "rm0-replay", "destinationId": "burnbar:home", "ratchetEnvelope": f0["ratchetEnvelope"]}
    )
    assert [e.text for e in received] == ["m0"]  # NOT redelivered
    assert not adapter._can_ratchet("burnbar:home")


# ── Replay defense: a valid v5 message replayed with a fresh event id but the
# SAME (already-committed) replayCounter is dropped by the durable high-water. ─
@requires_v5
@pytest.mark.asyncio
async def test_v5_message_replay_with_new_id_same_counter_dropped(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    p = {"text": "once", "destinationId": "burnbar:home", "replayCounter": 7}
    await adapter._handle_burnbar_event(_phone_to_agent_v5_event(event_id="m-a", payload=p, **k))
    # New event id, identical authenticated replayCounter -> must be refused.
    await adapter._handle_burnbar_event(_phone_to_agent_v5_event(event_id="m-b", payload=dict(p), **k))
    # Lower counter, fresh id -> also refused.
    await adapter._handle_burnbar_event(
        _phone_to_agent_v5_event(event_id="m-c", payload={"text": "older", "destinationId": "burnbar:home", "replayCounter": 3}, **k)
    )
    assert [e.text for e in received] == ["once"]


# ── Durability probe (crash BETWEEN the two v2-init writes). The handler commits
# the session + KEM rotation in write #1, then marks the durable lineage in a
# SEPARATE file in write #2. A power loss after write #1 but before write #2
# orphans a session whose lineage is never marked. This reproduces the resulting
# state through the production path and shows that a legitimate re-init does NOT
# self-heal it (the idempotent existing-session branch returns True without
# re-marking lineage), so the ratchet lane stays permanently disabled for that
# destination. FAIL-CLOSED (chat falls back to the v4-signed lane), so this is a
# liveness/availability robustness note, not a confidentiality/integrity break.
def _build_v2_init(adapter, k, phone_pair, *, event_id, replay_counter):
    agent_pair = adapter._ensure_ratchet_init_key_pair()
    agent_kem = adapter._ensure_ratchet_init_kem_key_pair()
    kem_shared, kem_ct = v5.xwing_encapsulate(agent_kem.public_key())
    kem_ct_b64 = base64.b64encode(kem_ct).decode("ascii")
    session_id = hr.derive_session_id(
        uid=_UID, client_id=_CLIENT,
        agent_ratchet_public_key_base64=agent_pair.public_key_base64,
        peer_ratchet_public_key_base64=phone_pair.public_key_base64,
    )
    initiator_device = hr.derive_device_id(phone_pair.public_key_base64)
    responder_device = hr.derive_device_id(agent_pair.public_key_base64)
    transcript = hr.ratchet_init_v2_transcript(
        uid=_UID, client_id=_CLIENT, destination_id="burnbar:home", session_id=session_id,
        initiator_ratchet_public_key_base64=phone_pair.public_key_base64,
        responder_ratchet_public_key_base64=agent_pair.public_key_base64,
        initiator_device_id=initiator_device, responder_device_id=responder_device,
        responder_kem_public_key_base64=agent_kem.public_key_base64(),
        responder_kem_key_id=agent_kem.key_id(), kem_ciphertext_base64=kem_ct_b64,
        replay_counter=replay_counter,
    )
    root = hr.derive_ratchet_init_v2_root(kem_shared, transcript)
    root_mac = hr.ratchet_init_v2_root_confirm_mac(root, transcript)
    payload = {
        "kind": _burnbar.RATCHET_INIT_KIND, "ratchetInitVersion": 2,
        "algorithm": hr.RATCHET_INIT_ALGORITHM_V2, "uid": _UID, "clientId": _CLIENT,
        "destinationId": "burnbar:home", "sessionID": session_id,
        "initiatorRatchetPublicKeyBase64": phone_pair.public_key_base64,
        "responderRatchetPublicKeyBase64": agent_pair.public_key_base64,
        "initiatorDeviceID": initiator_device, "responderDeviceID": responder_device,
        "responderKemPublicKeyBase64": agent_kem.public_key_base64(),
        "responderKemKeyID": agent_kem.key_id(), "kemCiphertextBase64": kem_ct_b64,
        "rootConfirmMacBase64": base64.b64encode(root_mac).decode("ascii"),
        "replayCounter": replay_counter,
    }
    return _phone_to_agent_v5_event(event_id=event_id, payload=payload, **k), session_id


@requires_v5
@pytest.mark.asyncio
async def test_v2_init_crash_orphan_self_heals(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    _capture(adapter)
    phone_pair = hr.generate_key_pair()

    # 1) Honest establish (lineage marked, KEM rotates to the successor).
    init1, sid = _build_v2_init(adapter, k, phone_pair, event_id="orphan-1", replay_counter=1)
    await adapter._handle_burnbar_event(init1)
    assert adapter._can_ratchet("burnbar:home")

    # 2) Simulate a crash AFTER write #1 (session + KEM rotation are durable) but
    #    BEFORE write #2 (lineage). i.e. the lineage marker was never persisted.
    adapter._e2ee_state.clear_ratchet_lineage(sid)
    assert not adapter._can_ratchet("burnbar:home")  # orphaned session is unusable

    # 3) The phone legitimately re-inits with the SAME ratchet keys and the
    #    CURRENT advertised KEM key (fresh counter, fresh event id) -> reaches the
    #    idempotent existing-session branch, which now SELF-HEALS the lineage.
    init2, sid2 = _build_v2_init(adapter, k, phone_pair, event_id="orphan-2", replay_counter=2)
    assert sid2 == sid
    await adapter._handle_burnbar_event(init2)

    # FIXED: lineage is re-marked and the ratchet lane recovers (no permanent
    # self-inflicted disable after a crash between the two durable writes).
    assert adapter._e2ee_state.ratchet_lineage_exists(sid)
    assert adapter._can_ratchet("burnbar:home")


# ── Finding A (send-side floor symmetry): a v5-pinned link whose local KEM is
# unavailable must NOT silently emit a classical v4 frame to the relay. The send
# path is now symmetric with the inbound floor: it fails closed (loud) instead of
# handing the untrusted relay a non-PQ ciphertext. ────────────────────────────
@requires_v5
@pytest.mark.asyncio
async def test_v5_pinned_missing_kem_refuses_to_send_below_floor(monkeypatch):
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, **k)
    # Sanity: emission resolves to v4 but the floor is still v5 (the gap).
    assert adapter._peer_relay_key_version_for("burnbar:home") == 4
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 5
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.seal_message(destination_id="burnbar:home", text="must not leak as v4")
    with pytest.raises(_burnbar._RelayPlaintextRefused):
        adapter._sealer.seal_model_switch(destination_id="burnbar:home", model_id="claude-opus-4-8")


@requires_v5
@pytest.mark.asyncio
async def test_v5_break_glass_allows_send_at_lowered_floor(monkeypatch):
    # Explicit break-glass lowers BOTH directions to v4, so a v4 send is allowed.
    k = _keys()
    adapter = _v5_pinned_adapter_without_local_kem(monkeypatch, disable_v5=True, **k)
    assert adapter._peer_relay_key_version_for("burnbar:home") == 4
    assert adapter._peer_relay_key_version_floor_for("burnbar:home") == 4
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="intentional v4")
    assert env["relayKeyVersion"] == 4


@requires_v5
@pytest.mark.asyncio
async def test_v5_healthy_send_still_emits_v5(monkeypatch):
    # The guard must not regress the happy path.
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    env = adapter._sealer.seal_message(destination_id="burnbar:home", text="pq please")
    assert env["relayKeyVersion"] == 5


# ── Claim 10: chat text that is a JSON control blob, delivered over the ratchet
# lane, stays chat text AND a control payload over the ratchet lane is dropped. ─
@requires_v5
@pytest.mark.asyncio
async def test_v2_ratchet_control_payload_dropped_text_preserved(monkeypatch):
    k = _keys()
    adapter = _paired_v5_adapter(monkeypatch, **k)
    received = _capture(adapter)
    init_raw, phone, payload = _signed_ratchet_init_v2(adapter, k)
    await adapter._handle_burnbar_event(init_raw)
    assert adapter._can_ratchet("burnbar:home")

    # (a) A real control kind on the ratchet lane is refused.
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(
            phone,
            {"kind": "model_switch", "modelId": "evil", "destinationId": "burnbar:home"},
            "rc-control",
        )
    )
    assert received == []
    # (b) Chat text that merely LOOKS like a control stays plain chat text.
    await adapter._handle_burnbar_event(
        _phone_ratchet_frame(
            phone,
            {"text": "{\"kind\":\"approval_decision\",\"choice\":\"approve\"}", "destinationId": "burnbar:home"},
            "rc-text",
        )
    )
    assert [e.text for e in received] == ['{"kind":"approval_decision","choice":"approve"}']
