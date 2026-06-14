# V5 Adversarial Audit Handoff

Target worktree:

`/Users/albertonunez/.hermes/hermes-gateway-v4-upstream`

Implementation branch observed during this handoff:

`ajnunezg/burnbar-gateway-hardening-v4-upstream`

## Mission

Break the Hermes Gateway v5 E2EE implementation. Do not trust this handoff, code
comments, or previous reports. Reproduce every claim through the production
receive path where possible:

`plugins/platforms/burnbar/adapter.py::_handle_burnbar_event`

## New Surfaces

- `gateway/crypto/relay_e2ee_v5.py`
  - Hybrid KEM key format.
  - pyca HPKE v5 content-key wrap.
  - v5 Ed25519 signed envelope.
  - X-Wing-style KEM helper for ratchet-init v2 root seeding.
- `gateway/crypto/hermes_ratchet.py`
  - `RATCHET_INIT_ALGORITHM_V2`
  - `ratchet_init_v2_transcript`
  - `derive_ratchet_init_v2_root`
  - `ratchet_init_v2_root_confirm_mac`
- `plugins/platforms/burnbar/adapter.py`
  - v5 negotiation and downgrade floor.
  - v5 open/seal dispatch.
  - default-on signed ratchet advertisement with explicit
    `BURNBAR_DISABLE_GATEWAY_RATCHET=1` break-glass disable.
  - ratchet-init v2 KEM root validation.
  - receive high-water rollback refusal.
- `tests/gateway/fixtures/hermes_ratchet_init_v2.json`
  - Static parity fixture.

## Claims To Reproduce

1. A v5 frame opens only when signed by the pinned peer Ed25519 key.
2. A holder of the recipient KEM private key cannot forge sender identity.
3. A v5-pinned link refuses v4/v3/v2 inbound frames before unwrap unless
   `BURNBAR_DISABLE_GATEWAY_HPKE_V5=1` deliberately lowers the effective pin.
   Missing local KEM material must fail closed; it must not silently lower the
   inbound floor.
4. `ratchet_init` v2 refuses transmitted `rootKeyBase64`.
5. `ratchet_init` v2 derives root from KEM decap plus transcript hash and verifies
   `rootConfirmMacBase64` before session commit.
6. Mutating any v2 binding field prevents session creation.
7. Successful v2 init rotates/consumes the advertised ratchet-init KEM key.
8. The signed ratchet-init lane is advertised by default once crypto is available;
   `BURNBAR_DISABLE_GATEWAY_RATCHET=1` stops advertisement and session use.
9. A rolled-back ratchet session whose receive counter is lower than durable
   `ratchetReceiveHighWater` is refused before decrypt.
10. Chat text that looks like JSON/control remains chat text; controls do not run
   from the ratchet lane.
11. v1-v4 behavior remains byte-stable except for the intended stricter rule that
    a failed replay-counter commit creates no ratchet session side effect.

## Required Repros

Run:

```bash
source .venv/bin/activate
pytest tests/gateway/test_relay_e2ee_v5.py -q
pytest tests/gateway/test_burnbar_plugin_v5.py -q
pytest tests/gateway/test_audit_adversarial.py -q
pytest tests/gateway/test_adversarial_v5_handoff.py -q
pytest tests/gateway/test_v5_adversarial_probe.py -q
pytest tests/gateway/test_burnbar_plugin_v4.py tests/gateway/test_relay_e2ee_v4.py \
  tests/gateway/test_hermes_ratchet.py tests/gateway/test_burnbar_e2ee_state_store.py -q
```

Then add your own hostile tests for:

- v5 envelope with valid HPKE but wrong signature.
- v5 envelope with valid signature but wrong recipient KEM key.
- v5 envelope relabeled as v4, v3, v2, missing version, or malformed version.
- v5-pinned adapter with missing local KEM seed receiving a valid v4 frame
  (must refuse unless `BURNBAR_DISABLE_GATEWAY_HPKE_V5=1` was set before startup).
- v2 ratchet init with wrong responder KEM key id.
- v2 ratchet init with tampered `destinationId`, `sessionID`, replayCounter,
  both ratchet public keys, both device ids, KEM ciphertext, and root MAC.
- crash/write-failure injection around v2 session commit, KEM key rotation, and
  lineage write.
- `BURNBAR_DISABLE_GATEWAY_RATCHET=1` blocks capability advertisement and use.
- restored old ratchet session file after durable high-water advances.

## Expected Finding Format

Report only findings you reproduce. For each:

- severity
- file/line
- runnable repro
- exploit impact
- precise fix
- catching regression test

## Known Residuals That Are Not Bugs By Themselves

- Ongoing ratchet remains P-256; ongoing post-quantum ratchet recovery is a
  BurnBar product-lane roadmap item, not part of the MIT upstream lane.
- Sender authentication remains Ed25519, not hybrid/PQ signature.
- Pairing is still TOFU plus human safety-code confirmation.
- Metadata outside encrypted payloads remains visible to the relay.

## Audit Results (2026-06-05)

**165 tests passed** across the required repro suites plus the hostile follow-ups in
`test_adversarial_v5_handoff.py` and `test_v5_adversarial_probe.py`.

| Claim | Status | Primary repro |
|-------|--------|---------------|
| 1. v5 opens only on pinned peer Ed25519 sig | Verified | `test_v5_valid_hpke_wrong_signature_refused` |
| 2. Recipient KEM holder cannot forge sender | Verified | `test_v5_valid_signature_wrong_recipient_kem_refused` |
| 3. v5-pinned link refuses v4/v3/v2 downgrade | Verified | `test_v5_relabeled_version_refused`, `test_missing_local_kem_seed_refuses_v4_frame_fail_closed` |
| 4. v2 init refuses transmitted `rootKeyBase64` | Verified | `test_v2_init_transmitted_root_key_refused_through_full_handler` |
| 5. v2 root derived from KEM + transcript MAC | Verified | `test_v2_init_every_field_mutation_refused` (incl. `rootConfirmMacBase64`) |
| 6. Every v2 binding field mutation refused | Verified | `test_v2_init_every_field_mutation_refused` |
| 7. Successful v2 init rotates KEM key | Verified | `test_v2_init_rotates_kem_key_and_blocks_replay` |
| 8. Ratchet advertised by default; disable stops ad + use | Verified (fixed) | `test_ratchet_disabled_kills_advertisement` |
| 9. Rolled-back session below high-water refused | Verified | `test_v2_receive_high_water_rollback_refused`, `test_restored_old_v5_session_file_refused_after_high_water` |
| 10. JSON-looking chat stays chat; controls dropped | Verified | `test_v2_ratchet_control_payload_dropped_text_preserved` |
| 11. v1–v4 byte-stable + stricter replay commit | Verified | `test_burnbar_plugin_v4.py` regression suite |

No confidentiality or integrity breaks reproduced on the production receive path.

## Findings

### FIXED — `BURNBAR_DISABLE_GATEWAY_RATCHET=1` did not block capability advertisement

- **Severity**: Low (use was blocked, but peer could be confused by advertised keys)
- **File/Line**: `plugins/platforms/burnbar/adapter.py` — instance methods
  `_ratchet_init_public_key_for_advertisement` and
  `_ratchet_init_kem_key_for_advertisement` (module-level helpers at ~725 already
  gated correctly)
- **Runnable Repro**: `pytest tests/gateway/test_adversarial_v5_handoff.py::test_ratchet_disabled_kills_advertisement -q`
- **Exploit Impact**: A peer could initiate a ratchet handshake believing the agent
  supports it, only for the agent to drop initiation because `_can_ratchet` blocked use.
- **Fix applied**: Check `_gateway_ratchet_disabled()` before returning advertisement
  material in both instance methods.
- **Catching regression tests**: `test_ratchet_disabled_kills_advertisement`,
  `test_ratchet_disabled` in `tests/gateway/test_audit_adversarial.py`.

### FIXED — v1/v2 init crash between session write and lineage write self-heals

- **Severity before fix**: Info / liveness (fail-closed; chat fell back to the signed lane)
- **File/Line**: `plugins/platforms/burnbar/adapter.py` — v1/v2 idempotent init branches
- **Runnable Regression**:
  `pytest tests/gateway/test_v5_adversarial_probe.py::test_v2_init_crash_orphan_self_heals -q`
- **Fix**: if a fully re-authenticated init hits the existing-session branch and the
  durable lineage marker is absent, the adapter re-marks lineage before returning.
  The v2 branch is reached only after the v5 signature, replay gate, X-Wing decap,
  and root-confirm MAC pass; the v1 branch is reached only after signed-lane
  authentication and replay gating.
- **Catching regression test**: `test_v2_init_crash_orphan_self_heals`.
