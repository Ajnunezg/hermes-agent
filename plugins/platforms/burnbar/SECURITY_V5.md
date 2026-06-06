# BurnBar Hermes Gateway E2EE v5 Security Notes

v5 is an additive relay lane. v1-v4 remain byte-stable.

## What v5 Changes

- Adds `relayKeyVersion = 5` for signed hybrid-KEM envelopes.
- Uses pyca `cryptography` HPKE `MLKEM768_X25519 + HKDF-SHA256 + AES-256-GCM`
  for content-key wrapping.
- Keeps v4's explicit Ed25519 sender signature and verifies it before HPKE open.
- Adds v5 KEM public keys to the pairing safety code.
- Adds ratchet-init v2, which derives the initial Double Ratchet root from a
  signed KEM transcript instead of accepting sender-chosen `rootKeyBase64`.
- Enforces the durable ratchet receive high-water so session-cache rollback cannot
  replay old ratchet frames.

## Threats Closed

| Threat | v5 defense | Regression test |
| --- | --- | --- |
| Relay downgrades a v5-pinned link to v4/v3/v2 | `_open_envelope` refuses `version < effective_pinned_version` before unwrap | `test_v5_link_refuses_downgraded_v4_frame`, `test_v5_inbound_floor_does_not_silently_degrade_when_local_kem_missing` |
| Recipient KEM key compromise forges sender identity | Ed25519 signature over the v5 transcript is required and pinned | `test_v5_recipient_kem_key_holder_cannot_forge_without_signing_key` |
| Sender chooses ratchet root | ratchet-init v2 derives root from KEM decap + transcript hash | `test_v5_signed_ratchet_init_v2_enables_chat_through_full_handler` |
| Malformed KEM ciphertext creates a dead session | root-confirm MAC verified before session commit | `test_v5_ratchet_init_v2_mutations_refused_through_handler` |
| Cache rollback replays ratchet frame | `_can_ratchet` / session load refuse receive counters below durable high-water | `test_receive_high_water_enforced_after_session_rollback` |
| PQ key substitution hidden from user | KEM public key is included in all-key safety code with tag `0x04` | `test_ratchet_init_v2_parity_vector` plus safety-code unit coverage |

## Operational Gates

Clean installs require:

```toml
gateway-e2ee = ["cryptography>=48,<49"]
```

If a link is pinned to v5 and the backend does not expose HPKE
`MLKEM768_X25519`, the adapter fails closed unless the operator explicitly sets:

```bash
BURNBAR_DISABLE_GATEWAY_HPKE_V5=1
```

That flag lowers the effective pin to v4. It is a break-glass rollback, not an
automatic downgrade.

The ratchet lane is separate: `BURNBAR_DISABLE_GATEWAY_RATCHET=1` stops ratchet
advertisement and session use without lowering the relay envelope floor.

## Ratchet Init v2

The v2 init payload is accepted only on a v5-pinned link and only when it is
opened from the signed relay lane. It must include:

- `ratchetInitVersion = 2`
- `algorithm = OpenBurnBar-HermesRatchet-v2-XWing-P256-HKDFSHA256-AESGCM`
- both P-256 ratchet public keys
- both derived device ids
- responder KEM public key and key id
- KEM ciphertext
- root-confirm MAC
- replayCounter

`rootKeyBase64` is forbidden for v2.

On successful v2 init, the adapter stores the session and rotates the ratchet-init
KEM key in one fsynced state-file replace. If the separate lineage write fails,
the session is rolled back while the KEM key remains consumed, so the same
captured init cannot recreate a session.

## Honest Residuals

- The ongoing message Double Ratchet is still classical P-256. v5 gives a hybrid
  PQ bootstrap/root, not a full Sparse Post-Quantum Ratchet.
- Authentication is still Ed25519. This is a break-now risk under a future
  signature-breaking quantum adversary, not a harvest-now-decrypt-later
  confidentiality risk. Hybrid PQ signatures remain future work.
- Pairing remains a human-confirmed safety-code flow. A user who accepts a wrong
  code can still pin the wrong peer.
- Timing, frequency, and destination metadata are outside the relay payload
  encryption boundary.

## Verification

Focused verification:

```bash
pytest tests/gateway/test_relay_e2ee_v5.py \
  tests/gateway/test_burnbar_plugin_v5.py \
  tests/gateway/test_audit_adversarial.py::test_receive_high_water_enforced_after_session_rollback -q
```

Regression verification:

```bash
pytest tests/gateway/test_burnbar_plugin_v4.py tests/gateway/test_audit_adversarial.py \
  tests/gateway/test_relay_e2ee_v4.py tests/gateway/test_hermes_ratchet.py \
  tests/gateway/test_burnbar_e2ee_state_store.py -q
```
