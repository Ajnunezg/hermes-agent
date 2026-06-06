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
| Silent send-side PQ downgrade (v5 pin, local KEM unavailable) emits classical v4 to the relay | `_emit_version_or_refuse` fails closed when `floor >= v5` but emission `< v5`; PQ-scoped (v4→v3/v3→v2 auth fallbacks unaffected) | `test_v5_pinned_missing_kem_refuses_to_send_below_floor`, `test_v5_break_glass_allows_send_at_lowered_floor` |
| Classical file-body key wrap on a v5 link (harvest-now for FILES) | `seal_attachment` carries the body key inside a v4/v5 SIGNED manifest (hybrid-KEM wrapped at v5); fails closed on a v5 pin when a PQ wrap can't be emitted | `test_attachment_v5_roundtrip_body_key_is_pq_wrapped`, `test_attachment_v5_pin_fails_closed_without_peer_caps` |
| Crash between v2-init session write and lineage write permanently disables the ratchet | Idempotent existing-session branch self-heals the lineage (reached only after full re-auth) | `test_v2_init_crash_orphan_self_heals` |

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
captured init cannot recreate a session. A crash *between* the session write and
the (separate-file) lineage write would otherwise orphan an unusable session; the
idempotent re-init path self-heals the lineage on the next authenticated init, so
the ratchet lane recovers instead of staying permanently disabled.

## Attachment Body-Key Wrap (v5)

The file BODY has always been AES-256-GCM-sealed under a per-attachment `body_key`
(post-quantum safe). Before this lane the `body_key` itself was wrapped with the
classical v3 HPKE wrap even on a v5-pinned link — a silent harvest-now-decrypt-later
gap for FILE contents. v5 closes it:

- On a v4/v5 link whose peer advertises signed-attachment support, the `body_key`
  is carried as `bodyKeyBase64` **inside the signed manifest**, which is sealed with
  `seal_signed_v4`/`seal_signed_v5` (the body-key's own transport content key is
  wrapped at the pinned version — hybrid ML-KEM at v5). One Ed25519 signature
  authenticates the manifest and the wrap together. The large body blob stays
  sealed separately under its own distinct AAD.
- **Capability negotiation:** the peer advertises
  `supportsGatewayAttachmentWrapVersions` (a list of v4/v5); the agent reads the
  peer's authenticated value from `BURNBAR_RELAY_PEER_ATTACHMENT_WRAP_VERSIONS`.
  Absent ⇒ the legacy v2/v3 wrap is kept byte-for-byte, so a phone that has not
  shipped signed-attachment open is never bricked.
- **Stopgap (fail closed):** on a v5 pin, if a v5 attachment wrap cannot be emitted
  (peer not yet capable, or local KEM unavailable), `seal_attachment` refuses rather
  than silently shipping a classical body key. Operators migrating an installed base
  may opt into the classical wrap with `BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS=1`
  (logged each time). The legacy path is unchanged for v2/v3 links.

The wire format the phone must mirror is documented in
`docs/gateway/RELAY_E2EE_V5_SPEC.md`.

## Honest Residuals

- The ongoing message Double Ratchet is still classical P-256. v5 gives a hybrid
  PQ bootstrap/root, not a full Sparse Post-Quantum Ratchet. See *Post-Quantum
  Roadmap* below.
- Authentication is still Ed25519. This is a break-now risk under a future
  signature-breaking quantum adversary, not a harvest-now-decrypt-later
  confidentiality risk. Hybrid PQ signatures remain future work (see roadmap).
- Pairing remains a human-confirmed safety-code flow. A user who accepts a wrong
  code can still pin the wrong peer.
- Timing, frequency, and destination metadata are outside the relay payload
  encryption boundary.
- File-body PQ confidentiality now follows the link pin (above), but only once the
  PEER has shipped signed-attachment open; until then a v5 link fails closed for
  file sends unless the operator opts into the classical wrap.

## Post-Quantum Roadmap

These are the only items between v5 and a fully post-quantum lane. Both are
*break-now* (not harvest-now) gaps, so confidentiality of recorded traffic is
already PQ; these close the remaining authentication and ongoing-ratchet gaps.

1. **Hybrid PQ sender signature.** Replace (or hybridize) the Ed25519 sender
   signature with a PQ signature (e.g. ML-DSA / FN-DSA) so a future quantum
   adversary cannot forge a sender after the fact. Pairing already reserves the
   `0x05` `PAIRING_TAG_PQ_SIGNING` tag for the second signing key, so the safety
   code and key-pinning plumbing are ready; the work is the dual-sign / dual-verify
   transcript and a v6 envelope marker. Keep Ed25519 in the hybrid until PQ
   signatures are broadly validated.
2. **Post-quantum ongoing ratchet (SPQR).** The v5 root is PQ-seeded (X-Wing), but
   each DH ratchet step is classical P-256. A Sparse Post-Quantum Ratchet would
   carry a periodic ML-KEM re-encapsulation alongside the P-256 step so post-
   compromise security heals against a quantum adversary too. This is the larger
   effort (new ratchet state + cross-language parity) and should land behind its own
   `ratchetInitVersion`/algorithm string with a parity fixture.

Neither blocks shipping v5: confidentiality (incl. file bodies) is PQ today.

## Verification

Focused verification:

```bash
pytest tests/gateway/test_relay_e2ee_v5.py \
  tests/gateway/test_burnbar_plugin_v5.py \
  tests/gateway/test_audit_adversarial.py::test_receive_high_water_enforced_after_session_rollback -q
```

Adversarial audit gate (run in CI via `scripts/run_tests_parallel.py` auto-discovery):

```bash
pytest tests/gateway/test_v5_adversarial_probe.py \
  tests/gateway/test_v5_attachment_wrap.py -q
```

Regression verification:

```bash
pytest tests/gateway/test_burnbar_plugin_v4.py tests/gateway/test_audit_adversarial.py \
  tests/gateway/test_relay_e2ee_v4.py tests/gateway/test_hermes_ratchet.py \
  tests/gateway/test_burnbar_e2ee_state_store.py -q
```
