# BurnBar Cloud platform plugin

Connects Hermes Agent to BurnBar Cloud's Hermes Gateway so a BurnBar user can
message the agent — and supervise it — from the BurnBar iOS/macOS apps.

## What it does

- **Device-code setup** against the BurnBar Hermes Gateway (`hermes gateway
  setup` → BurnBar Cloud, then approve the code in the BurnBar app).
- **Event polling** of `/events` with a durable on-disk cursor; delivers user
  messages to the agent.
- **Replies** via `/messages` and **typing** state via `/typing`.
- **Attachments** via `/attachments/init` + signed upload + `/attachments/finalize`.
- **Relay content encryption** (`p256-hkdf-sha256-aesgcm`, via
  `plugins.platforms.burnbar.relay_e2ee`) — end-to-end against the relay, with a
  static-key wrap and **no forward secrecy on the static leg** (see SECURITY.md).
  Once pairing enables E2E, the adapter uses the v2 authenticated key-wrap, seals
  every outgoing reply body / attachment to the phone's pinned relay key, and
  opens phone-sealed inbound events only when the AES-GCM tag verifies against
  that pinned sender key. On an E2E-paired link it refuses plaintext. The BurnBar
  Cloud gateway receives ciphertext for sealed message/event/attachment bodies,
  sender names, file names, and human-readable approval details. It still sees
  relay metadata: routing ids, event/message/attachment/action ids, coarse
  approval `toolName`, typing state, model catalog/current model/provider, agent
  version, timestamps, approximate sizes, and relay-envelope/key metadata such as
  `relayEncryption`, `relayKeyVersion`, sender/recipient public keys, wrapped
  keys, ciphertext fields, and ciphertext lengths (SECURITY.md § Non-Goals).
- **Safety-code comparison** after setup: when E2E is enabled, the CLI prints the
  same short code BurnBar shows in the Private messages sheet. The prompt defaults
  to **no** and only accepts valid X9.63 P-256 public keys. Matching codes confirm
  the two apps are displaying the same agent/phone relay keys for this pairing. If
  the user approves without comparing the code, there is no first-pairing MITM defense.
- **Runtime status** to `/runtime` (on connect and every 30s): the agent's model
  catalog, current model/provider, and agent version. The gateway exposes this on
  `/state`, which is how BurnBar clients show whether the gateway is online and
  what model it is running.
- **Remote model switch**: a `model_switch` event is applied as `/model <id>`,
  after which runtime status is republished so the new model is reflected in
  `/state` within ~1s instead of waiting for the next heartbeat.
- **Human-in-the-loop oversight**: on an E2E-paired link, oversight mode is pinned at
  pairing (`BURNBAR_OVERSIGHT_MODE`); the relay-visible `/state` toggle is **not**
  authoritative. When oversight is *supervised*, Hermes' slash-confirm prompts arm a
  BurnBar approval gate (`/approvals`, control-plane only) and deliver the readable
  detail over the sealed message channel. The relay-visible approval gate carries
  the opaque action id, destination id, and coarse `toolName`; it does not carry
  the prompt summary, command, file path, or tool arguments. On E2E links the
  agent **does not** trust
  `/approvals` poll status (a malicious relay could forge `approved`); it applies
  decisions only from phone-authenticated sealed `approval_decision` events (the
  BurnBar app enqueues one after the native callable succeeds). Authenticated
  `oversight_mode` events are the E2E path for changing the mode after pairing.
  Legacy plaintext links still mirror oversight from `/state` and poll `/approvals`
  as before.
- **Replay defense**: authenticated event ids are deduped in memory and persisted to
  `burnbar_replay_ledger.json` (beside the event cursor), keyed by `uid`,
  `clientId`, and the pinned phone key fingerprint. Every E2E sealed inbound event
  must carry an authenticated `replayCounter`/`eventCounter`; the adapter persists a
  high-water mark and drops counters at or below it before dispatch, so an old valid
  frame is still dropped after restart or bounded-cache saturation.
- **AAD routing identity**: E2E setup requires the authenticated device grant to
  include both `uid` and `clientId`. The adapter refuses to enable or process E2E
  without them, because learning the first AAD-routing ids from `/events` or
  `/state` would let an untrusted relay pin wrong values and cause persistent
  decrypt failure.

## Configuration

`hermes gateway setup` writes these; they can also be set in the environment:

- `BURNBAR_API_BASE_URL` — gateway base URL (default
  `https://api.burnbar.ai/v1/hermes-gateway`).
- `BURNBAR_ACCESS_TOKEN` — bearer token minted when the device code is approved.
- `BURNBAR_HOME_CHANNEL` — default destination id (default `burnbar:home`).

Optional:

- `HERMES_BURNBAR_AGENT_VERSION` — overrides the reported agent version.
- `HERMES_BURNBAR_CURSOR_FILE` — overrides the profile-aware event-cursor path.
- `HERMES_BURNBAR_REPLAY_FILE` — overrides the profile-aware durable replay-ledger path.
- `BURNBAR_OVERSIGHT_MODE` — E2E-paired oversight mode (`supervised` by default).
- `BURNBAR_ALLOW_PLAINTEXT=1` — explicit opt-in to the legacy plaintext path when
  this agent already has a relay identity but the BurnBar link is not E2E-paired.

E2EE requires the optional relay crypto extra:

```bash
pip install -e '.[gateway-e2ee]'
```

Without that extra, legacy plaintext setup still works, but an already E2E-paired
link (`BURNBAR_RELAY_E2E=1`) refuses to start rather than downgrading.

## Setup

```bash
hermes gateway setup        # choose "BurnBar Cloud", approve the code in the app
hermes gateway restart
hermes gateway status
```

After approval, compare the printed safety code with BurnBar's **Private
messages** screen before sending sensitive prompts. If the codes do not match,
revoke the gateway in BurnBar and pair again from a trusted network.

## Security notes

See [`SECURITY.md`](SECURITY.md) for the maintainer-facing threat model and
merge checklist.

This is relay-content confidentiality, not Signal-grade metadata privacy. On an
E2E-paired link, the relay does not receive plaintext message text, sender names,
human-readable approval detail, attachment names, content types, or file bytes,
and cannot forge post-pairing v2 events under the relay-only threat model, absent
sender or recipient static-key compromise. It still sees routing ids,
event/message/attachment/action ids, coarse approval `toolName`, typing state,
runtime model catalog/current model/provider, agent version, relay key/envelope
metadata, timing, and approximate ciphertext sizes.

The v2 key wrap is HPKE-AuthEncap-shaped (`ECDH(ephemeral, recipient) ||
ECDH(senderStatic, recipient)` with domain-separated HKDF info), but it is not
RFC 9180 HPKE framing. This keeps compatibility with the existing BurnBar mobile
relay wire format. This repo verifies the Python side with vendored known-answer
vectors; mobile-client parity is maintained outside this repo. The adapter uses
only the v2 byte format covered by the in-tree vectors.

KCI and static-key compromise are explicit non-goals. If the recipient static
private key is stolen, past messages wrapped to that key can be decrypted and an
attacker can forge as any sender. The static leg has no post-compromise forward
secrecy; key protection belongs in the OS keychain and re-pairing/key rotation
policy. Replay rejection is enforced by the adapter's persisted id ledger plus
sealed replay-counter high-water mark, not by AES-GCM alone.

Safety-code check: compare the safety code during setup; clicking through
without checking it gives the relay a first-pairing MITM opportunity.

## Tests

From the Hermes repo root:

```bash
# Plugin surface + relay E2EE + reproducible wire vectors.
scripts/run_tests.sh \
  tests/gateway/test_burnbar_plugin.py \
  tests/gateway/test_burnbar_e2ee.py \
  tests/gateway/test_relay_e2ee.py \
  tests/gateway/test_relay_e2ee_v2.py \
  tests/gateway/test_wire_vectors_reproducible.py
```

It exercises:

- `test_burnbar_plugin.py` — registration + `Platform("burnbar")` resolution,
  config / env-enablement / yaml-precedence, `/events` → `MessageEvent` and
  `model_switch` (incl. unsafe-id rejection), `/messages` send happy/error,
  `/attachments/init` + signed upload (incl. over-size refusal), cursor
  round-trip, supervised vs autonomous oversight, runtime-status payload, and
  per-event poll isolation.
- `test_burnbar_e2ee.py` — the adapter E2E wiring: v2 + pinned-sender open
  requirement, plaintext refusal on paired links, TOFU-pin lifecycle, replay
  ledger, sealed approvals/attachments/model-switch, and the fail-closed crypto
  backend check.
- `test_relay_e2ee.py` / `test_relay_e2ee_v2.py` — the relay crypto primitive:
  wrap/unwrap, AAD domain separation, v1↔v2 separation, wrong-sender/recipient
  rejection, and the gateway AAD helper byte-contract.
- `test_wire_vectors_reproducible.py` — every committed wire-vector ciphertext
  byte regenerates from inputs (`python -m tests.gateway.vectors.generate_wire_vectors --check`).
