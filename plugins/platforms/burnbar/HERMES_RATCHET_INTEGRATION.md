# HermesRatchet v1 adapter integration points

`gateway.crypto.hermes_ratchet` is the Python mirror of the Swift
`OpenBurnBarCore/.../HermesRatchetCrypto.swift` primitive. It is intentionally
not wired into `plugins/platforms/burnbar/adapter.py` until the BurnBar gateway
schema ships ratchet session/prekey fields.

Production wiring should be limited to these adapter seams:

- `_RelaySealer.seal_message(...)`: after the server/schema path carries a
  ratchet envelope, build the sealed JSON payload exactly as today, then call
  `hermes_ratchet.encrypt(payload_bytes, session_state, associated_data=...)`.
  Missing ratchet state on an E2E link must raise `_RelayPlaintextRefused`; do
  not route to the existing plaintext/legacy branch.
- `_RelaySealer.open_event(...)` / `_RelaySealer.open_model_switch(...)`: when a
  `ratchetEnvelope` is present, parse it with
  `HermesRatchetEnvelope.from_wire(...)` and decrypt with the pinned session
  state before dispatch. A replay, bad AD, bad header, or missing state must drop
  the event and preserve the existing no-plaintext-fallback invariant.
- `BurnBarAdapter.__init__`: hydrate ratchet session state from a local secret
  store only. Root keys, chain keys, ratchet private keys, and skipped-message
  keys must never be read from or written to the relay.
- `_record_event(...)`: keep replay recording after authenticated open. Ratchet
  replay failures happen inside `hermes_ratchet.decrypt`; the adapter ledger
  still owns side-effect replay dedupe.

AAD policy:

- Use the same routing identity material that the existing HPKE/v2 path pins at
  pairing time (`uid`, `clientId`, destination/message/event id). Do not learn
  first AAD identity values from `/events`, `/state`, or any relay-controlled
  runtime payload.
- The ratchet module's inner AEAD AAD format is fixed by Swift:
  `OpenBurnBar-HermesRatchet-v1-AAD` plus UInt64 big-endian length-prefixed
  associated data and header fields.

