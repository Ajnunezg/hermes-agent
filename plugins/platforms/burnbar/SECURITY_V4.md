# Gateway E2EE v4 — Production Signed-Lane Hardening

v4 is an **additive** hardening layer over the v3 RFC 9180 HPKE wrap. It does not
change the v1/v2/v3 wire formats; it adds five independently-testable, standards-
grounded controls that remediate the residual risks v2/v3 documented as non-goals.
Every primitive is `pyca/cryptography` + stdlib — **no new dependency**. The Python
side is the reference; the Swift/Kotlin clients mirror these constructions
byte-for-byte (cross-language parity is maintained in those repositories).

## What v4 closes

| Residual risk (v3) | v4 remediation | Standard / anchor |
|---|---|---|
| **KCI / implicit-only auth** — a leaked *recipient* static key lets a holder forge any sender | **Explicit Ed25519 sender signature**, encrypt-then-sign, verified against the *pinned* key | RFC 8032; RFC 9180 §9.1.1 (its own recommendation) |
| **No forward secrecy / no PCS** for the static leg | The signed chat lane requires a v4-signed `ratchet_init` before accepting ratchet frames; after the first phone ratchet message, chat uses Double Ratchet FS/PCS. Controls and pre-init chat stay on the v4 signed lane. | Signal Double Ratchet (Perrin & Marlinspike), v4 signed init |
| **Size metadata** (relay sees ciphertext length) | **Padmé** length padding (≤ ~12% overhead) | Nikitin et al., PoPETs 2019 |
| **Pairing MITM** anchored on a code that bound only the static key | **All-key safety code** for currently shipped keys (encryption + signing) | Signal safety numbers (SAS) |
| **No rotation / key-ids** (rotation = full re-pair) | **Sign-the-successor rotation event** + 128-bit key-id selectors | X3DH signed-prekey rotation; key-continuity |

## Constructions

### 1. Explicit sender authentication (KCI) — `relay_e2ee_v4.py`

HPKE `mode_auth` gives only *implicit* authentication; if the recipient static
private key leaks, a holder of it can forge any sender (RFC 9180 §9.1). v4 adds a
detached **Ed25519** signature (separate long-term key, never derived from the
P-256 key) over a length-prefixed, encrypt-then-sign transcript:

```text
sigContext = "OpenBurnBar-HermesRelay-Sig-v4"
  || LP(version) || LP(senderEd25519Pub) || LP(recipientEd25519Pub)
  || LP(recipientP256X963) || LP(keyAAD) || LP(enc||wrappedKey)
  || LP(payloadAAD) || LP(nonce||ct||tag)            ; LP(x) = u32be(len) || x
```

`enc` and `wrappedKey` are bound as separate length-prefixed fields (no internal
boundary shifting). The recipient reconstructs the transcript from the bytes it
received and the **pinned** sender verification key (never a wire field) and
requires the Ed25519 verify **AND** the HPKE/AEAD open to pass — the signature is
checked *first*, so a forged frame is rejected before the AEAD layer and before
any side effect or replay-cache write. Binding both recipient keys closes the
Davis surreptitious-forwarding class (a `skR` holder cannot re-target a still-
valid signed frame). The v4 signed seal path applies Padmé (below) to the payload
*inside* the AEAD, so the relay sees only a length-hidden ciphertext. Anchored to
the RFC 8032 §7.1 known-answer vectors in `test_relay_e2ee_v4.py`.

### 2. Signed ratchet init + chat lane — `hermes_ratchet.py` + adapter

`hermes_ratchet.py` implements a Signal-style Double Ratchet over P-256 /
HKDF-SHA256 / AES-256-GCM, with bounded skipped-message keys and transactional
decrypt.

The old deterministic static-static bootstrap is disabled because a holder of the
recipient static private key could derive the same initial session and forge the
initiator. The only acceptable production bootstrap is a v4-signed `ratchet_init`
control message that binds the first ratchet public keys, a 32-byte nonzero root
key, session id, device ids, destination id, `uid`, `clientId`, algorithm, and
replay counter to the Ed25519-pinned pairing identity. The adapter advertises a
durable `agentRatchetInitPublicKey` by default; `BURNBAR_DISABLE_GATEWAY_RATCHET=1`
is the explicit break-glass disable. It refuses every `ratchetEnvelope` until the
signed init has established a destination session.
The responder (agent) has no sending chain until it receives the first phone
ratchet message, so pre-init and pre-first-message replies fall back to the v4
signed lane. After that first receive, normal chat replies use the ratchet lane.

### 3. Size-metadata minimization — Padmé

`padme_pad` prepends a 4-byte true-length header and zero-pads to the Padmé
length (computed with integer bit-length, never floating `log2`, so the padded
length is identical across languages at powers of two). `padme_unpad` verifies
every trailing pad byte is zero (no pad-oracle / covert channel) and that the
declared length fits. Overhead is bounded at ≤ ~12%.

### 4. All-key pairing safety code

`relay_safety_code_v4` commits to the full *set* of each peer's currently shipped
pinned keys — `(tag, key)` entries length-prefixed and sorted, under a domain-
separated label, the two party blobs sorted (role-free), SHA-256, 128-bit. Adding
a key class changes the code, so a relay can never substitute a new signing key
while the human-compared code still matches. (The current two-key code already
binds the static key; v4 extends it to the signing key. The ratchet init binds
its first ratchet keys inside the signed init transcript.)

### 5. Authenticated rotation + key-ids

`relay_key_id` is a 128-bit selector over an encryption key — a selector **only**;
the key bytes still come from the pinned set and the frame must still authenticate.
`build_rotation_signed_body` / `verify_rotation_event` implement "sign-the-
successor": the new encryption key is signed by the **current pinned identity
key**, with a strictly monotonic epoch (`to == from + 1`, replays and gaps
rejected), a validity window, and a 32-byte nonce. The recipient swaps the pin
atomically and (integration responsibility) carries the replay high-water forward
so a swap does not reopen the old-frame replay window.

## Honest residual risk (after v4)

- **Signing-key compromise** still forges senders **on the v4 signed lane** — but
  this moves the trust to a key that *no longer also decrypts* (a `skR` leak alone
  no longer forges), and the signed rotation path lets a compromised key be
  retired. Store keys in the OS keychain / Secure Enclave. Ratchet FS/PCS applies
  only after a v4-signed init and ratchet traffic; it does not make a compromised
  v4 signing key harmless for future signed-control events.
- **No post-quantum protection** — a harvest-now-decrypt-later adversary can break
  P-256 / the ratchet DH with a future quantum computer. Closing this is a future
  wire version (v5), not an additive patch, and is **deliberately deferred** after
  verifying the current ecosystem (June 2026): `pyca/cryptography` only gained
  ML-KEM in v48 and only on the AWS-LC / BoringSSL / OpenSSL-3.5+ backends (not the
  standard wheels most installs ship), ML-KEM-in-HPKE is still in progress, and the
  Swift/Kotlin clients would each need a matching ML-KEM. A Python-only hybrid now
  would be unusable end-to-end. The migration path is a hybrid KEM (X25519/P-256 +
  ML-KEM-768, e.g. RFC 9180 hybrid-KEM / X-Wing) as `relayKeyVersion = 5`, layered
  the same additive way v4 was. The Double Ratchet already bounds the per-message
  blast radius in the meantime.
- **FS/PCS is chat-lane only after init** — the v4 signed lane is still the
  authoritative control/pre-init transport. Forward secrecy and post-compromise
  healing begin only for messages exchanged inside an established ratchet session.
- **Timing, frequency, and message ordering** remain visible to a store-and-forward
  relay and are **not** addressable without a mixnet / cover-traffic regime the
  threat model excludes. Padmé hides size, not timing. Sealed-sender + rotating
  mailbox tags (relay-interface changes) are a documented future control, not in
  this layer.
- **TOFU is still human-anchored** — a relay MITM at *pairing* time, before any
  key exists, defeats everything; the all-key safety code only helps if the human
  actually compares it.

## Adapter integration (wired end-to-end)

The Python adapter wires all five controls through the real send/open/pairing path
(the Swift/Kotlin clients mirror the same wire contract):

- **Negotiation.** The agent advertises `supportsHpkeV4` and (at device/start and
  runtime status) its Ed25519 `agentRelaySigningKey`. The authenticated pairing
  grant pins the peer signing key and selects the highest supported version (v4
  preferred), flooring to v3 if the peer signing key is absent. Break-glass:
  `BURNBAR_DISABLE_GATEWAY_HPKE_V4` forces v2/v3-only emission.
- **Signed wrap.** `seal_message` / `seal_model_switch` emit a v4 signed envelope
  on a v4 link; `_open_envelope` version-dispatches v4 to verify the Ed25519
  signature (pinned key) AND the HPKE unwrap, refusing a frame missing its
  marker / `enc` / `senderSig` / pinned signing key.
- **Pairing safety code.** Binds all pinned keys (encryption + signing) via
  `_relay_safety_code_v4` so a substituted signing key changes the human code.
- **Ratchet chat lane.** A durable `agentRatchetInitPublicKey` is advertised by
  default unless `BURNBAR_DISABLE_GATEWAY_RATCHET=1` is set. The receive path
  refuses `ratchetEnvelope` frames until a v4-signed `ratchet_init` authenticates
  the phone ratchet key, agent ratchet key, root key, session id, device ids,
  routing ids, algorithm, destination, and replay counter. Controls are still
  refused on ratchet; they must use the v4 signed lane.
- **Anti-downgrade floor.** On a link the grant pinned to v4, a v2/v3-labeled
  inbound frame is refused explicitly before unwrap (a relay cannot strip the
  Ed25519 layer by relabeling); break-glass floors the pinned version so a
  deliberate rollback still opens.
- **Rotation.** A sealed `key_rotation` control event is verified against the
  pinned peer identity key (monotonic epoch + window), then the pinned peer key is
  swapped; the replay high-water is not reset and the cached + persisted ratchet
  session is dropped (so a crash cannot resurrect a stale lineage).

New env keys: `BURNBAR_RELAY_SIGNING_KEY` (agent signing seed),
`BURNBAR_RELAY_PEER_SIGNING_KEY` (pinned peer signing key),
`BURNBAR_RELAY_PEER_KEY_EPOCH` (rotation epoch),
`BURNBAR_DISABLE_GATEWAY_RATCHET` (break-glass disable for signed-init ratchet
chat), `BURNBAR_DISABLE_GATEWAY_HPKE_V4` (break-glass). The legacy
`BURNBAR_RELAY_RATCHET` opt-in flag is accepted as a no-op for older launch
scripts. The
matching clients must follow the same reference wire contract; Python parity is
locked by `tests/gateway/fixtures/hermes_ratchet_init_v1.json`.
