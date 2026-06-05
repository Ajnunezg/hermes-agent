# Gateway E2EE v4 — State-of-the-Art Hardening

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
| **No forward secrecy / no PCS** for the static leg | **Double Ratchet** (per-message forward secrecy + post-compromise self-healing) | Signal Double Ratchet (Perrin & Marlinspike) |
| **Size metadata** (relay sees ciphertext length) | **Padmé** length padding (≤ ~12% overhead) | Nikitin et al., PoPETs 2019 |
| **Pairing MITM** anchored on a code that bound only the static key | **All-key safety code** (binds encryption + signing + ratchet keys) | Signal safety numbers (SAS) |
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

### 2. Forward secrecy + PCS — `hermes_ratchet.py`

A Signal Double Ratchet over P-256 / HKDF-SHA256 / AES-256-GCM: `KDF_RK` =
HKDF-SHA256 keyed by the root key over the DH output; `KDF_CK` = two HMAC-SHA256
calls under distinct domain-separated labels; the DH ratchet derives a receiving
chain then a fresh sending chain each turn. Message keys are single-use (forward
secrecy); a DH-ratchet round-trip heals a prior state compromise (PCS). Skipped
message keys are bounded **both** per chain (`max_skip`) **and** in total
(`max_skipped_keys`) so an untrusted relay cannot force unbounded allocation. The
full header is bound into the GCM tag via a length-prefixed AAD.

`decrypt()` is **transactional**: every ratchet mutation (the skipped-key pop, the
skip walk, the DH-ratchet step, the receiving-chain advance) runs on a working
copy and is committed to the caller's session state only *after* the AEAD
authenticates. A forged or tampered frame therefore leaves the session byte-for-
byte unchanged — the untrusted relay cannot irreversibly advance the ratchet (a
permanent session DoS), pop a stored key, or fill the skipped-key store before
authentication. The Swift/Kotlin clients must mirror this trial-decrypt-then-
commit shape.

**Bootstrap.** The module takes the initial 32-byte shared secret as input; the
integration MUST exchange the initial ratchet public keys and seed it inside a v4
*signed* envelope so the first ratchet keys inherit the pairing pin (a relay-
seeded session would defeat the ratchet).

### 3. Size-metadata minimization — Padmé

`padme_pad` prepends a 4-byte true-length header and zero-pads to the Padmé
length (computed with integer bit-length, never floating `log2`, so the padded
length is identical across languages at powers of two). `padme_unpad` verifies
every trailing pad byte is zero (no pad-oracle / covert channel) and that the
declared length fits. Overhead is bounded at ≤ ~12%.

### 4. All-key pairing safety code

`relay_safety_code_v4` commits to the full *set* of each peer's pinned keys —
`(tag, key)` entries length-prefixed and sorted, under a domain-separated label,
the two party blobs sorted (role-free), SHA-256, 128-bit. Adding a key class
changes the code, so a relay can never substitute a new key while the human-
compared code still matches. (The current two-key code already binds only the
static key; v4 extends it to the signing + ratchet keys.)

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

- **Signing-key compromise** still forges senders — but this moves the trust to a
  key that *no longer also decrypts* (a `skR` leak alone no longer forges), and the
  signed rotation path lets a compromised key be retired. Store keys in the OS
  keychain / Secure Enclave.
- **No post-quantum protection** — a harvest-now-decrypt-later adversary can break
  P-256/the ratchet DH with a future quantum computer. A hybrid (ML-KEM) KEM is a
  later version, explicitly deferred.
- **PCS heals only after a DH-ratchet round-trip** — a persistent device implant
  that continuously exfiltrates ratchet state keeps reading until a healing turn.
- **Timing, frequency, and message ordering** remain visible to a store-and-forward
  relay and are **not** addressable without a mixnet / cover-traffic regime the
  threat model excludes. Padmé hides size, not timing. Sealed-sender + rotating
  mailbox tags (relay-interface changes) are a documented future control, not in
  this layer.
- **TOFU is still human-anchored** — a relay MITM at *pairing* time, before any
  key exists, defeats everything; the all-key safety code only helps if the human
  actually compares it.

## Integration boundary

This change ships the **crypto reference + tests** (the standards-grounded
primitives that remediate each risk, KAT-anchored where a vector exists). Wiring
them into the adapter — v4 negotiation, the signed-seal path, stateful ratchet
session persistence, and rotation-event handling — and the matching Swift/Kotlin
client implementations are the next integration stage; the reference here is the
spec they implement, exactly as the v3 crypto reference grounded the v3 wire
contract.
