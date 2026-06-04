# BurnBar HPKE v3 cross-language vectors (test lane)

Canonical vector suite + RFC 9180 reference that prove the BurnBar phone (Swift)
and the Hermes agent (Python) agree byte-for-byte on the `relayKeyVersion == 3`
relay **content-key wrap**. This directory is **test tooling / a conformance
oracle** — never imported by production.

## Frozen v3 contract

| Field | Value |
| --- | --- |
| Suite | `DHKEM(P-256, HKDF-SHA256)` [KEM `0x0010`] + `HKDF-SHA256` [KDF `0x0001`] + `AES-256-GCM` [AEAD `0x0002`] |
| Mode | HPKE **auth** (`mode_auth` = `0x02`) — recipient binds the **pinned** sender static key |
| `info` | `b"OpenBurnBar-HermesRelay-HPKE-v3|" + key_aad` |
| AEAD `aad` | `key_aad` (the single HPKE seal's associated data) |
| `pt` | the 32-byte content key (HPKE wraps only the content key; the payload/attachment AES-GCM layers are unchanged from v2) |
| `enc` | base64 of the 65-byte X9.63 uncompressed ephemeral public key |
| `wrappedKey` | base64 of the 48-byte HPKE ciphertext (`ct(32) ‖ tag(16)`) |
| markers | `relayKeyVersion = 3`, `relayEncryption = "hpke-auth-p256-hkdfsha256-aes256gcm"` |

This mirrors `gateway/crypto/relay_e2ee.py` (`_HPKE_*`, `wrap_symmetric_key_v3`,
`unwrap_symmetric_key_v3`) and the Swift `HermesRelayCrypto` v3 surface
byte-for-byte.

## Files

- `hpke_v3_reference.py` — self-contained RFC 9180 HPKE Auth reference (only
  `hashlib`/`hmac` + `cryptography` EC/AEAD). Includes `run_self_test()`.
- `generate_burnbar_hpke_v3_vectors.py` — fixture generator.
- `../fixtures/BurnBarHpkeV3Vector.json` — the canonical fixture (5 positives,
  9 negatives). Vendored byte-identical into the Swift test bundle at
  `OpenBurnBarCore/Tests/OpenBurnBarCoreTests/Fixtures/BurnBarHpkeV3Vector.json`.
- `../test_burnbar_hpke_v3_vectors.py` — the Python verifier (opens positives,
  rejects negatives, cross-checks the production `relay_e2ee` v3 path).
- `OpenBurnBarCore/.../BurnBarHpkeV3CrossPlatformVectorTests.swift` — Swift
  CryptoKit opens the same fixture.

## Regenerate

```bash
cd /Users/albertonunez/.hermes/hermes-agent
venv/bin/python -m tests.gateway.vectors.generate_burnbar_hpke_v3_vectors
# then re-vendor the Swift copy:
cp tests/gateway/fixtures/BurnBarHpkeV3Vector.json \
   /Users/albertonunez/Documents/Windsurf/BurnBar/OpenBurnBarCore/Tests/OpenBurnBarCoreTests/Fixtures/
```

Static recipient/sender keypairs and per-case content keys are **deterministic**
(stable, reviewable, aligned with the Swift deterministic fixture scheme); each
HPKE `enc` uses a **fresh random ephemeral** exactly as production does. These
are *open-verification* vectors: regenerating yields a fresh **valid** fixture,
not identical bytes — verifiers open them rather than diffing them.

## Cross-language proof (triangulated)

1. The independent Python **reference** generates the fixture and opens it.
2. The production **`relay_e2ee`** HPKE primitives are byte-identical to the
   reference, and `wrap/unwrap_symmetric_key_v3` open it (bidirectional).
3. Swift **CryptoKit** (`HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`, auth mode) —
   a third independent RFC 9180 implementation — opens it.

Three independent implementations agreeing is the byte-agreement guarantee.

## Coordination / handoff

- **Owner:** the vector/tests lane. Adds test tooling + fixtures only; it does
  **not** modify `relay_e2ee.py`, `HermesRelayCrypto.swift`, or the adapter.
- **Preferred emitter:** once the Swift `HermesRelayCrypto` v3 wrap/open lands,
  Swift becomes the canonical generator (a Swift-emitted fixture proves the
  phone and agent agree on bytes); regenerate from Swift and re-vendor the
  Python copy. Until then this Python-reference fixture is the handoff and the
  permanent independent cross-check.
- **Kotlin/Android:** when the Android v3 port lands, replay this same fixture
  through the Kotlin implementation. Do **not** overwrite vendored copies
  without the owning lane regenerating from its canonical emitter.
