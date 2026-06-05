# BurnBar HPKE v3 cross-language vectors (test lane)

Canonical vector suite + RFC 9180 reference that prove the BurnBar phone (Swift),
BurnBar Android (Kotlin/JCE), and the Hermes agent (Python) agree byte-for-byte
on the `relayKeyVersion == 3` relay **content-key wrap**. This directory is
**test tooling / a conformance oracle** - never imported by production.

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
  13 negatives). Vendored byte-identical into the Swift test bundle at
  `OpenBurnBarCore/Tests/OpenBurnBarCoreTests/Fixtures/BurnBarHpkeV3Vector.json`
  and the Android test resources at
  `android/app/src/test/resources/hermes-relay/HermesGatewayWireVectorV3.json`.
- `../test_burnbar_hpke_v3_vectors.py` — the Python verifier (opens positives,
  rejects negatives, cross-checks the production `relay_e2ee` v3 path).
- `OpenBurnBarCore/.../BurnBarHpkeV3CrossPlatformVectorTests.swift` — Swift
  CryptoKit opens the same fixture.
- `android/.../HermesRelayCryptoHpkeV3Test.kt` — Android opens the same fixture.

## Regenerate

```bash
cd <hermes-agent checkout>
venv/bin/python -m tests.gateway.vectors.generate_burnbar_hpke_v3_vectors
# then mirror the exact JSON bytes into the companion app test resources:
cp tests/gateway/fixtures/BurnBarHpkeV3Vector.json \
  <BurnBar checkout>/OpenBurnBarCore/Tests/OpenBurnBarCoreTests/Fixtures/BurnBarHpkeV3Vector.json
cp tests/gateway/fixtures/BurnBarHpkeV3Vector.json \
  <BurnBar checkout>/android/app/src/test/resources/hermes-relay/HermesGatewayWireVectorV3.json
```

Static recipient/sender keypairs, per-case content keys, HPKE Auth ephemerals,
and payload AES-GCM nonces are **deterministic in the fixture only**. Production
still generates fresh HPKE ephemerals and AES-GCM nonces. Determinism makes the
review artifact reproducible: regenerating the fixture must produce the exact
same semantic JSON object and the mirrored fixture hash must stay stable.

Current canonical fixture hash:

```text
sha256 04ebb743b0f6df75cfa5602c18f311fe289aa6186a6e3fa86ddc39021aae936f
```

## Cross-language proof (triangulated)

1. The independent Python **reference** generates the fixture and opens it.
2. The production **`relay_e2ee`** HPKE primitives are byte-identical to the
   reference, and `wrap/unwrap_symmetric_key_v3` open it (bidirectional).
3. Swift **CryptoKit** (`HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`, auth mode) —
   a third independent RFC 9180 implementation — opens it.
4. Android's production Kotlin/JCE implementation opens the same fixture and
   asserts the same destination/replay schema on JSON payloads.

The proof is not just "Python seals, Python opens": the committed verifier pins
the RFC 9180 known-answer vector, regenerates the canonical fixture, opens every
positive case, rejects every negative, and checks production Python against the
reference in both directions.

## Coordination / handoff

- **Owner:** the vector/tests lane. The Python RFC 9180 reference is the
  canonical fixture generator for this upstream Hermes PR.
- **Mirror rule:** all companion app copies must be byte-identical to
  `tests/gateway/fixtures/BurnBarHpkeV3Vector.json`; mirror drift is a test
  failure, not an acceptable reformat.
- **Swift/Kotlin:** both companion implementations consume this fixture. Swift
  also has a separate read-only fixture-emission test for handoff/debugging, but
  it does not overwrite the canonical fixture by default.
