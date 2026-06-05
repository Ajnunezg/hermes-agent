# BurnBar Gateway HPKE v3 Proof Package

This note documents what `relayKeyVersion == 3` proves before upstream review.
It is intentionally narrower than "state-of-the-art E2EE": v3 is a standards
shaped authenticated content-key wrap for the BurnBar gateway relay. It does not
claim forward secrecy after static recipient-key compromise, post-compromise
security, or metadata privacy.

## Frozen Wire Contract

| Field | Value |
| --- | --- |
| Version | `relayKeyVersion == 3` |
| Algorithm marker | `hpke-auth-p256-hkdfsha256-aes256gcm` |
| HPKE suite | RFC 9180 `DHKEM(P-256, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM` |
| HPKE mode | Auth mode, `mode_id = 0x02` |
| `info` | `b"OpenBurnBar-HermesRelay-HPKE-v3|" + key_aad` |
| HPKE AEAD `aad` | `key_aad` |
| Plaintext | the 32-byte content key only |
| `enc` | base64 65-byte P-256 X9.63 uncompressed ephemeral public key |
| `wrappedKey` | base64 48-byte HPKE ciphertext, `ct(32) || tag(16)` |

The existing payload layer is unchanged from v2: the opened 32-byte content key
decrypts message, event, attachment manifest, and attachment body ciphertexts
with their existing gateway AAD labels.

## Canonical Fixture

Fixture:

```text
tests/gateway/fixtures/BurnBarHpkeV3Vector.json
```

Current SHA-256:

```text
04ebb743b0f6df75cfa5602c18f311fe289aa6186a6e3fa86ddc39021aae936f
```

The fixture contains five positive production-shaped cases:

- phone -> agent chat event
- phone -> agent model switch event
- agent -> phone text reply
- agent -> phone attachment manifest
- agent -> phone attachment body key

It also contains negative cases for wrong pinned sender key, wrong recipient key,
wrong key AAD, mutated `enc`, valid-point swapped `enc`, mutated `wrappedKey`,
wrong authenticated destination, replay-counter rollback, v3-to-v2 and v3-to-v1
downgrade, missing `enc`, missing `senderPublicKey`, and missing
`relayEncryption`.

## Proof Matrix

| Claim | Evidence |
| --- | --- |
| The v3 math is RFC 9180 Auth mode for the shipped suite | `tests/gateway/test_relay_e2ee_v3.py::test_v3_production_key_schedule_is_rfc_consistent` and `tests/gateway/test_burnbar_hpke_v3_vectors.py::test_reference_matches_rfc9180_known_answer_vector` |
| The fixture is reproducible | `tests/gateway/test_burnbar_hpke_v3_vectors.py::test_generator_reproduces_checked_in_fixture` |
| Production Python opens every reference vector | `tests/gateway/test_burnbar_hpke_v3_vectors.py::test_production_public_v3_open_parity` |
| Reference Python opens production Python wraps | `tests/gateway/test_burnbar_hpke_v3_vectors.py::test_production_and_reference_v3_are_bidirectionally_interoperable` |
| Wrong pinned sender fails authentication | `tests/gateway/test_relay_e2ee_v3.py::test_v3_wrong_pinned_sender_raises_invalid_tag` and the fixture negative `wrong_pinned_sender_key` |
| v3 downgrade/strip fails closed | `tests/gateway/test_burnbar_hpke_v3_vectors.py::test_downgrade_and_strip_fail_closed_in_production` and `tests/gateway/test_burnbar_plugin_v3.py` downgrade tests |
| Adapter emits v3 only after authenticated peer capability | `tests/gateway/test_burnbar_plugin_v3.py::test_seal_message_emits_v3_when_peer_advertises_v3` and v2 fallback tests |
| Adapter opens v3 only with the pinned sender key | `tests/gateway/test_burnbar_plugin_v3.py::test_agent_opens_phone_sealed_v3_event` and `test_agent_refuses_v3_event_from_unpinned_sender` |
| Attachment manifest and body are covered | fixture cases `agent_reply_attachment_manifest` and `agent_reply_attachment_body_key`; both bind `destinationId` or body AAD as appropriate |
| Swift CryptoKit opens the same fixture | BurnBar companion suite `OpenBurnBarCore/Tests/OpenBurnBarCoreTests/BurnBarHpkeV3CrossPlatformVectorTests.swift` |
| Python opens a Swift-emitted v3 sample | `HermesRelayHPKEv3VectorTests.swift` can emit a read-only handoff sample; `relay_e2ee.unwrap_symmetric_key_v3` opens every positive and rejects every negative |
| Android opens the same fixture | BurnBar companion suite `android/app/src/test/java/com/openburnbar/data/hermes/relay/HermesRelayCryptoHpkeV3Test.kt` |

## Verification Commands

Hermes-only proof:

```bash
cd <hermes-agent checkout>
venv/bin/python -m pytest \
  tests/gateway/test_relay_e2ee_v3.py \
  tests/gateway/test_burnbar_plugin_v3.py \
  tests/gateway/test_burnbar_hpke_v3_vectors.py -q
```

Full gateway regression surface:

```bash
cd <hermes-agent checkout>
venv/bin/python -m pytest \
  tests/gateway/test_relay_e2ee.py \
  tests/gateway/test_relay_e2ee_v2.py \
  tests/gateway/test_relay_e2ee_v3.py \
  tests/gateway/test_burnbar_plugin.py \
  tests/gateway/test_burnbar_plugin_v3.py \
  tests/gateway/test_burnbar_hpke_v3_vectors.py -q
```

Companion app mirror checks, from the BurnBar checkout:

```bash
shasum -a 256 \
  OpenBurnBarCore/Tests/OpenBurnBarCoreTests/Fixtures/BurnBarHpkeV3Vector.json \
  android/app/src/test/resources/hermes-relay/HermesGatewayWireVectorV3.json
```

Both hashes must equal the Hermes fixture hash above.

Focused companion suites:

```bash
swift test --package-path OpenBurnBarCore \
  --filter BurnBarHpkeV3CrossPlatformVectorTests

cd android
./gradlew :app:testDebugUnitTest \
  --tests com.openburnbar.data.hermes.relay.HermesRelayCryptoHpkeV3Test \
  --no-daemon
```

Optional bidirectional Swift -> Python sanity check:

```bash
cd <BurnBar checkout>
OPENBURNBAR_EMIT_HPKE_V3_FIXTURE=1 \
OPENBURNBAR_HPKE_V3_FIXTURE_OUT=/tmp/BurnBarHpkeV3Vector.swift-emitted.json \
swift test --package-path OpenBurnBarCore \
  --filter HermesRelayHPKEv3VectorTests/test_emitsHPKEv3Vector_forCrossLanguageHandoff

cd <hermes-agent checkout>
venv/bin/python - <<'PY'
import base64, json
from pathlib import Path
from gateway.crypto import relay_e2ee

fixture = json.loads(Path("/tmp/BurnBarHpkeV3Vector.swift-emitted.json").read_text())
for case in fixture["positives"]:
    key = relay_e2ee.unwrap_symmetric_key_v3(
        case["enc"], case["wrappedKey"],
        base64.b64decode(case["recipientPrivateKey"], validate=True),
        case["keyAAD"].encode(),
        pinned_sender_public=case["senderPublicKey"],
    )
    assert base64.b64encode(key).decode("ascii") == case["contentKey"]
    plaintext = relay_e2ee.open_base64(case["payloadCiphertext"], key, case["payloadAAD"].encode())
    assert plaintext.decode("utf-8") == case["plaintext"]
for neg in fixture["negatives"]:
    try:
        relay_e2ee.unwrap_symmetric_key_v3(
            neg["enc"], neg["wrappedKey"],
            base64.b64decode(neg["recipientPrivateKey"], validate=True),
            neg["keyAAD"].encode(),
            pinned_sender_public=neg["pinnedSenderPublicKey"],
        )
    except Exception:
        continue
    raise AssertionError(f"negative opened unexpectedly: {neg['name']}")
PY
```

## Non-Claims

- v3 is not a Signal/Double-Ratchet replacement.
- v3 is not forward-secret for ciphertexts wrapped to a stolen long-term
  recipient key.
- v3 does not hide relay metadata such as routing ids, document ids, timing, or
  approximate ciphertext size.
- v3 is not proof that every live deployed BurnBar gateway flow has negotiated
  v3; it proves that peers which advertise v3 can emit and open the v3 frame and
  that downgrade/strip attempts fail closed.
