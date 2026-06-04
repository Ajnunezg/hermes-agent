# BurnBar Gateway Security Notes

This plugin treats BurnBar Cloud as an untrusted relay. The relay may reorder,
drop, duplicate, mutate, or inject gateway documents. It must not be able to read
sealed payload bodies or forge post-pairing v2/v3 events without the sender's
private key. When both peers publish ratchet material, text/control traffic uses
a ratcheted envelope; the relay likewise must not be able to forge those messages
without the sender's ratchet state.

Maintainer note: compare the setup safety code. If the user clicks through
without comparing the code shown by Hermes and BurnBar, first-pairing MITM
protection is defeated.

## Protocol Shape

The v2 key wrap is HPKE-AuthEncap-shaped but is not RFC 9180 HPKE framing:

```text
ikm  = ECDH(ephemeral, recipient) || ECDH(senderStatic, recipient)
info = "OpenBurnBar-HermesRelay-KeyWrap-v2|" || aad || enc || recipientPub || senderPub
key  = HKDF-SHA256(ikm, zero-salt, info, 32)
wrap = AES-256-GCM(key, randomNonce, symmetricKey, aad)
```

The bespoke frame exists for Swift/Kotlin/Python byte compatibility with the
existing `HermesRelayCrypto` gateway vectors. If upstream wants standard HPKE,
that is `relayKeyVersion == 3` with separate RFC 9180 HPKE vectors; v2 must remain
byte-stable.

The v3 frame is RFC 9180 HPKE Auth mode over P-256/HKDF-SHA256/AES-GCM, with
the HPKE `enc` field stored beside the ciphertext. It is domain-separated from
v2 by version-specific AAD and fixture coverage. v3 is not a forward-secrecy
claim for long-lived static recipient compromise; ratcheting is the mitigation
track for stronger conversation-security claims.

## Fail-Closed Requirements

- E2E setup requires `uid`, `clientId`, and the phone relay public key from the
  authenticated device grant. Runtime `/events` or `/state` responses can
  confirm these AAD-binding values but cannot establish the first value.
- E2E open requires a supported production relay envelope version (`2` or `3`)
  and unwraps only with the pinned phone sender key. For v3, the `enc` field is
  required and authenticated by the HPKE open path. The relay-visible
  `senderPublicKey` field is advisory.
- Plaintext is refused in BOTH directions whenever it is forbidden on the link:
  once `BURNBAR_RELAY_E2E=1` (paired), and also when this agent holds a relay
  identity but the link is not yet E2E-paired (unless `BURNBAR_ALLOW_PLAINTEXT=1`).
  The inbound open path uses the same `must_seal` predicate as the send path, so a
  relay cannot drive the agent with an injected plaintext event/control by
  advertising an E2E-capable link as "legacy".
- Every inbound sealed E2E event must carry an authenticated
  `replayCounter` or `eventCounter`. The adapter persists a high-water mark plus
  a bounded id ledger and drops old counters before side effects.

## Non-Goals

- Static recipient-key compromise is out of scope. If the recipient static
  private key is stolen, past messages wrapped to that key can be decrypted and
  the attacker can forge as any sender.
- There is no post-compromise forward secrecy for the static leg. Store static
  keys in OS-protected storage and rotate by re-pairing.
- The relay still sees metadata: routing ids, event/message ids, timing, and
  approximate ciphertext sizes. This is relay-content confidentiality, not
  Signal-grade metadata privacy.
- AES-GCM does not provide replay rejection by itself. Replay rejection is an
  adapter ledger and counter policy.

## Vector Coverage

`tests/gateway/fixtures/HermesGatewayWireVector.json` proves Swift/Python/Kotlin
byte compatibility for v2 key wrapping and production-shaped payload opening,
including destination-bound message/event/attachment bodies and wrong-sender/AAD
rejection.

`tests/gateway/fixtures/BurnBarHpkeV3Vector.json` proves the v3 HPKE frame across
Python, Swift, and Kotlin. The generator and tests cover positive message/event/
attachment/model-switch payloads plus required negatives: wrong destination,
wrong recipient, replay rollback, missing sender public key, swapped `enc`,
downgrade, and payload-policy rejection.
