# BurnBar Gateway Security Notes

This plugin's standalone relay-crypto primitive treats BurnBar Cloud as an
untrusted relay. The relay may reorder, drop, duplicate, mutate, or inject
gateway documents. Under that relay-only threat model, the primitive is intended
to keep sealed payload bodies confidential and make a v2 wrapped key fail to open
unless it was sealed by the holder of the pinned sender static private key.
Sender or recipient static-key compromise is outside that scope and covered
below.

Safety-code check: compare the setup safety code. If the user clicks through
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

This frame exists for compatibility with BurnBar's existing mobile relay wire
format. This repo verifies the Python side with vendored known-answer
vectors; mobile-client parity is maintained outside this repo. This change introduces
only this v2 primitive and its test vectors.

AAD is a UTF-8 `|`-joined protocol label. The helpers in `relay_e2ee.py` reject
`|` and control characters in every dynamic part so two logical contexts cannot
serialize to the same byte string.

## Primitive Boundary Requirements

- `AgentRelayIdentity.key_version` advertises `2`, the authenticated v2
  key-wrap primitive. The anonymous v1 wrap/unwrap remains available only when
  callers omit the sender static-key arguments.
- `wrap_symmetric_key` accepts only 32-byte symmetric keys, and
  `unwrap_symmetric_key` rejects decrypted symmetric keys that are not exactly 32
  bytes before returning them to a caller.
- v2 unwrap authenticates only the pinned sender public key supplied by the
  caller as `sender_public_base64`. A relay-visible `senderPublicKey` field is
  not trustworthy unless a caller has independently pinned it.
- Public and private key imports fail with typed relay-crypto errors on malformed
  base64, wrong byte counts, invalid P-256 points, and invalid private scalars.
- Importing `relay_e2ee.py` does not require the optional `cryptography` backend.
  `crypto_backend_available()` is the explicit probe for whether the primitive
  can actually seal/open.

## Non-Goals

- This change does not prove adapter wiring, runtime plaintext refusal, device-grant
  establishment, replay-ledger persistence, or production fail-closed behavior.
  Those are caller/runtime responsibilities and belong to adapter tests.
- Static recipient-key compromise is out of scope. If the recipient static
  private key is stolen, past messages wrapped to that key can be decrypted and
  the attacker can forge as any sender.
- There is no post-compromise forward secrecy for the static leg. Store static
  keys in OS-protected storage and rotate by re-pairing.
- The relay still sees metadata: routing ids, event/message ids, timing, and
  approximate ciphertext sizes. Two control signals are sent in cleartext by
  design and carry no message content: typing indicators (destination/thread
  routing ids only) and runtime status (the agent's model catalog, current
  model id, and agent version, for the BurnBar model picker). This is
  relay-content confidentiality, not Signal-grade metadata privacy.
- AES-GCM does not provide replay rejection by itself. Replay rejection is an
  adapter or caller ledger and counter policy.

## Vector Coverage

`tests/gateway/fixtures/gateway_wire_vector.json` is an in-tree known-answer
vector for the v2 key wrap and payload opening (event, agent reply, model_switch,
and attachment slots), including wrong-sender and wrong-recipient rejection. Its
event and `model_switch` plaintexts carry strict E2E fields such as
`destinationId` and `replayCounter`, but this change only proves the primitive can unwrap
and open those vector payloads. It does not prove the production adapter enforces
those fields.

Both this and the v1 realtime vector (`relay_wire_vector.json`) are regenerated
and byte-verified in-tree by `tests/gateway/vectors/generate_wire_vectors.py`
(`python -m tests.gateway.vectors.generate_wire_vectors --check`, also enforced by
`tests/gateway/test_wire_vectors_reproducible.py`), so a maintainer can re-derive
every ciphertext byte from this repo alone with no non-Python toolchain. The same
wire format is implemented by the BurnBar iOS/Android clients; cross-language parity
is maintained in those client repositories and is not re-proven here.
