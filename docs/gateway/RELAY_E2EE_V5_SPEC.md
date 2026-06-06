# Hermes Gateway Relay E2EE v5 Spec

Status: implemented in Python reference, additive to v1-v4.

## Suite

`relayKeyVersion = 5`

`relayEncryption = "hpke-base-mlkem768-x25519-hkdfsha256-aes256gcm-ed25519sig"`

The v5 content-key wrap uses pyca `cryptography` HPKE:

- KEM: `MLKEM768_X25519`
- KDF: `HKDF_SHA256`
- AEAD: `AES_256_GCM`

The explicit sender authentication primitive remains Ed25519. The hybrid KEM is
base-mode recipient confidentiality only; it is not treated as sender auth.

## KEM Key Format

Public key wire/storage format:

`mlkem768_public_key(1184) || x25519_public_key(32)` = 1216 bytes, base64 on wire.

Private key storage format:

`seed(32)`, base64 in `BURNBAR_RELAY_KEM_PRIVATE_KEY`. The seed expands with
SHAKE256 into:

- `mlkem768_seed(64)`
- `x25519_private(32)`

KEM key id:

`hex128(SHA256("OpenBurnBar-HermesRelay-v5-KemKeyId" || public_key_bytes))`

## Envelope

The v5 envelope shape mirrors v4:

```json
{
  "relayEnvelope": {
    "payloadCiphertext": "base64(nonce || ciphertext || tag)",
    "wrappedKey": "base64(hpke ciphertext || tag over content key)",
    "enc": "base64(HPKE encapsulated key, 1120 bytes)",
    "senderSig": "base64(Ed25519 signature)",
    "relayEncryption": "hpke-base-mlkem768-x25519-hkdfsha256-aes256gcm-ed25519sig",
    "relayKeyVersion": 5,
    "eventId": "..."
  }
}
```

HPKE output from pyca is split as:

`enc = combined[:1120]`

`wrappedKey = combined[1120:]`

Payload sealing and Padme padding are unchanged from v4.

## Signature Transcript

v5 reuses the v4 canonical length-prefixed transcript builder with:

- label: `OpenBurnBar-HermesRelay-Sig-v5`
- version byte: `5`
- recipient encryption field: v5 KEM public key bytes, not P-256 X9.63 bytes

The transcript binds, in order:

1. domain label
2. version
3. sender Ed25519 verify key
4. recipient Ed25519 verify key
5. recipient KEM public key
6. key AAD
7. HPKE `enc`
8. wrapped content key
9. payload AAD
10. raw sealed payload

The receiver verifies `senderSig` against the pinned peer Ed25519 key before HPKE
open and before payload open.

## Downgrade Policy

The authenticated pairing grant pins the peer relay version. The open path
refuses any inbound envelope whose `relayKeyVersion` is lower than the effective
pinned version before unwrap.

`BURNBAR_DISABLE_GATEWAY_HPKE_V5=1` is the explicit break-glass knob that lowers a
v5-pinned link to v4. Without that flag, a v5-pinned install missing
`cryptography>=48` or a local KEM seed fails closed; missing local v5 capability
does not silently downgrade inbound frames.

The signed ratchet-init lane is enabled by default once the relay lane is paired.
`BURNBAR_DISABLE_GATEWAY_RATCHET=1` is the explicit break-glass knob that stops
advertisement and session use. The legacy `BURNBAR_RELAY_RATCHET=1` flag is no
longer required.

## Ratchet Init v2

`ratchetInitVersion = 2`

`algorithm = "OpenBurnBar-HermesRatchet-v2-XWing-P256-HKDFSHA256-AESGCM"`

v2 removes transmitted `rootKeyBase64`. The phone encapsulates to the agent's
advertised ratchet-init KEM key:

`kemCiphertextBase64 = base64(mlkem_ct(1088) || x25519_pub(32))`

The KEM shared secret is combined as:

`SHA3-256(mlkem_ss || x25519_ss || x25519_ephemeral_pub || responder_x25519_pub || "\\.//^\\")`

The ratchet root is:

`HKDF-SHA256(kem_shared_secret, salt=32 zero bytes, info="OpenBurnBar-HermesRatchet-v2-root-pq|" || SHA256(transcript))`

The initiator must include:

`rootConfirmMacBase64 = base64(HMAC-SHA256(root, "OpenBurnBar-HermesRatchet-v2-root-confirm" || transcript))`

The responder verifies the MAC before storing a session.

The transcript binds kind, version, algorithm, uid, clientId, destinationId,
sessionID, both P-256 ratchet public keys, both device ids, responder KEM public
key, responder KEM key id, KEM ciphertext, and replayCounter.

On successful v2 init, the agent rotates the ratchet-init KEM key in the same
fsynced session-state write that stores the new ratchet session.

## Attachment Body-Key Wrap

The file body is sealed independently with a per-attachment `body_key`:

`bodyCiphertext = AES-256-GCM(body_key, file_bytes, aad = "...|gatewayAttachmentBody|uid|clientId|attachmentId")`

The body blob (base64 of the sealed body) is uploaded as the attachment content.

**Legacy (v2/v3 link, or peer without signed-attachment support):** unchanged. The
manifest is sealed with `body_key` under the `gatewayAttachmentManifest` AAD and the
`body_key` is wrapped with the v2/v3 content-key wrap. No signature.

**Signed (v4/v5 link, peer advertises `supportsGatewayAttachmentWrapVersions`):** the
`body_key` travels INSIDE the signed manifest as `bodyKeyBase64`, and the manifest is
sealed exactly like a v4/v5 message envelope:

- `payloadCiphertext` = the v4/v5 signed seal of the manifest JSON
  `{fileName, byteCount, contentType, destinationId, replayCounter, bodyKeyBase64}`,
  Padmé-padded, AES-256-GCM under the manifest's own content key.
- `wrappedKey` + `enc` = the manifest content key wrapped at the pinned version
  (P-256 HPKE-Auth at v4; hybrid ML-KEM-768/X25519 HPKE at v5).
- `senderSig` = Ed25519 over the v4/v5 signing transcript with
  `key_aad = "...|gatewayAttachmentKey|..."` and
  `payload_aad = "...|gatewayAttachmentManifest|..."`.
- top-level `attachmentId`, plus the usual `relayKeyVersion`/`relayEncryption`/sender
  key fields.

To OPEN: verify+open the manifest envelope with `open_signed_v4`/`open_signed_v5`
(recipient = the receiving peer; pinned sender = the agent), read `bodyKeyBase64`
from the manifest, then open the body blob under the `gatewayAttachmentBody` AAD.
The body key — and therefore the file — inherits the link's PQ confidentiality at v5.

`supportsGatewayAttachmentWrapVersions` (list of `{4,5}`) is advertised in the relay
capability payload; absence means "cannot open a signed attachment wrap" so the agent
keeps the legacy wrap. On a v5 pin the agent fails closed rather than ship a classical
body key (`BURNBAR_ALLOW_CLASSICAL_ATTACHMENTS=1` is the migration escape hatch).

## Fixtures

`tests/gateway/fixtures/hermes_ratchet_init_v2.json` is the parity fixture for the
v2 ratchet init. It includes deterministic private seeds, expected public keys,
KEM key id, recorded KEM ciphertext, root-confirm MAC, and root/shared-secret
hashes.

`tests/gateway/test_v5_attachment_wrap.py` round-trips the signed attachment wrap
(v4 and v5) by opening the agent's own output the way the phone must, and is the
executable reference for the format above.

## Residuals

v5 protects the relay content-key wrap and ratchet root bootstrap with a hybrid
post-quantum KEM. The ongoing Double Ratchet still uses P-256. Full June-2026
SOTA remains an official libsignal Triple Ratchet/SPQR migration or equivalent
ongoing PQ ratchet.
