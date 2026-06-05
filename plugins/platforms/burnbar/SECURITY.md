# BurnBar Gateway Security Notes

This plugin treats BurnBar Cloud as an untrusted relay. The relay may reorder,
drop, duplicate, mutate, or inject gateway documents. It must not be able to read
sealed payload bodies or forge post-pairing v2/v3 events without the sender's
static private key.

Two authenticated content-key wraps are supported and negotiated per link: **v2**
(a bespoke authenticated 2-DH wrap, retained byte-stable for the existing clients)
and **v3** (standard **RFC 9180 HPKE `mode_auth`**). Both bind the *pinned* sender
static key as the forgery defense; the open path version-dispatches on each
envelope's own `relayKeyVersion` and refuses any version outside `{2, 3}`.

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
existing `HermesRelayCrypto` gateway vectors; v2 must remain byte-stable.

`relayKeyVersion = 3` is standard **RFC 9180 HPKE `mode_auth`** and wraps only the
32-byte content key (the payload/manifest/body AES-256-GCM layers are unchanged
from v2):

```text
suite       = DHKEM(P-256, HKDF-SHA256) [0x0010] + HKDF-SHA256 [0x0001] + AES-256-GCM [0x0002]
mode        = mode_auth (0x02)
(shared, enc) = AuthEncap(pkR, skS)        # dh = DH(skE,pkR) || DH(skS,pkR); kem_context = enc || pkRm || pkSm
info        = "OpenBurnBar-HermesRelay-HPKE-v3|" || key_aad
key,nonce   = KeySchedule_auth(shared, info)
wrappedKey  = AES-256-GCM(key, base_nonce, contentKey, aad=key_aad)
enc         = 65-byte X9.63 ephemeral public key
```

The construction is implemented directly from RFC 9180 §4–§6 on top of the
`cryptography` P-256/HKDF/AES-GCM primitives plus stdlib `hmac`/`hashlib` — **no
new dependency**. It is anchored to the RFC's own Appendix-A known-answer vector
for this exact suite (`test_relay_e2ee_v3.py`), so a reviewer can verify the
encapsulated key, shared secret, key-schedule key/nonce, and ciphertext byte-for-
byte against the RFC text. The recipient binds the **pinned** sender static key in
`AuthDecap` (never a wire-supplied `senderPublicKey`); a forged sender, recipient,
`enc`, `aad`, or ciphertext changes the derived key and fails the AES-GCM tag.

**Authenticated context bound by v3.** Recipient and sender *identities* are bound
cryptographically in the DHKEM `kem_context` (not merely as AAD). The envelope
*version* and *suite* are bound through the `-HPKE-v3` `info` prefix and the
RFC-9180 suite id mixed into every labeled KDF call. Routing identity (`uid`,
`clientId`), the per-message/event/attachment id, and the *payload kind* are bound
through the injective, delimiter-guarded request `aad` (`RelayNamespace.aad`
rejects any `|` or control char, so the flat part-list cannot be re-segmented).
Attachment slots are separated by distinct manifest/body/key AAD labels. A
fully length-prefixed canonical AAD would be a future coordinated wire bump across
all three client languages and is intentionally out of scope here.

## Attack Matrix

Relay-as-adversary. Each row names the defending code path, the test that pins it,
and the residual caveat. `relay_e2ee` = `gateway/crypto/relay_e2ee.py`; the open
dispatch is `_RelaySealer._open_envelope` in `adapter.py`.

| Threat | Defense / code path | Test | Residual caveat |
|---|---|---|---|
| Relay reads plaintext | Every body is AES-256-GCM-sealed under a content key wrapped to the peer; the relay store-and-forwards ciphertext only. `seal_message`/`seal_attachment`/`seal_model_switch` + `must_seal` | `test_relay_e2ee_v3::test_v3_unwrap_then_open_payload`; `test_burnbar_plugin` must-seal suite | Routing ids, ids, timing, approximate sizes stay visible. |
| Relay forges phone→agent | `_open_envelope` binds the **pinned** peer key in `unwrap_symmetric_key_v3` (HPKE `AuthDecap`) / v2 `unwrap_symmetric_key`; the wire `senderPublicKey` is advisory. | `test_burnbar_plugin_v3::test_open_event_refuses_v3_frame_from_wrong_sender`; `test_relay_e2ee_v3::test_v3_wrong_pinned_sender_raises_invalid_tag` | Holds only if the pin is correct (first-pairing safety code). |
| Relay forges agent→phone | Agent seals with its own static key as the authenticated HPKE sender; the phone opens only against the pinned agent key. | `test_seal_message_emits_v3_to_v3_peer_and_phone_opens` | Same pin dependency on the client side. |
| Relay strips v3 sender fields | `_open_envelope` refuses a v3 frame missing `enc` or the HPKE `relayEncryption` marker; `AuthDecap` binds the pinned sender regardless. | `test_open_event_refuses_v3_frame_with_stripped_enc`, `…without_hpke_marker` | — |
| Relay downgrades v3→v2/v1 | Version dispatch refuses anything outside `{2, 3}`; v1 and plaintext are unreachable on a paired link; v2 and v3 wraps do not cross-open (domain-separated). | `test_open_event_refuses_downgraded_version`; `test_relay_e2ee_v3::test_v3_wrap_does_not_open_under_v2_unwrap`, `…v2_wrap_does_not_open_under_v3_unwrap` | A v2-capable link legitimately still *accepts* v2 (both are authenticated); this is version support, not a downgrade to plaintext. |
| Relay replays authenticated frames | Persisted replay ledger: id dedup + high-water `replayCounter`, recorded only **after** a successful authenticated open. | `test_burnbar_plugin` replay suite | The cache, not AES-GCM, is the replay boundary. |
| Relay swaps attachment manifest/body/key slots | Manifest, body, and key are bound to **distinct** AAD labels; any swap fails the tag. | `test_relay_e2ee_v3::test_v3_attachment_manifest_body_slot_swap_rejected` | — |
| Relay rotates TOFU pins | The pin is immutable post-pairing (`_pin_peer_public_key(allow_new_pin=False)`); the peer wrap version is raised to v3 only by the authenticated pairing grant, never runtime state. | `test_burnbar_plugin` pin suite; `test_pairing_grant_selects_v3_runtime_does_not` | The first pin still trusts the pairing safety code. |
| Relay injects model-switch flags | `model_switch` is a typed, sealed control event opened only through the authenticated open path; the model id is validated (`_is_safe_model_id`) before `/model` is applied. | `test_seal_attachment_and_model_switch_emit_v3_to_v3_peer`, `test_open_model_switch_opens_v3_frame`; `test_burnbar_plugin` model-switch suite | — |
| Relay mixes sender key ids | One pinned key per link; v3 carries no per-frame key-id selector, so there is no key to mix. | (n/a — single pin) | Per-frame key-id selectors are out of scope; rotation is by authenticated re-pairing. |
| Relay reorders messages | The AAD binds the per-message id and the replay high-water counter drops stale frames. | `test_burnbar_plugin` replay suite | No cryptographic total-order guarantee under a relay-only model. |
| Recipient key compromise | Explicit non-goal — the KCI bound of any 2-DH `AuthEncap` (v2) or HPKE `AuthDecap` (v3). | documented | If the recipient static key leaks, an attacker can decrypt prior wraps and forge as any sender; store the key in the OS keychain. |
| First-pairing MITM | Two-key safety code compared by the human at pairing before the pin is persisted. | setup safety-code prompt (defaults to "no") | Defeated if the user approves without comparing the code. |

## Fail-Closed Requirements

- E2E setup requires `uid`, `clientId`, and the phone relay public key from the
  authenticated device grant. Runtime `/events` or `/state` responses can
  confirm these AAD-binding values but cannot establish the first value.
- E2E open requires `relayKeyVersion` in `{2, 3}` and unwraps only with the pinned
  peer sender key (v2 `unwrap_symmetric_key` / v3 `unwrap_symmetric_key_v3`). A v3
  frame is additionally refused without its HPKE `enc` and `relayEncryption` marker.
  The relay-visible `senderPublicKey` field is advisory. The peer wrap version is
  raised to v3 only by the authenticated pairing grant
  (`BURNBAR_RELAY_PEER_KEY_VERSION`), never runtime relay state; an unknown/v2-only
  peer floors to v2 and `BURNBAR_DISABLE_GATEWAY_HPKE_V3=1` forces v2-only emission.
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

`tests/gateway/fixtures/HermesGatewayWireVector.json` is a known-answer vector for
the v2 key wrap and payload opening (event, agent reply, model_switch, and
attachment slots), including wrong-sender and wrong-recipient rejection. Its event
and `model_switch` plaintexts already carry the strict E2E schema (authenticated
`destinationId` + `replayCounter`), and
`test_gateway_event_vector_passes_production_open_path` runs that slot through the
full production `_handle_burnbar_event` path — not merely the bare crypto open.

`tests/gateway/fixtures/HermesGatewayWireVectorV3.json` is the parallel v3
known-answer vector: the same slots and synthetic keys, wrapped with RFC 9180 HPKE
`mode_auth`, each slot carrying the HPKE `enc` and the `relayKeyVersion`/
`relayEncryption` markers. `test_relay_e2ee_v3.py` opens every slot, exercises the
wrong-sender / wrong-recipient / tampered-AAD / tampered-ciphertext / tampered-enc
/ stripped-enc / cross-version rejections, and validates the production HPKE
primitives against the **RFC 9180 Appendix-A** known-answer vector for the exact
shipped suite (`mode_auth`, P-256, HKDF-SHA256, AES-256-GCM).

All three vectors (v1 realtime, v2 gateway, v3 gateway) are regenerated and
byte-verified in-tree by `tests/gateway/vectors/generate_wire_vectors.py`
(`python -m tests.gateway.vectors.generate_wire_vectors --check`, also enforced by
`tests/gateway/test_wire_vectors_reproducible.py`), so a maintainer can re-derive
every ciphertext byte from this repo alone with no non-Python toolchain — and the
`--check` fails if any committed fixture drifts. The static test keypairs are
intentionally low-entropy synthetic scalars; no production key material is
embedded. The same wire format is implemented by the BurnBar iOS/Android clients;
cross-language parity is maintained in those client repositories and is not
re-proven here.

## Migration (v2 → v3)

v3 is purely additive. v1/v2 wire bytes and vectors are unchanged, so existing
paired links keep working with no action. A link is raised to v3 only when the
authenticated pairing grant advertises v3 capability (`gatewayRelayKeyVersion: 3`
or the HPKE `gatewayRelayEncryption` marker), which the setup flow persists as
`BURNBAR_RELAY_PEER_KEY_VERSION=3`; until then the agent emits v2. Both peers
always *open* whichever supported version arrives (the open path is version-
dispatched), so an agent and client can upgrade independently. To roll back, set
`BURNBAR_DISABLE_GATEWAY_HPKE_V3=1`: the agent advertises and emits v2 only while
still accepting any already-issued v3 frame it can authenticate.
