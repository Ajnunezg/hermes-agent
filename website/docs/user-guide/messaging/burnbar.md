---
sidebar_position: 9
title: "BurnBar Cloud"
description: "Connect Hermes Agent to BurnBar Cloud through the BurnBar Hermes Gateway API"
---

# BurnBar Cloud Setup

BurnBar Cloud connects to Hermes through the BurnBar Hermes Gateway API. Hermes
runs the gateway adapter locally; BurnBar provides the mobile and cloud surface
that sends events to the adapter and receives replies.

Use this integration when you want BurnBar to act as a mobile control surface for
a local Hermes agent: send messages, receive replies, approve sensitive actions,
and route scheduled `deliver=burnbar` notifications to a home destination.

## Capabilities

| Surface | Behavior |
|---------|----------|
| **Inbound events** | Hermes polls BurnBar `/events` with a durable cursor. |
| **Replies** | Hermes sends through `/messages`. |
| **Typing** | Hermes publishes typing state through `/typing`. |
| **Attachments** | Hermes initializes signed uploads through `/attachments/init`. |
| **Relay content encryption** | On a paired link, sealed message and attachment bodies are relay-blind with a static-key wrap. |
| **Oversight** | Supervised mode gates slash confirmations; autonomous mode auto-approves. |
| **Cron delivery** | `deliver=burnbar` sends to `BURNBAR_HOME_CHANNEL`. |

## Setup

Run the gateway setup wizard and choose **BurnBar Cloud**:

```bash
hermes gateway setup
hermes gateway restart
hermes gateway status
```

The setup flow starts a device-code grant. Approve the displayed code in BurnBar,
then restart the gateway. The approved token is written to your active Hermes
home `.env`.

## Configuration

The setup flow writes the required token automatically:

| Variable | Purpose |
|----------|---------|
| `BURNBAR_ACCESS_TOKEN` | Scoped bearer token from the approved device grant. |
| `BURNBAR_API_BASE_URL` | Gateway API base URL. Defaults to the BurnBar Cloud API. |
| `BURNBAR_HOME_CHANNEL` | Default destination for cron and notification delivery. |
| `BURNBAR_HOME_CHANNEL_NAME` | Human-readable label for the home destination. |
| `BURNBAR_ALLOWED_USERS` | Comma-separated BurnBar sender IDs allowed to reach Hermes. |
| `BURNBAR_ALLOW_ALL_USERS` | Set to `true` only for a trusted account/workspace. |
| `BURNBAR_OVERSIGHT_MODE` | E2E-paired oversight mode. Defaults to `supervised`. |
| `BURNBAR_ALLOW_PLAINTEXT` | Set to `1` only to opt back into the legacy plaintext relay path after this agent holds an E2E relay identity. |

You can also set non-secret defaults in `config.yaml` under the BurnBar platform
entry. Secrets belong in `.env`.

## Access Control

BurnBar uses the same gateway access-control model as other Hermes messaging
platforms:

- set `BURNBAR_ALLOWED_USERS` for an explicit sender allowlist
- set `BURNBAR_ALLOW_ALL_USERS=true` only when every sender in the connected
  BurnBar account is trusted
- use `/whoami` from BurnBar to confirm the active scope and command access

## Oversight Mode

On legacy plaintext links, BurnBar's server-owned `/state` response controls the
current oversight mode:

- `supervised` arms a phone approval gate before slash-confirm actions proceed
- `autonomous` allows the adapter to auto-approve those actions

On E2E-paired links, the relay-visible `/state` toggle is not authoritative.
The mode is pinned from pairing state (`BURNBAR_OVERSIGHT_MODE`) and can change
only through phone-authenticated sealed `oversight_mode` events.
Supervised approval prompts keep the readable summary, command, file path, and
tool arguments in the sealed message channel. The relay-visible approval gate
still carries the opaque action id, destination id, and coarse `toolName`.

## Relay Content Encryption

When the BurnBar client and Hermes link are E2E-paired, the adapter uses the
`p256-hkdf-sha256-aesgcm` relay wire format from
`plugins.platforms.burnbar.relay_e2ee`:

- outgoing reply bodies, attachment manifests/bytes, sender names, file names,
  content types, and readable approval prompt details are sealed to the phone's
  pinned relay key
- inbound sealed events must be version 2 and authenticate as the pinned phone
  sender key
- plaintext is refused on paired links

This is relay-content confidentiality, not Signal-grade metadata privacy. The
relay still sees routing ids, event/message ids, timing, approximate ciphertext
sizes, typing indicators, attachment ids, approval action ids, coarse approval
`toolName`, runtime model-catalog/current-model/provider status, agent version,
and relay key/envelope metadata such as `relayEncryption`, `relayKeyVersion`,
sender/recipient public keys, wrapped keys, ciphertext fields, and ciphertext
lengths. The static-key leg has no post-compromise forward secrecy; see
`plugins/platforms/burnbar/SECURITY.md` in the repository for the exact threat
model.

## Troubleshooting

Check the gateway status first:

```bash
hermes gateway status
hermes logs --level warning
```

Common causes:

- `BURNBAR_ACCESS_TOKEN` is missing or expired: rerun `hermes gateway setup`
- the home channel is unset: send from BurnBar once or set `BURNBAR_HOME_CHANNEL`
- the sender is denied: add the sender to `BURNBAR_ALLOWED_USERS` or explicitly
  enable `BURNBAR_ALLOW_ALL_USERS`

## Tests

The plugin tests load the adapter through the same plugin-loader guard used by
the Hermes gateway tests:

```bash
scripts/run_tests.sh \
  tests/gateway/test_burnbar_plugin.py \
  tests/gateway/test_burnbar_e2ee.py \
  tests/gateway/test_relay_e2ee.py \
  tests/gateway/test_relay_e2ee_v2.py \
  tests/gateway/test_wire_vectors_reproducible.py
```
