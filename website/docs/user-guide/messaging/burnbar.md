---
sidebar_position: 7
title: "BurnBar Cloud"
description: "Set up Hermes Agent as a BurnBar Cloud messaging surface"
---

# BurnBar Cloud Setup

BurnBar Cloud lets you use BurnBar as a Hermes messaging surface. After setup,
Hermes receives BurnBar messages, replies back into BurnBar, shows typing state,
and can deliver generated files as BurnBar attachments.

> Run `hermes gateway setup` and pick **BurnBar Cloud** for the guided device-code flow.

## Prerequisites

- A BurnBar Cloud or BurnBar Cloud Pro account
- A Hermes Agent install with the messaging gateway enabled
- Network access from the Hermes host to `https://api.burnbar.ai`

No bot token or third-party chat-app developer account is required. Hermes starts
a device-code link, BurnBar shows you the approval screen, and Hermes saves the
scoped gateway token to `~/.hermes/.env`.

## Configure Hermes

### Via setup wizard

```bash
hermes gateway setup
```

Select **BurnBar Cloud**, then:

1. Confirm the BurnBar Hermes Gateway API URL.
2. Open the approval link shown by Hermes.
3. Sign in to BurnBar with a Cloud or Cloud Pro account.
4. Approve the displayed code.
5. Restart the gateway when setup completes.

The wizard writes:

```dotenv
BURNBAR_API_BASE_URL=https://api.burnbar.ai/v1/hermes-gateway
BURNBAR_ACCESS_TOKEN=obb_hgw_...
BURNBAR_HOME_CHANNEL=burnbar:home
```

### Via environment variables

If you already have a BurnBar Hermes Gateway token, add:

```dotenv
BURNBAR_ACCESS_TOKEN=obb_hgw_...
BURNBAR_HOME_CHANNEL=burnbar:home
```

| Variable | Required | Description |
|---|---|---|
| `BURNBAR_ACCESS_TOKEN` | Yes | Scoped bearer token issued by BurnBar's device-code flow |
| `BURNBAR_API_BASE_URL` | Optional | Gateway base URL. Defaults to `https://api.burnbar.ai/v1/hermes-gateway` |
| `BURNBAR_HOME_CHANNEL` | Optional | Default BurnBar destination for cron and notification delivery |
| `BURNBAR_HOME_CHANNEL_NAME` | Optional | Display label for the home destination |
| `BURNBAR_ALLOWED_USERS` | Recommended | Comma-separated BurnBar sender IDs allowed to talk to Hermes |
| `BURNBAR_ALLOW_ALL_USERS` | Optional | Set `true` to allow every sender on this BurnBar account |

## Device-Code Security Model

BurnBar does not ask users to paste long-lived app passwords into Hermes. Setup
uses a short device code:

1. Hermes creates a one-time device session with a hashed device secret.
2. The user signs in to BurnBar and approves the code.
3. BurnBar returns a scoped token to the polling Hermes process one time.
4. BurnBar stores only a hash-indexed token record server-side.
5. Users can revoke connected Hermes clients from BurnBar.

Gateway tokens are scoped to Hermes messaging reads, writes, and client
management. BurnBar revalidates Cloud or Cloud Pro entitlement on authenticated
gateway requests.

## Sending Files to BurnBar

BurnBar supports native attachment delivery. When Hermes produces a local file
or an agent response uses `MEDIA:/path/to/file`, the adapter:

1. Creates a BurnBar attachment manifest.
2. Uploads the file through a short-lived signed URL.
3. Sends the BurnBar message with the resulting attachment ID.

This supports images, documents, audio, and video files up to the BurnBar
gateway attachment limit.

## Cron Delivery

Set `BURNBAR_HOME_CHANNEL`, then cron jobs can deliver to BurnBar:

```python
cronjob(
    action="create",
    schedule="every weekday at 8am",
    deliver="burnbar",
    prompt="Summarize what changed overnight and send a short action list.",
)
```

You can also target a destination explicitly:

```python
send_message(target="burnbar:burnbar:home", message="Done.")
```

## Troubleshooting

**Setup code expires** - Run `hermes gateway setup` again and approve the new code.

**Authorization fails** - Sign in with a BurnBar Cloud or Cloud Pro account. Free
accounts cannot approve Hermes Gateway clients.

**Gateway starts but ignores messages** - Check `BURNBAR_ALLOWED_USERS`. If it is
set, the sender ID in BurnBar must be included. For a personal single-user
setup, `BURNBAR_ALLOW_ALL_USERS=true` is acceptable.

**Cron delivery fails** - Make sure `BURNBAR_HOME_CHANNEL` is set and the token
has not been revoked from BurnBar.

**Attachments fail** - Confirm the file still exists on the Hermes host and is
under the BurnBar attachment size limit.
