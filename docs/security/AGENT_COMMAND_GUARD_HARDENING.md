# Agent command-guard hardening (OpenBurnBar security remediation C-4)

**Threat:** OpenBurnBar drives this agent on a user's Mac and can be steered
remotely. The dominant risk is *prompt injection → host action*: untrusted
content (a web page, a repo file, screen text, a remote chat message) coerces
the model into a tool call that reads the user's secrets or exfiltrates them.

The always-on command guard (`tools/approval.py`) already covered destructive
operations (`rm -rf`, `dd`, `mkfs`, fork bombs, shutdown) and remote-to-shell
pipes (`curl … | sh`). This change closes the remaining gaps.

## What changed

1. **Secret-file reads are now gated.** `cat ~/.ssh/id_rsa`,
   `cat ~/.aws/credentials`, `head ~/.config/gcloud/...`, reading `*.pem` /
   `*.p12` / `id_rsa*`, `cat ~/.hermes/.env`, etc. now require explicit human
   approval. Previously the sensitive-path fragments were only used in *write*
   patterns, so secret **reads** ran silently.

2. **Credential exfiltration is now gated.** `security dump-keychain` /
   `security find-*-password`, `curl --data @file` / `curl -T file`,
   `scp/sftp <secret> user@host:`, `nc host < secret`, and `put <secret>`
   (sftp/ftp) now require approval.

3. **tirith fails CLOSED by default.** `tools/tirith_security.py` previously
   defaulted `tirith_fail_open = True` — if the policy scanner could not run
   (spawn error, timeout, install-in-progress) the command was silently
   allowed. The shipped default is now **fail-closed**: an unavailable scanner
   routes the command through the approval flow instead of waving it through.
   Operators who accept the risk can opt back in via
   `security.tirith_fail_open: true` or `TIRITH_FAIL_OPEN=1`.

4. **The injectable smart-guardian can no longer rubber-stamp exfil.** When
   `approvals.mode: smart`, the auxiliary "is this safe?" LLM reads
   attacker-influenced command text and is itself susceptible to prompt
   injection. The highest-sensitivity categories (secret reads, credential
   exfil, keychain dumps) now **always escalate to a human** even in smart
   mode (`_NEVER_SMART_APPROVE_DESCRIPTIONS`).

5. **Opt-in subprocess-env hardening.** `HERMES_HARDEN_SUBPROCESS_ENV=1` (or
   `security.harden_subprocess_env: true`) additionally strips third-party
   secret-shaped env vars (`AWS_SECRET_ACCESS_KEY`, `*_TOKEN`, `*_API_KEY`, …)
   from terminal subprocesses. Default **off** to preserve the reviewed
   "agent == user" posture (GHSA-rhgp-j443-p4rf); the existing
   `env_passthrough` allow-list always wins.

These changes are **additive** to the deny-list: the worst outcome of a false
positive is one extra confirmation prompt, never a missed destructive command.
The default approval mode remains `manual` (human confirmation); `smart`,
`off`, and `--yolo` are explicit opt-ins, and approval timeouts deny
("silence is not consent").

## Why NOT a blanket OS sandbox (sandbox-exec / seatbelt)

The audit suggested wrapping every command in a `sandbox-exec` profile that
denies reading `~/.ssh`, the Keychain, `~/.aws`, etc. **We deliberately did not
do this**, because a kernel-level deny-read cannot distinguish legitimate use
from exfiltration and would break core functionality:

- Deny-read of `~/.ssh/id_rsa` breaks `ssh` and `git`-over-SSH (they read the
  key to authenticate).
- Deny-read of the login Keychain breaks the `osxkeychain` git credential
  helper and any tool that stores creds there.
- Deny network egress breaks `curl`, `git`, `pip`, and most agent work.

The **command guard is the more precise mechanism**: it flags `cat`/`base64`/
`scp` of a key (exfil-shaped) for approval while allowing `ssh user@host`
(legitimate use) — a distinction the OS sandbox cannot make.

For **true isolation**, run the agent under one of the already-supported
containerized backends (`docker`, `modal`, `singularity`, `daytona`). Those
backends cannot touch the host, so the guard intentionally bypasses them.
**Recommendation:** for remote-controlled / untrusted sessions, default the
backend to `docker` rather than `local`. (`local` remains full-user trust and
should be treated as such.)

## Tests

`tests/tools/test_secret_exfil_guard.py` — 40 cases covering secret-read/exfil
detection, false-positive avoidance on everyday commands (`ls ~/.ssh`,
`cat README.md`, `curl --data '{json}'`, `ssh-keygen`, `git`, `npm install`),
the fail-closed default, the smart-mode escalation, and the env heuristic.
