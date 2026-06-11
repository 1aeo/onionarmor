# ssh-hardening

**Write a Mozilla-OpenSSH-guidelines hardening drop-in to one managed file —
disable root and password login, pin modern Kex/Cipher/MAC/HostKey algorithms,
cap auth retries, set a client-alive timeout, and turn off X11/agent/gateway/
tunnel forwarding — then prune weak DSA/ECDSA host keys and regenerate a
sub-4096-bit RSA host key.**

It maps to the onionauditor **`ssh-hardness`** category. Because a wrong cipher
set, or `PasswordAuthentication no` on a host with no key installed, can lock the
operator out on the **next** login, this module is **recommended-OFF by default**
and arms a 5-minute auto-revert safety latch before reloading sshd.

## Risk

**Medium-HIGH.** Unlike kernel-hardening, this changes how you authenticate.
Disabling password auth and root login, or restricting algorithms a client/jump
host doesn't support, can strand you. The safety latch (below) makes a bad apply
self-recovering, but you should still confirm a fresh SSH session works before
cancelling it.

## Quick start

```sh
# Apply (writes the drop-in, arms a 5-min auto-revert latch, validates, reloads):
sudo onionarmor apply --module ssh-hardening

# See what would change first (no host changes, arms no latch):
sudo onionarmor apply --module ssh-hardening --dry-run

# After applying: open a NEW ssh session, confirm you can log in, THEN:
sudo onionarmor apply --module ssh-hardening --cancel-safety-latch

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module ssh-hardening

# Undo (removes the drop-in; sshd returns to distro defaults):
sudo onionarmor revert --module ssh-hardening
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | off | Print the rendered drop-in + the planned `sshd -t` validation + the latch plan. Changes nothing. |
| `--no-safety-latch` | latch on | Skip the auto-revert latch. **Console access required** — a wrong config locks you out with no auto-recovery. |
| `--cancel-safety-latch` | — | Cancel a pending auto-revert latch and exit 0. Run once you've confirmed you can still SSH in. |
| `--latch-minutes <N>` | 5 | Auto-revert window in minutes (must be ≥ 1). |
| `-h`, `--help` | — | Module help. |

## Managed directives

Written to `/etc/ssh/sshd_config.d/99-onionarmor-hardening.conf` in a
byte-deterministic order (so a re-apply with no change rewrites nothing). Source:
<https://infosec.mozilla.org/guidelines/openssh>.

| Directive | Value | Why |
|---|---|---|
| `PermitRootLogin` | no | No direct root SSH — force a named account + `sudo`. |
| `PasswordAuthentication` | no | Key-only auth; defeats credential-stuffing / brute force. |
| `HostKeyAlgorithms` | ed25519, rsa-sha2-512/256 | Drop weak/legacy host-key types. |
| `KexAlgorithms` | curve25519 + ecdh + DH-group16/18 (SHA-2) | Modern key exchange only. |
| `Ciphers` | chacha20-poly1305, aes-gcm, aes-ctr | AEAD-first, no CBC/arcfour. |
| `MACs` | hmac-sha2 / umac-128 (ETM) | Encrypt-then-MAC only. |
| `MaxAuthTries` | 3 | Cap auth attempts per connection. |
| `ClientAliveInterval` | 300 | Reap idle/dead sessions. |
| `X11Forwarding` | no | A relay has no X clients. |
| `AllowAgentForwarding` | no | No agent hijacking via a compromised relay. |
| `GatewayPorts` | no | No remote-bound forwarded ports. |
| `PermitTunnel` | no | No tun/tap VPN tunnels over SSH. |
| `UsePAM` | yes | Keep PAM (account/session, lockout policies). |

## What it does

1. Backs up any pre-existing drop-in and records whether it pre-existed (so the
   latch can restore vs. remove).
2. Renders a `#!/bin/sh` restore script and **arms the shared safety latch**
   (`at now + N min`) **before** reloading sshd. If `at`/atd is unavailable the
   apply aborts without touching the live config (unless `--no-safety-latch`).
3. Writes the drop-in (idempotent via `oa_write_if_changed`).
4. **Validates** with `sshd -t`. A failed validation removes the drop-in (or
   restores the backup), cancels the latch, and exits non-zero — it **never**
   reloads a broken config.
5. Reloads sshd (`systemctl reload ssh`).
6. **Host keys (best-effort, after the config is safely applied):** removes
   `ssh_host_dsa_key*` and `ssh_host_ecdsa_key*`, and regenerates the RSA host
   key at 4096 bits if it is currently weaker. These are warnings, never fatal.

`revert` cancels any pending latch, backs up then removes the drop-in, and
validates + reloads sshd so the distro defaults take over.

## The safety latch

This module uses the shared `lib/safety_latch.sh` dead-man's switch. A broken SSH
config only bites on the **next** login, so polling can't catch it — only a
wall-clock timer can. The flow:

1. Apply renders a restore script that undoes the change (restore the prior
   drop-in, or remove ours) and validates + reloads sshd.
2. That script is scheduled via `at now + 5 minutes` **before** sshd is reloaded.
3. Apply prints the cancel command and **`atrm <jobid>`**.
4. You open a fresh SSH session and confirm you can still log in, then cancel:
   `onionarmor apply --module ssh-hardening --cancel-safety-latch`.
5. If you do **not** cancel within the window, atd fires the restore script and
   the host reverts to its pre-apply sshd config — a bad change can never strand
   you. `--no-safety-latch` disables this (console access required).

## Threat model

Shrinks the SSH attack surface: no root login or password brute-forcing, no
downgrade to weak ciphers/MACs/kex or legacy host-key types, no
forwarding-based pivoting (X11/agent/gateway/tunnel) through a compromised
relay, and no weak (DSA/ECDSA/sub-4096 RSA) host keys for an attacker to factor
or impersonate. It does **not** install fail2ban or change the SSH port, and it
cannot restore host keys it deleted — a `revert` returns sshd to distro defaults
but the pruned DSA/ECDSA keys are gone for good (clients that pinned them must
re-trust the host).

## Tests

`tests/bats/` drives apply→audit→revert against stub `sshd` (a `-t` validator
with a controllable exit code), `systemctl` (records reloads), `ssh-keygen`
(controllable RSA bit count + a regeneration log), and the firewall suite's
`at`/`atrm` stubs wired to the shared latch: full-directive render, idempotency
(no second latch stacked), `--dry-run` writes/reloads nothing, the latch is
armed (jobid + staged `restore.sh` + printed cancel command), `--no-safety-latch`
applies without a latch, `--cancel-safety-latch` disarms it, a failed `sshd -t`
removes the drop-in + cancels the latch + exits non-zero with **no** reload, a
latch-arming failure (atd down) aborts before writing anything, DSA/ECDSA key
removal, RSA regeneration below 4096 (and none at/above), audit RED-before /
GREEN-after / yellow-while-latch-pending, and the apply→audit→revert→audit round
trip — 32 tests.
