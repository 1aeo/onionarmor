# account-hygiene

**Tighten local account / sudo posture on a relay host: lock + de-sudo the
cloud-init default accounts, enforce an operator sudo allowlist across the
`sudo`/`wheel`/`admin` groups, assert only `root` has UID 0, and flag blanket
`NOPASSWD: ALL` sudoers rules.**

This module maps to the onionauditor **`accounts`** category. It is **medium
risk** and **recommended-off by default**: a mis-applied account or sudo change
can lock the operator out, so apply requires either `--dry-run` or `--confirm`
and arms a 5-minute safety latch that auto-restores the prior state.

## Risk

**Medium.** Stripping the wrong user from `sudo`, or locking the only working
account, can lock you out of the host. Two guards make that recoverable:

1. A bare `apply` (no `--dry-run`, no `--confirm`) **refuses to mutate** — it can
   never silently lock accounts.
2. Before any change, apply snapshots the current membership/locks, renders a
   `/bin/sh` restore script, and **arms a 5-minute `at`-job safety latch** that
   re-adds every removed user and unlocks every locked account. You confirm you
   can still `sudo`, then cancel the latch; if you do not, the host auto-reverts.

If the operator sudo allowlist file is **absent**, apply **dies** rather than
risk removing every sudoer (which would itself be a lockout).

## Quick start

```sh
# 0. Create the operator sudo allowlist (one username per line):
sudo install -Dm644 /dev/stdin /etc/onionarmor/sudo-allowlist.conf <<'EOF'
# operators allowed to keep sudo/wheel/admin
operator
EOF

# 1. Preview every account/group change (no host changes):
sudo onionarmor apply --module account-hygiene --dry-run

# 2. Apply (mutates; arms the 5-min latch — read the printed cancel command):
sudo onionarmor apply --module account-hygiene --confirm

# 3. Confirm you can still `sudo`, THEN cancel the latch within 5 minutes:
sudo onionarmor apply --module account-hygiene --cancel-safety-latch

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module account-hygiene

# Undo (cancels any latch + restores the snapshot):
sudo onionarmor revert --module account-hygiene
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | off | Print the full plan of every lock / de-sudo / removal and exit. Changes nothing. Default-safe. |
| `--confirm` | off | Required to actually mutate accounts/groups. Without `--dry-run` and without `--confirm`, apply refuses (or prompts) so a bare run can't silently lock you out. |
| `--no-safety-latch` | off | Do **not** arm the 5-minute auto-restore latch. Console access strongly recommended. |
| `--cancel-safety-latch` | — | Cancel a pending safety latch and exit (no other work). |
| `--latch-minutes <N>` | 5 | Minutes before the latch auto-restores. |
| `-h`, `--help` | — | Module help. |

## What it does

1. **Cloud-init defaults.** For each of `ubuntu debian ec2-user centos fedora
   admin vagrant pi` that actually exists (overridable via
   `ONIONARMOR_AH_CLOUD_DEFAULTS`), it locks the account (`usermod -L`) and
   removes it from `sudo` (`gpasswd -d`). Only present accounts are touched.
2. **Operator allowlist.** Reads `/etc/onionarmor/sudo-allowlist.conf` (one
   username per line, `#` comments; path overridable via
   `ONIONARMOR_AH_ALLOWLIST`). Any member of `sudo`, `wheel`, or `admin` not on
   the allowlist is removed from that group. **If the allowlist is missing, apply
   dies** with instructions — it will not strip every sudoer.
3. **UID 0 assertion.** If any account other than `root` has UID 0, that is a
   hard problem (possible backdoor). Audit **FAILs** and apply **warns loudly** —
   it is never auto-fixed (deleting a stray UID-0 account blindly is too risky).
4. **`NOPASSWD: ALL` scan.** Any file in `/etc/sudoers.d/` (overridable via
   `ONIONARMOR_AH_SUDOERS_D`) containing a blanket `NOPASSWD: ALL` line is a FAIL
   in audit and a loud warning in apply. Sudoers files are **never auto-edited** —
   a bad edit can break `sudo` entirely.

`audit` is read-only: it reports each of the four checks plus a yellow line when
a safety latch is still pending. `revert` cancels any pending latch and restores
the snapshot taken at apply (re-adds removed users to their groups, unlocks
locked accounts); if no snapshot exists, it says so.

## Safety latch

This module uses the shared `lib/safety_latch.sh` dead-man's-switch under the
literal module name `account-hygiene`. Apply (unless `--no-safety-latch`):

1. Snapshots the current `sudo`/`wheel`/`admin` membership and which cloud
   accounts are unlocked.
2. Renders a `/bin/sh` restore script that re-adds every user it is about to
   remove and unlocks every account it is about to lock.
3. Arms that script via `at now + N minutes`. **If arming fails (atd down), apply
   dies before mutating anything** — a risky account change with no auto-revert
   is exactly what the latch exists to prevent.
4. Performs the mutations, then prints the job id and both cancel commands:
   `atrm <jobid>` and `onionarmor apply --module account-hygiene
   --cancel-safety-latch`.

Confirm you can still `sudo`, then cancel within N minutes — otherwise the host
restores your prior account/sudo state automatically.

## Threat model

Reduces the local attack surface and lateral-movement / persistence footholds on
a relay host: well-known cloud-init accounts (`ubuntu`, `ec2-user`, …) with
default or guessable credentials and inherited sudo, sudo creep where stale
operators accumulate in `sudo`/`wheel`/`admin`, stealthy non-root UID-0
backdoors, and blanket `NOPASSWD: ALL` rules that turn any compromised allowed
user into instant root. It does **not** manage SSH key/credential policy or PAM —
it complements those. It assumes the operator maintains an accurate allowlist;
the latch + mandatory dry-run/confirm make an over-aggressive allowlist
recoverable rather than fatal.

## Tests

`tests/bats/` drives apply→audit→revert against stub `getent`/`usermod`/`passwd`/
`gpasswd` backed by a fake passwd + group + lock database, plus stub `at`/`atrm`
for the shared latch — fully offline, no root, never touching the real host.
Coverage: `bash -n`; dry-run prints the plan and changes nothing; missing
allowlist dies with no mutation; a stranger in `sudo`/`wheel`/`admin` is removed
while an allowlisted user stays; a present cloud default (`ubuntu`, `pi`) is
locked + de-sudoed; a non-root UID-0 account → audit RED + apply warns; a
`NOPASSWD: ALL` sudoers.d file → audit RED + apply warns (no edit); latch armed
(job id + `restore.sh` staged) with the cancel command printed; `--no-safety-latch`;
`--cancel-safety-latch`; latch-arm failure aborts before any mutation; revert
restores membership + unlocks; the apply→audit→revert→audit round trip; and the
audit-log lines.
