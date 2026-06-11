# account-hygiene

Clean up the account attack surface a cloud image leaves behind: lock and
de-sudo leftover cloud-init users, enforce an operator sudo allowlist, refuse
shared UID-0 accounts, and flag blanket `NOPASSWD: ALL` sudoers — behind a
**5-minute safety latch** so a wrong allowlist can't strand the operator.

| | |
|---|---|
| **Risk** | Medium — a misconfigured allowlist could remove your own sudo. Mitigated by the safety latch + confirmation prompt. |
| **Default** | **Off** (opt-in). |
| **Manages** | sudo-group membership + account lock state for cloud-init users. Reports (never edits) `/etc/sudoers.d` and shared UID-0 accounts. |
| **Needs** | `at` (for the latch), `getent`, `gpasswd`, `usermod`, `passwd`. |

```sh
sudo onionarmor apply  --module account-hygiene --dry-run   # preview
sudo onionarmor apply  --module account-hygiene             # apply (+ latch)
# confirm you still have sudo (e.g. 'sudo -v'), THEN:
atrm <job>                                                  # cancel the latch
onionarmor      audit  --module account-hygiene
sudo onionarmor revert --module account-hygiene
```

## What it does

- **Cloud-init cleanup.** For each of `ubuntu debian ec2-user centos fedora admin
  vagrant pi` that exists and holds sudo: remove it from every sudo group
  (`gpasswd -d`) and lock the account (`usermod -L`). `--purge` additionally
  `userdel -r`s them (not latch-reversible — run without `--purge` first).
- **Sudo allowlist.** `/etc/onionarmor/sudo-allowlist.conf` (one username per
  line, `#` comments). Any user in `sudo`/`wheel`/`admin` not on the allowlist is
  removed from that group. **If the allowlist is missing or empty, enforcement is
  skipped** — a typo can't strip every admin. `--no-allowlist` disables it.
- **Shared UID-0.** Any UID-0 account other than `root` is a **red** audit
  finding. apply reports it but never auto-deletes a UID-0 account.
- **Blanket NOPASSWD.** Any `/etc/sudoers.d/*` granting `NOPASSWD: ALL` is a
  **red** audit finding; apply warns but never edits sudoers.

## The safety latch

Before removing any sudo, apply snapshots the current membership, renders a
restore script, and schedules an `at` job for 5 minutes out that re-adds the
removed memberships and unlocks the accounts. Confirm you still have sudo, then
cancel the latch with the printed `atrm` command. `--no-safety-latch` skips it
(console access required); `--latch-minutes <n>` changes the delay.

## Threat model

Cloud images ship a default sudo-capable account (`ubuntu`, `ec2-user`, …) with a
well-known name — a standing target for credential attacks. Stale admins
accumulate as a fleet ages, and a single shared UID-0 account or blanket
`NOPASSWD: ALL` collapses the whole privilege model. This module shrinks the set
of accounts that can escalate to exactly the operator's allowlist, while refusing
to make any change it cannot reverse (no UID-0 deletion, no sudoers edits) and
guarding the reversible changes with the latch.
