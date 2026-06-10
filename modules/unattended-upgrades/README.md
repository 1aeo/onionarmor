# Module: `unattended-upgrades`

**Auto-install Debian/Ubuntu _security_ updates every day, and reboot at 03:00 only when an upgrade says one is required.**

`unattended-upgrades` turns on the distro's own unattended-upgrade machinery
under the 1aeo fleet posture: **security archives only** (never the feature
pockets), a daily `apt update` + unattended upgrade, and an automatic reboot
**at 03:00 that fires only when an upgrade sets `/run/reboot-required`** (kernel
or libc). It installs `unattended-upgrades` + `apt-listchanges` if missing and
writes two managed `apt.conf.d` drop-ins.

> A relay that is months behind on security patches is the easy target on the
> fleet. Letting security fixes land unattended — while feature upgrades stay a
> deliberate, operator-driven act — keeps the patch window small without
> surprising version bumps. See [Threat model](#threat-model).

## Quick start

```sh
# Turn on unattended security upgrades (autodetects Debian/Ubuntu + codename):
sudo onionarmor apply --module unattended-upgrades

# See exactly what it would do first — changes nothing:
sudo onionarmor apply --module unattended-upgrades --dry-run

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module unattended-upgrades

# Undo (restores the distro defaults, masks the service — disables the control):
sudo onionarmor revert --module unattended-upgrades
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--distro <Debian\|Ubuntu>` | autodetected | Override the distribution (otherwise from `lsb_release -is`, then `/etc/os-release`). |
| `--codename <name>` | autodetected | Override the release codename (e.g. `bookworm`, `noble`). |
| `--reboot` / `--no-reboot` | reboot | Auto-reboot when `/run/reboot-required` appears (kernel/libc). |
| `--reboot-time <HH:MM>` | `03:00` | When to take the reboot. |
| `--reboot-with-users` / `--no-reboot-with-users` | with-users | Reboot even with a logged-in session (default: yes — headless fleet). |
| `--dry-run` | off | Print the plan + both rendered config files. Changes nothing. |

## What it writes

| File | Purpose |
|---|---|
| `/etc/apt/apt.conf.d/50unattended-upgrades` | `Origins-Pattern` (security archives only), reboot policy, dpkg-safety knobs. |
| `/etc/apt/apt.conf.d/20auto-upgrades` | the apt periodic schedule (`Update-Package-Lists "1"; Unattended-Upgrade "1";`). |

The security origins are distribution-specific:

- **Debian** → `origin=Debian,codename=${distro_codename}-security,label=Debian-Security`
- **Ubuntu** → `archive=${distro_codename}-security` plus the `UbuntuESMApps` /
  `UbuntuESM` infra-security archives.

No `-updates` / feature pocket is ever added — only security.

## What `audit` checks

`audit` is read-only and exits non-zero if any check is **red**:

1. **service enabled** — `unattended-upgrades.service` is `enabled` (and active
   or idle-between-runs). **Red** if it is `masked` or `disabled`.
2. **config present + matches** — both managed files exist and match the posture
   byte-for-byte; a short `sha256` is reported. **Red** if missing, drifted, or
   present but not onionarmor-managed.
3. **last run** — the most recent timestamp parsed from
   `/var/log/unattended-upgrades/unattended-upgrades.log`. **Yellow** (not red)
   if the service simply hasn't run yet.
4. **apt holds** — any `apt-mark showhold` packages, which unattended-upgrade
   silently skips. **Yellow**, advisory — a held package is the operator's choice.

## Revert

`revert`:

1. restores `50unattended-upgrades` / `20auto-upgrades` from the distro-default
   backup taken at apply time (or removes our file if there was no prior
   default — and leaves a hand-edited, unmanaged file alone),
2. disables **and masks** `unattended-upgrades.service`.

`unattended-upgrades` and `apt-listchanges` are left installed. **Revert turns
off automatic security updates — it removes a security control;** the command
says so, loudly.

## Threat model

**What this defends:** the patch-latency window. Unpatched, network-reachable
services (OpenSSH, the TLS stack, the kernel) are the most reliable way onto a
host; shrinking the time between a security advisory and the fix being live on
the fleet removes a large class of n-day exposure with no human in the loop.

**Why security-only, and why deliberate feature upgrades:** auto-pulling
`-updates`/feature pockets risks an unattended version bump breaking tor, FRR,
or the relay's own tooling at 03:00. Security archives are the high-value,
low-surprise subset — they get automated; everything else stays a reviewed,
operator-driven upgrade.

**Why reboot only when required:** `Automatic-Reboot` fires only when an upgrade
sets `/run/reboot-required` (kernel / libc), so a relay isn't bounced for a
userspace-only fix. The 03:00 window keeps the brief capacity dip off-peak.

**What it does _not_ do:**

- It does **not** upgrade across releases (no `do-release-upgrade`).
- It does **not** firewall or otherwise harden the services it patches — it only
  keeps them current.
- It does **not** guarantee a reboot happens immediately; required reboots are
  batched to the configured time.

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/apt/apt.conf.d/50unattended-upgrades` | the managed origins + reboot policy |
| `/etc/apt/apt.conf.d/20auto-upgrades` | the managed apt periodic schedule |
| `/var/lib/onionarmor/unattended-upgrades/*.orig` | distro-default backups, restored by `revert` |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against a sandbox.

## Tests

```sh
bats modules/unattended-upgrades/tests/bats/
```

The offline suite stubs `systemctl`, `apt-get`, `dpkg-query`, `apt-mark`,
`lsb_release` and `sha256sum`, covering apply (install, both config files,
security-only origins, Debian vs Ubuntu, reboot flags, idempotency, distro-default
backup), audit (green/yellow/red + exit codes), and revert (restore-or-remove,
mask the service, round-trip). `docker.bats` adds an **opt-in**
apply→audit→revert round-trip on real `debian:bookworm` / `ubuntu:24.04` images
(skipped unless `ONIONARMOR_DOCKER_TESTS=1` and docker is present — CI runs the
offline suite).

---

**See also:** [Modules overview](../../docs/modules.md) · [Troubleshooting](../../docs/troubleshooting.md) · [main README](../../README.md)
