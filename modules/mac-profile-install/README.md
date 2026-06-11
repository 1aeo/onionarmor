# mac-profile-install

**Install and enforce a Mandatory Access Control (MAC) layer for tor, matched to
the host's distro family — AppArmor on Debian/Ubuntu, SELinux on the RHEL
family.** A confined tor process cannot read, write, or exec outside the policy
even if it is exploited.

This module maps to the onionauditor **`apparmor-selinux`** category. It is
**recommended-OFF**: a MAC layer can constrain a misconfigured tor, so the
operator opts in deliberately.

## Risk

**Low.** It cannot lock the operator out of the box — at worst it confines
*tor*, and `audit` surfaces exactly what state the layer is in. No safety latch
is needed. `revert` is conservative: it **relaxes** enforcement (AppArmor
complain mode / SELinux permissive) rather than ripping the LSM off the host,
which would be far more destructive and could break unrelated profiles.

## Quick start

```sh
# Apply (detect distro, install the LSM packages, enforce tor):
sudo onionarmor apply --module mac-profile-install

# See what would change first (no host changes):
sudo onionarmor apply --module mac-profile-install --dry-run

# Force a family (testing / cross-distro):
sudo onionarmor apply --module mac-profile-install --distro debian

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module mac-profile-install

# Relax enforcement (LSM left installed):
sudo onionarmor revert --module mac-profile-install
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--distro <debian\|rhel>` | autodetect | Force the family instead of reading `/etc/os-release`. Useful for testing or forcing the path on an oddly-labelled host. |
| `--dry-run` | off | Print the plan (detected distro, packages to install, profile/enforce actions). Changes nothing. |
| `-h`, `--help` | — | Module help. |

## What it does, per distro

**Detection.** Reads `/etc/os-release` (`ID` / `ID_LIKE`). Debian/Ubuntu →
`debian` (AppArmor); RHEL/CentOS/Fedora/Rocky/Alma → `rhel` (SELinux). An
unrecognised host fails fast with guidance to pass `--distro`.

**Debian / Ubuntu → AppArmor**

1. Install `apparmor apparmor-profiles apparmor-utils` via `apt-get`.
2. If a tor profile exists at `/etc/apparmor.d/usr.bin.tor`, `aa-enforce` it.
   Absence is honest, not fatal — the packages are installed and a later profile
   drop-in can be enforced.

**RHEL family → SELinux**

1. Install `policycoreutils selinux-policy-targeted` via `dnf`.
2. Write `SELINUX=enforcing` into `/etc/selinux/config` (portable awk rewrite +
   `mv`) so it survives a reboot.
3. `setenforce 1` to flip the running system now. A box booted with SELinux fully
   disabled cannot `setenforce` live — that is surfaced honestly, with the config
   already set to enforce for the next boot.

**Idempotency.** If tor is already enforcing (AppArmor profile in enforce mode,
or SELinux running **and** config = enforcing), the module installs nothing and
prints **"already applied"**.

## Audit meaning

`audit` is read-only. It reports the active LSM, its enforce state, and the tor
profile status:

| Distro | green | yellow | red |
|---|---|---|---|
| Debian | tor profile loaded **+ enforcing** | tor profile loaded but **complain** mode | no tor profile loaded / `aa-status` unavailable |
| RHEL | running **enforcing** + config enforcing | running **permissive** / config permissive | SELinux **disabled** / `sestatus` unavailable / config not enforcing |

Any red exits non-zero; yellow exits 0 (a relaxed-but-present layer is a warning,
not a failure).

## Threat model

A MAC layer is defence-in-depth for a **compromised tor**: even with code
execution inside the tor process, the kernel-enforced policy confines what files
it can touch, what it can exec, and what capabilities it holds — turning a relay
RCE into a far smaller blast radius. It complements, and does not replace,
`kernel-hardening` (sysctl read-restrictions / anti-spoofing) and
`onionarmor apply-lockdown` (`lockdown=integrity`). Leaving the LSM installed but
permissive after `revert` keeps the policy loaded for fast re-enforcement.

## Tests

`tests/bats/` drives apply→audit→revert against a sandbox that never touches the
host: a fake `os-release` (Debian/Ubuntu/RHEL), stub `apt-get`/`dnf` that only
record their `install` calls, stub `aa-enforce`/`aa-complain` that flip a
controllable AppArmor state, a stub `aa-status` rendering real section layout,
and stub `setenforce`/`sestatus` over a controllable SELinux runtime mode with a
sandbox `/etc/selinux/config`. Coverage: distro detection + `--distro` override,
the AppArmor install+enforce path, the SELinux install + `SELINUX=enforcing`
config rewrite + `setenforce 1` path, `--dry-run` (installs/enforces nothing),
idempotency, audit red/green/yellow for each family, revert to complain /
permissive, and the apply→audit→revert→audit round trips. 29 tests.
