# Modules

Beyond the sysctl [roles](roles.md), onionarmor ships **modules** —
self-contained hardening postures you apply with `--module`. Each module is the
same three-verb shape as the rest of the tool: **apply**, **audit**, **revert**.

```sh
onionarmor list-modules                                # discover installed modules
sudo onionarmor apply  --module dns-posture --dry-run  # preview, change nothing
sudo onionarmor apply  --module dns-posture            # apply the posture
onionarmor      audit  --module dns-posture            # green/yellow/red status
sudo onionarmor revert --module dns-posture            # undo it
```

Run `onionarmor apply --module <name> --help` for that module's own flags.

## The module catalog

| Module | What it does | Risk | Needs | Docs |
|---|---|---|---|---|
| `dns-posture` | Local validating DoT resolver (`unbound` + DNSSEC); masks `systemd-resolved`, pins `resolv.conf`. | Medium — replaces the system resolver (clean revert). | `unbound` (auto-installed) | [README](../modules/dns-posture/README.md) |
| `kernel-reserved-ports` | Reserve the relay's loopback tor ports from the kernel ephemeral source-port pool, so an outbound connection can't steal a port tor needs to bind. | Low — one sysctl drop-in, fully reversible. | reads your torrc (`--auto`) | [README](../modules/kernel-reserved-ports/README.md) |
| `bgp-hardening` | Bind FRR `bgpd` to a specific peer-facing IP (not `0.0.0.0`); opt-in `tcp/179` firewall, RPKI, GTSM. | Medium — restarts `bgpd` (graceful, keeps the FIB). | FRR (`/etc/frr`) | [README](../modules/bgp-hardening/README.md) |
| `ssh-hardening` | Mozilla "modern" OpenSSH drop-in (no root/password login, modern KEX/ciphers/MACs), weak host-key cleanup. **5-min auto-restore latch.** | Medium-high — highest lockout risk; latch + `AllowUsers` mitigate. **Default-off.** | `at`, `sshd` | [README](../modules/ssh-hardening/README.md) |
| `account-hygiene` | Lock + de-sudo leftover cloud-init users, enforce a sudo allowlist, refuse shared UID-0, flag blanket `NOPASSWD`. **5-min latch.** | Medium — could remove your own sudo; latch + confirm mitigate. **Default-off.** | `at`, `getent`/`gpasswd` | [README](../modules/account-hygiene/README.md) |
| `tor-config-baseline` | Baseline torrc directives across instances (stats off, signing-key lifetime, loopback Metrics/Control, cookie auth) without touching operator-domain config. | Medium — reloads tor. **Default-off.** | `/etc/tor/instances` | [README](../modules/tor-config-baseline/README.md) |
| `kernel-hardening` | KSPP-recommended sysctl drop-in (dmesg/kptr/bpf/ptrace restrictions, rp_filter, source-route/redirect off). | Very low — runtime-reversible. **Default-on.** | none | [README](../modules/kernel-hardening/README.md) |
| `package-minimization` | Remove the build toolchain + debug tools (gcc/make/gdb/strace/...) from production relays; skipped on build/CI roles. | Low — reinstallable on demand. **Default-on.** | `apt`/`dpkg` | [README](../modules/package-minimization/README.md) |
| `mac-profile-install` | Install + enforce a MAC LSM (AppArmor on Debian/Ubuntu, SELinux on RHEL) and enforce the tor profile. | Low — failure mode is permissive, not broken. **Default-on.** | `apparmor`/`selinux` | [README](../modules/mac-profile-install/README.md) |

Each module's README has its flags, customization examples, threat model, and
the exact files it manages. **Start with the dry-run** — every module prints its
full plan and changes nothing until you drop `--dry-run`.

## Auditor-driven remediation (`remediate`)

[`onionauditor`](https://github.com/) scores a host across categories
(`ssh-hardness`, `firewall`, `accounts`, `kernel-sysctl`, …). `onionarmor
remediate` reads that scan and maps each failing finding to the module that fixes
it, then applies them in a dependency-safe order — `kernel-hardening` first,
`ssh-hardening` **last** (so you can confirm everything else worked before risking
the SSH config), with `firewall-default-deny` before any service-inventory work.

```sh
onionauditor scan --output json > /tmp/score.json
onionarmor remediate --from-audit /tmp/score.json            # dry-run plan
onionarmor remediate --from-audit /tmp/score.json --apply    # apply in order
onionauditor scan                                            # re-score to confirm uplift
```

The mapping is category → module (the auditor finding's `category` field): e.g.
`ssh-hardness → ssh-hardening`, `firewall → firewall-default-deny`, `accounts →
account-hygiene`, `kernel-sysctl → kernel-hardening`, `tor-config →
tor-config-baseline`, `package-hygiene → package-minimization`, `time-ntp →
chrony-pinning`, `tor-dns-resolver → dns-posture`, `systemd-tor-units →
systemd-hardening`. Categories with no module (e.g. `service-inventory`) are
listed as unmapped. Each apply cites the auditor finding ids it addresses.

## How a module works

A module lives under `modules/<name>/` and provides:

```text
modules/<name>/
  apply.sh       # apply the posture
  audit.sh       # report green/yellow/red status (read-only)
  revert.sh      # undo it
  lib.sh         # shared helpers (every path + external command env-overridable)
  README.md      # flags, examples, threat model, managed files
  tests/bats/    # offline suite — external commands stubbed
```

The registry is a **directory scan**, not a manifest: a directory is a module
iff it has those three action scripts. `list-modules` reads each module's
one-line description straight from the `# MODULE:` header in `apply.sh`, so there
is no manifest file to drift from the real scripts. See
[`lib/module.sh`](../lib/module.sh) for the dispatch convention.

`apply --module <name>` and the role-based `apply --role <name>` are distinct
paths — `--module` routes to the module, everything else is unchanged. Module
`apply`/`audit`/`revert` all write to the same audit log
(`/var/log/onionarmor/audit.log`) as the role-based commands.

## Reading `audit` output

Every module's `audit` reports each check as **green / yellow / red** and exits
non-zero if **anything is red** — so it drops cleanly into a monitoring cron or
CI gate.

| Colour | Meaning |
|---|---|
| 🟢 green | check passed / posture in place. |
| 🟡 yellow | advisory — not applied, or a non-fatal gap (exit stays `0`). |
| 🔴 red | the posture is broken or drifted (exit non-zero). |

What's green vs yellow vs red is module-specific; each module README has the
exact table. A control that is *opt-in* (e.g. `bgp-hardening`'s firewall) audits
**green when you never enabled it** — absence of an opt-in extra is not a
failure.

## Writing a new module

To add one, create `modules/<name>/` with the four files above and an offline
bats suite. The roadmap (Phase 2) generalizes the same `apply`/`audit`/`revert`
convention to apparmor, systemd-sandbox, and nftables-egress. Conventions to
follow:

- `apply.sh` starts with a `# MODULE: <one-line description>` header (this is
  what `list-modules` prints).
- Make every path and external command overridable via environment variables in
  `lib.sh`, so the bats suite can drive the whole module against a sandbox with
  stub binaries.
- `apply` must be idempotent and support `--dry-run`; `audit` must be read-only;
  `revert` must back up before it removes anything.
- Back every behaviour with an offline bats suite (stub all externals).
