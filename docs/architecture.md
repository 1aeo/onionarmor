# Architecture & internals

Background for operators who want to understand *why* onionarmor is shaped the
way it is, and contributors working on the code. For day-to-day use, the
[README](../README.md) is enough.

## The three-tool split

`onionarmor` is the apply-side of a deliberately separated trio:

| Tool | Role | Touches host? |
|---|---|---|
| [`onionwarden`](https://github.com/1aeo/onionwarden) | Monitor / detect drift in kernel + network posture | **No** (read-only) |
| [`onionleak`](https://github.com/1aeo/onionleak) | Audit Tor-relay metadata for unintended disclosures | **No** (read-only) |
| **`onionarmor`** (this repo) | **Apply** the hardening onionwarden surfaces | **Yes** — sysctls + GRUB cmdline, with safety rails |

onionwarden tells you what's drifting from CIS / RHEL-STIG / kernel-doc
recommendations; onionarmor closes the gap.

## Why a separate apply tool?

The original onionwarden design note is explicit:

> Onionwarden surfaces; operator applies if/when desired. Each item below is a
> state of the host that an operator may want to change. None are auto-applied;
> this is a monitoring tool.

That split is deliberate — a monitor that also mutates blurs the trust model and
the blast radius. `onionarmor` is the explicitly opt-in mutator: separate
binary, separate review, separate audit log.

## Status & roadmap

Phase 1 — sysctl tunings (25 keys, three [role](roles.md) profiles) **plus a
modular hardening system**. Kernel-lockdown via GRUB cmdline is documented and
stageable but never applied by `apply` (separate `apply-lockdown` subcommand).

The first [modules](modules.md) are `dns-posture`, `kernel-reserved-ports`, and
`bgp-hardening`. The module convention generalizes to the Phase 2 roadmap:
apparmor, systemd-sandbox, nftables-egress.

## Safety rails (full list)

1. **No `apply` without `--role` set.** The CLI refuses if you omit it.
2. **Host `role.conf` cross-check.** `apply` and `rollback` refuse unless
   `/etc/onionarmor/role.conf` contains `role=<r>` matching the `--role` flag —
   so you can't apply a `tor-relay` posture to a workstation by mistake.
3. **Backup before every write.** The prior
   `/etc/sysctl.d/99-onionarmor-<r>.conf` is copied to `…conf.bak.<UTC-ts>`
   before the new one is written. `rollback` restores the most recent; any
   historical backup can be restored manually.
4. **First-run confirmation.** `apply --first-run` requires an interactive `yes`
   before writing. Subsequent applies are direct.
5. **Convergent.** Re-running `apply` with no role-config change preserves the
   same posture and writes zero `apply.change` audit entries. (The managed file
   gets a fresh `Written:` header timestamp, so the bytes aren't guaranteed
   identical — the *posture* is.)
6. **Reboot-required items gated.** Kernel lockdown is never applied by `apply`;
   only `apply-lockdown` stages it, and it never auto-reboots.
7. **Append-only audit log.** Every apply, backup, and rollback is appended to
   `/var/log/onionarmor/audit.log` with timestamp, operator, and details. It is
   a plain operator trail, **not** cryptographically tamper-evident (no hash
   chaining or signing) — see [SECURITY.md](../SECURITY.md).

## Repo layout

```text
install.sh                     # curl|sudo bash installer (clone + symlink, idempotent)
bin/onionarmor                 # CLI entrypoint
bin/check-own-roa-status       # operator helper: report RPKI validity of YOUR prefixes
lib/common.sh                  # paths, logging, audit log, confirmation prompt
lib/role.sh                    # role config parsing + host role.conf validation
lib/sysctl_ops.sh              # current/target read, managed-file write, backups
lib/module.sh                  # module registry + apply/audit/revert dispatch
roles/*.conf                   # the three 25-key sysctl postures
modules/<name>/                # apply.sh audit.sh revert.sh lib.sh README.md tests/bats/
tests/*.bats                   # core bats suite (CLI surfaces, incl. module dispatch)
tests/install.bats             # bats regression suite for install.sh
tests/fixtures/                # fake-sysctl driver + synthetic baseline state
.github/workflows/tests.yml    # CI: bats (core + modules) + shellcheck
```

## Tests

```sh
bats tests/                          # core CLI + module dispatch
bats modules/*/tests/bats/           # per-module suites (e.g. dns-posture)
```

The core suite spins up a sandbox tree, swaps in a `fake-sysctl` fixture, and
runs every CLI surface (`list`, `diff`, `apply --dry-run`, `apply`, `apply`
twice for idempotency, `rollback`, `audit`, `apply-lockdown`, plus `list-modules`
+ module dispatch) plus a full round-trip.

`tests/install.bats` is a separate, fully offline regression suite for
[`install.sh`](../install.sh): it stubs `apt-get` / `git` / `dpkg-query`, then
exercises the OS / root / bash / kernel gates, the apt-skip and apt-failure
paths, idempotency + partial prior-install state, the symlink + `/opt/onionarmor`
layout, and the safety rails (never writes `role.conf` by default, never stages
GRUB lockdown).

Each module ships its own offline suite (all external commands stubbed). CI runs
the core, install, and module suites on `ubuntu-latest` and `ubuntu-22.04` via
GitHub Actions, plus `shellcheck` over `bin/`, `lib/`, `install.sh`, and
`modules/*/*.sh`; see [`.github/workflows/tests.yml`](../.github/workflows/tests.yml).
