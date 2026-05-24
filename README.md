# onionarmor

**Apply hardening recommendations to Ubuntu/Debian relay fleets — idempotently, with backup and rollback.**

`onionarmor` is the apply-side counterpart to two read-only sister tools:

| Tool | Role | Touches host? |
|---|---|---|
| [`onionwarden`](https://github.com/1aeo/onionwarden) | Monitor / detect drift in kernel + network posture | **No** (read-only) |
| [`onionleak`](https://github.com/1aeo/onionleak) | Audit Tor-relay metadata for unintended disclosures | **No** (read-only) |
| **`onionarmor`** (this repo) | **Apply** the hardening recommendations onionwarden surfaces | **Yes** — sysctls + GRUB cmdline, with safety rails |

The sharp scope boundary is intentional: onionwarden tells you what's drifting from CIS / RHEL-STIG / kernel-doc recommendations; onionarmor closes the gap. Recommendations are sourced from onionwarden's reference data (see [Reference data](#reference-data) below) and pinned to this repo's role configs, so any change upstream doesn't silently change apply behaviour.

## Status

Phase 1 — sysctl tunings only (25 keys, three role profiles). Kernel-lockdown via GRUB cmdline is documented and stageable but never applied by `apply` (separate `apply-lockdown` subcommand).

## Install

`onionarmor` is a self-contained Bash CLI. Clone and put `bin/` on `PATH`:

```sh
git clone https://github.com/1aeo/onionarmor.git /opt/onionarmor
sudo ln -s /opt/onionarmor/bin/onionarmor /usr/local/sbin/onionarmor
```

No dependencies beyond a POSIX shell, `awk`, `sysctl`, and (for the optional CI lint) `shellcheck`.

## Quickstart — tor-relay

```sh
# 1. Declare the host's role (one-time, manual step).
sudo mkdir -p /etc/onionarmor
echo 'role=tor-relay' | sudo tee /etc/onionarmor/role.conf

# 2. Inspect the target posture.
onionarmor list --role tor-relay

# 3. See what would change vs the live kernel.
onionarmor diff --role tor-relay

# 4. Dry-run an apply (no host change).
sudo onionarmor apply --role tor-relay --dry-run

# 5. First-time apply (interactive confirmation).
sudo onionarmor apply --role tor-relay --first-run

# 6. (Optional, separate.) Stage kernel lockdown for next reboot.
sudo onionarmor apply-lockdown
# Reboots are never automatic — `onionarmor` only edits /etc/default/grub
# and runs update-grub; you reboot when convenient.

# 7. If anything misbehaves, roll back to the previous managed file.
sudo onionarmor rollback --role tor-relay

# 8. Review every change ever made on this host.
sudo onionarmor audit
```

Subsequent applies (after the first) don't need `--first-run`:

```sh
sudo onionarmor apply --role tor-relay
```

## Commands

| Command | What it does |
|---|---|
| `list --role <r>` | Print the role's 25 target sysctls + values (read-only). |
| `diff --role <r>` | Show current host values vs target; mark each `ok` / `DRIFT` / `missing`. |
| `apply --role <r>` `[--dry-run]` `[--first-run]` | Apply target sysctls. Backs up the prior managed file, writes `/etc/sysctl.d/99-onionarmor-<r>.conf`, calls `sysctl --system`, audits every change. |
| `rollback --role <r>` | Restore the most recent backup of the managed file and reload sysctls. |
| `audit` | Print the full audit log (every apply / rollback ever). |
| `apply-lockdown` `[--no-reboot]` | Stage `lockdown=integrity` in GRUB cmdline. Prints a REBOOT REQUIRED warning by default; `--no-reboot` suppresses the warning but still requires a reboot to activate. Never auto-reboots. |
| `help` | Show usage. |

## Roles

Each role is a complete posture (all 25 sysctls), not just a delta:

| Role | File | Sysctls | Role-specific exceptions |
|---|---|---|---|
| `tor-relay` | [`roles/tor-relay.conf`](roles/tor-relay.conf) | 25 | None — full baseline. |
| `eval-host` | [`roles/eval-host.conf`](roles/eval-host.conf) | 25 | `kernel.kexec_load_disabled=0` (nested KVM workloads). |
| `receiver` | [`roles/receiver.conf`](roles/receiver.conf) | 25 | Recommend also running `apply-lockdown` after `apply`. |

Each sysctl in a role config carries:

- `# DOC:` — plain-English explanation of what the setting does.
- `# REF:` — rationale source (CIS Debian 12, RHEL 9 STIG, Linux kernel docs).
- `# COMPAT:` — known compatibility gotchas ("breaks perf-record annotate", etc.).

## Safety rails

1. **No `apply` without `--role` set.** The CLI refuses if you omit it.
2. **Host role.conf cross-check.** `apply` and `rollback` refuse unless `/etc/onionarmor/role.conf` contains `role=<r>` matching the `--role` flag. This prevents applying a `tor-relay` posture to a workstation by mistake.
3. **Backup before every write.** The prior `/etc/sysctl.d/99-onionarmor-<r>.conf` is copied to `…conf.bak.<UTC-ts>` before the new one is written. Any historical backup can be restored manually; `rollback` restores the most recent.
4. **First-run confirmation.** `apply --first-run` requires interactive `yes` before writing. Subsequent applies are direct.
5. **Idempotent.** Re-running `apply` with no role-config change produces the same managed file and zero `apply.change` audit entries.
6. **Reboot-required items gated.** Kernel lockdown is never applied by `apply`; only `apply-lockdown` stages it. `apply-lockdown` itself never auto-reboots.
7. **Tamper-evident audit log.** Every apply, backup, and rollback is appended to `/var/log/onionarmor/audit.log` with timestamp, operator, and details.

## Reference data

The canonical recommendations are derived from two upstream sources in the onionwarden repository:

- `onionwarden:lib/checks/kernel_state.sh` — the `REFERENCE` comment block defines the 25 security-relevant sysctls onionwarden tracks (CIS Debian 12 / RHEL 9 STIG / Linux kernel docs).
- onionwarden's snapshot reports (`snapshots/<host>/SNAPSHOT_RUN_REPORT.md` §3) — the live-vs-recommended table per snapshot.

We **pin** the values in this repo's role configs rather than reading onionwarden's sources at runtime, so an upstream change to the reference list doesn't silently change onionarmor's apply behaviour.

## Tests

```sh
bats tests/
```

The bats suite spins up a sandbox tree, swaps in a `fake-sysctl` fixture, and runs every CLI surface (`list`, `diff`, `apply --dry-run`, `apply`, `apply` twice (idempotency), `rollback`, `audit`, `apply-lockdown`) plus a full round-trip (`apply` → diff clean → mutate live state → `apply` again → still clean → `rollback` → original).

CI runs the suite on `ubuntu-latest` and `ubuntu-22.04` via GitHub Actions; see [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Repo layout

```
bin/onionarmor                 # CLI entrypoint
lib/common.sh                  # paths, logging, audit log, confirmation prompt
lib/role.sh                    # role config parsing + host role.conf validation
lib/sysctl_ops.sh              # current/target read, managed-file write, backups
roles/tor-relay.conf           # 25-key tor-relay posture
roles/eval-host.conf           # 25-key eval-host posture (kexec exception)
roles/receiver.conf            # 25-key receiver posture
tests/*.bats                   # bats test suite
tests/test_helper.bash         # sandbox setup
tests/fixtures/fake-sysctl     # stub sysctl driver for tests
tests/fixtures/debian13-relay-baseline.state  # synthetic Debian-13 starting posture
.github/workflows/tests.yml    # CI: bats + shellcheck
```

## Why a separate apply tool?

The original onionwarden design note (snapshot §5 "Actionable items") says explicitly:

> Onionwarden surfaces; operator applies if/when desired. Each item below is a state of the host that an operator may want to change. None are auto-applied; this is a monitoring tool.

That split is deliberate — a monitor that also mutates blurs the trust model and the blast radius. `onionarmor` is the explicitly opt-in mutator: separate binary, separate review, separate audit log.

## License

MIT — see [LICENSE](LICENSE).
