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

Phase 1 — sysctl tunings (25 keys, three role profiles) **plus a modular hardening system**. Kernel-lockdown via GRUB cmdline is documented and stageable but never applied by `apply` (separate `apply-lockdown` subcommand).

The first modules are [`dns-posture`](modules/dns-posture/README.md) — the 1aeo fleet's DoT + DNSSEC + `unbound` posture (systemd-resolved masked); [`kernel-reserved-ports`](modules/kernel-reserved-ports/README.md) — reserving a relay's loopback service ports from the kernel ephemeral source-port pool so an outbound connection can't steal a port tor needs to bind; and [`bgp-hardening`](modules/bgp-hardening/README.md) — FRR `bgpd` listener-bind + `tcp/179` firewalling + RPKI origin validation for hosts that run BGP. The module convention generalizes to the Phase 2 roadmap (apparmor, systemd-sandbox, nftables-egress).

## Install

### One-liner (recommended)

```sh
curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh | sudo bash
```

> **Supply-chain note.** This pipes branch-tip (`main`) code straight into
> `sudo bash`, which is convenient but non-reproducible. To pin and review a
> fixed revision before running it as root:
>
> ```sh
> curl -sSLO https://raw.githubusercontent.com/1aeo/onionarmor/<tag-or-sha>/install.sh
> less install.sh                                  # review before running
> sudo ONIONARMOR_REPO_REF=<tag-or-sha> bash install.sh
> ```

The installer is conservative and idempotent (safe to re-run). It:

- refuses to run as non-root, on a non-Debian/Ubuntu distro, on too-old a bash, or on a kernel too old for the role sysctl keys (≥ 5.2);
- `apt-get install`s any missing prerequisites;
- clones (or updates) the repo into `/opt/onionarmor` and symlinks `onionarmor` onto `PATH` at `/usr/local/sbin/onionarmor`;
- **never** applies a role posture on its own and **never** stages GRUB kernel lockdown — both stay deliberate, opt-in operator steps (see [Safety rails](#safety-rails)). It only prints the next steps.

To also apply a role in the same run (declares the host role + runs `apply --first-run`), set `ONIONARMOR_INSTALL_ROLE`:

```sh
curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh \
  | sudo ONIONARMOR_INSTALL_ROLE=tor-relay bash
```

Common knobs: `INSTALL_PREFIX` (default `/opt/onionarmor`), `SYMLINK_PATH` (default `/usr/local/sbin/onionarmor`), `ONIONARMOR_REPO_REF` (default `main`; accepts a branch, tag, or commit SHA), `ONIONARMOR_INSTALL_FORCE` (default `0`; set to `1` to discard uncommitted local changes in `$INSTALL_PREFIX` when updating an existing checkout). See the header of [`install.sh`](install.sh) for the full list.

### Manual

`onionarmor` is a self-contained Bash CLI. Clone and put `bin/` on `PATH`:

```sh
git clone https://github.com/1aeo/onionarmor.git /opt/onionarmor
sudo ln -s /opt/onionarmor/bin/onionarmor /usr/local/sbin/onionarmor
```

> **Pin and review before you run.** `onionarmor` mutates host state as root, so
> don't track branch tip blindly. Check out a reviewed tag or commit SHA and
> inspect the diff before putting `bin/` on `PATH`:
>
> ```sh
> git -C /opt/onionarmor checkout <tag-or-sha>   # pin to a reviewed revision
> ```

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
| `list-modules` | List installed hardening modules + descriptions. |
| `apply --module <m>` / `audit --module <m>` / `revert --module <m>` | Apply / status / undo a [module](#modules). `audit --module` exits non-zero if any check is red. |
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

## Modules

Beyond the sysctl roles, onionarmor ships **modules** — self-contained hardening postures applied with `--module`:

```sh
onionarmor list-modules                          # discover installed modules
sudo onionarmor apply  --module dns-posture      # apply a posture
onionarmor      audit  --module dns-posture      # green/yellow/red status (non-zero exit if red)
sudo onionarmor revert --module dns-posture      # undo it
sudo onionarmor apply  --module dns-posture --dry-run   # preview, change nothing
```

A module lives under `modules/<name>/` and provides `apply.sh`, `audit.sh`, `revert.sh`, a `README.md`, and `tests/bats/`. The registry is a **directory scan** — a directory is a module iff it has those three action scripts; `list-modules` reads each module's one-line description from the `# MODULE:` header in `apply.sh`. (No manifest file to drift from the real scripts.) See [`lib/module.sh`](lib/module.sh) for the convention.

| Module | What it does | Docs |
|---|---|---|
| [`dns-posture`](modules/dns-posture/README.md) | Local validating DoT resolver (`unbound` + DNSSEC), `systemd-resolved` masked, `resolv.conf` pinned. Every default (upstreams, DNSSEC, listener, threads, masking) is overridable. | [README](modules/dns-posture/README.md) |
| [`kernel-reserved-ports`](modules/kernel-reserved-ports/README.md) | Reserve the relay's loopback service ports (`MetricsPort`/`ControlPort`/…) from the kernel ephemeral source-port pool via `net.ipv4.ip_local_reserved_ports`, so an outbound connection can't steal a port tor needs to bind. Auto-detects ports from torrc (`--auto`). | [README](modules/kernel-reserved-ports/README.md) |
| [`bgp-hardening`](modules/bgp-hardening/README.md) | For hosts running FRR BGP: bind `bgpd` to a specific peer-facing IP (not `0.0.0.0`), restrict `tcp/179` to known peer(s) at the firewall, and RPKI-validate inbound origins (drop INVALID, keep the full feed). Optional GTSM. Auto-detects bind IP + peers from `/etc/frr`. | [README](modules/bgp-hardening/README.md) |

Module `apply`/`audit`/`revert` all write to the same tamper-evident audit log as the role-based commands. `apply --module <name>` and the role-based `apply --role <name>` are distinct paths — `--module` routes to the module, everything else is unchanged.

## Safety rails

1. **No `apply` without `--role` set.** The CLI refuses if you omit it.
2. **Host role.conf cross-check.** `apply` and `rollback` refuse unless `/etc/onionarmor/role.conf` contains `role=<r>` matching the `--role` flag. This prevents applying a `tor-relay` posture to a workstation by mistake.
3. **Backup before every write.** The prior `/etc/sysctl.d/99-onionarmor-<r>.conf` is copied to `…conf.bak.<UTC-ts>` before the new one is written. Any historical backup can be restored manually; `rollback` restores the most recent.
4. **First-run confirmation.** `apply --first-run` requires interactive `yes` before writing. Subsequent applies are direct.
5. **Convergent.** Re-running `apply` with no role-config change preserves the same sysctl posture and writes zero `apply.change` audit entries. (The managed file is rewritten with a fresh `Written:` header timestamp, so the bytes are not guaranteed identical — the *posture* is.)
6. **Reboot-required items gated.** Kernel lockdown is never applied by `apply`; only `apply-lockdown` stages it. `apply-lockdown` itself never auto-reboots.
7. **Append-only audit log.** Every apply, backup, and rollback is appended to `/var/log/onionarmor/audit.log` with timestamp, operator, and details. It is a plain operator trail, not cryptographically tamper-evident (no hash chaining or signing) — see [SECURITY.md](SECURITY.md).

## Reference data

The canonical recommendations are derived from two upstream sources in the onionwarden repository:

- `onionwarden:lib/checks/kernel_state.sh` — the `REFERENCE` comment block defines the 25 security-relevant sysctls onionwarden tracks (CIS Debian 12 / RHEL 9 STIG / Linux kernel docs).
- onionwarden's snapshot reports (`snapshots/<host>/SNAPSHOT_RUN_REPORT.md` §3) — the live-vs-recommended table per snapshot.

We **pin** the values in this repo's role configs rather than reading onionwarden's sources at runtime, so an upstream change to the reference list doesn't silently change onionarmor's apply behaviour.

## Tests

```sh
bats tests/
```

The core suite spins up a sandbox tree, swaps in a `fake-sysctl` fixture, and runs every CLI surface (`list`, `diff`, `apply --dry-run`, `apply`, `apply` twice (idempotency), `rollback`, `audit`, `apply-lockdown`, plus `list-modules` + module dispatch) plus a full round-trip.

`tests/install.bats` is a separate, self-contained regression suite for the curl-friendly [`install.sh`](install.sh): it stubs `apt-get`/`git`/`dpkg-query` so it stays fully offline, then exercises the OS / root / bash / kernel gates, the apt-skip and apt-failure paths, idempotency + partial prior-install state, the symlink + `/opt/onionarmor` layout, and the safety rails (never writes `role.conf` by default, never stages GRUB lockdown).

Each module also has its own offline suite (external commands stubbed):

```sh
bats tests/                          # core CLI + module dispatch
bats modules/*/tests/bats/           # per-module suites (e.g. dns-posture)
```

The `dns-posture` suite includes a regression for the duplicate-anchor bug: `audit` must return red on two `auto-trust-anchor-file` lines, and `apply` must produce a config `unbound-checkconf` accepts.

CI runs the core, install, and module suites on `ubuntu-latest` and `ubuntu-22.04` via GitHub Actions, plus `shellcheck` over `bin/`, `lib/`, `install.sh`, and `modules/*/*.sh`; see [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Repo layout

```
install.sh                     # curl|sudo bash installer (clone + symlink, idempotent)
bin/onionarmor                 # CLI entrypoint
lib/common.sh                  # paths, logging, audit log, confirmation prompt
lib/role.sh                    # role config parsing + host role.conf validation
lib/sysctl_ops.sh              # current/target read, managed-file write, backups
lib/module.sh                  # module registry + apply/audit/revert dispatch
roles/tor-relay.conf           # 25-key tor-relay posture
roles/eval-host.conf           # 25-key eval-host posture (kexec exception)
roles/receiver.conf            # 25-key receiver posture
modules/dns-posture/           # DoT + DNSSEC + unbound module
  apply.sh audit.sh revert.sh  #   the three action scripts
  lib.sh                       #   shared helpers (env-overridable cmds/paths)
  README.md                    #   flags, examples, threat model
  tests/bats/                  #   offline module suite (stubbed externals)
modules/kernel-reserved-ports/ # reserve loopback tor ports from ephemeral pool
  apply.sh audit.sh revert.sh  #   the three action scripts
  lib.sh                       #   torrc auto-detect + range compaction helpers
  README.md                    #   flags, examples, threat model
  tests/bats/                  #   offline module suite (stubbed sysctl)
modules/bgp-hardening/         # FRR bgpd listener-bind + tcp/179 firewall + RPKI
  apply.sh audit.sh revert.sh  #   the three action scripts
  lib.sh                       #   FRR auto-detect + nft/RPKI/version helpers
  README.md                    #   flags, examples, threat model
  tests/bats/                  #   offline module suite (stubbed vtysh/nft/ss)
tests/*.bats                   # core bats suite (CLI surfaces, incl. modules.bats dispatch)
tests/install.bats             # bats regression suite for install.sh
tests/test_helper.bash         # sandbox setup
tests/fixtures/fake-sysctl     # stub sysctl driver for tests
tests/fixtures/debian13-relay-baseline.state  # synthetic Debian-13 starting posture
.github/workflows/tests.yml    # CI: bats (core + modules) + shellcheck
```

## Why a separate apply tool?

The original onionwarden design note (snapshot §5 "Actionable items") says explicitly:

> Onionwarden surfaces; operator applies if/when desired. Each item below is a state of the host that an operator may want to change. None are auto-applied; this is a monitoring tool.

That split is deliberate — a monitor that also mutates blurs the trust model and the blast radius. `onionarmor` is the explicitly opt-in mutator: separate binary, separate review, separate audit log.

## License

MIT — see [LICENSE](LICENSE).
