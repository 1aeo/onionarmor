# Roles (sysctl postures)

A **role** is a complete kernel-sysctl posture for a class of host — all 25
tracked keys, not just a delta. You declare one role per host and `onionarmor`
keeps that host's sysctls converged to it.

For the common commands, see [Quick start in the README](../README.md#quick-start-5-minutes).

## The three roles

| Role | File | Sysctls | Role-specific exception |
|---|---|---|---|
| `tor-relay` | [`roles/tor-relay.conf`](../roles/tor-relay.conf) | 25 | None — the full baseline. |
| `eval-host` | [`roles/eval-host.conf`](../roles/eval-host.conf) | 25 | `kernel.kexec_load_disabled=0` (nested-KVM workloads). |
| `receiver` | [`roles/receiver.conf`](../roles/receiver.conf) | 25 | Recommends also running `apply-lockdown` after `apply`. |

Each role is the *complete* expected state, so the role file fully describes the
host — there's no base file to diff against.

## Declaring a host's role

`apply` and `rollback` refuse unless `/etc/onionarmor/role.conf` declares the
same role you pass with `--role`. This cross-check stops you from applying, say,
a `tor-relay` posture to a workstation by mistake.

```sh
sudo mkdir -p /etc/onionarmor
echo 'role=tor-relay' | sudo tee /etc/onionarmor/role.conf
```

## Role-file format

Every sysctl entry in a role config carries three machine-readable comments,
then the `key = value`:

```ini
# DOC: Hide kernel pointers in /proc/kallsyms and /proc/modules from non-root,
#      blunting kernel-address exploitation that needs symbol locations.
# REF: CIS Debian 12 §1.5.3; Documentation/admin-guide/sysctl/kernel.rst
# COMPAT: Breaks tools that read /proc/kallsyms (perf-record annotate, some
#         eBPF profilers, kernel-symbol resolvers in crash analyzers).
kernel.kptr_restrict = 2
```

| Tag | Meaning |
|---|---|
| `# DOC:` | Plain-English explanation of what the setting does. |
| `# REF:` | Rationale source (CIS Debian 12, RHEL 9 STIG, or Linux kernel docs). |
| `# COMPAT:` | Known compatibility gotcha, or `none`. |

`onionarmor list --role <r>` prints the keys and target values; the role file
itself is the place to read the *why* behind each one.

## Kernel lockdown is separate

A role never stages `lockdown=integrity` on the kernel cmdline — that needs a
GRUB edit plus a reboot, so it lives behind its own `onionarmor apply-lockdown`
subcommand, which itself never auto-reboots. The `receiver` role recommends
running it after `apply`.

## Reference data (where the 25 keys come from)

The canonical recommendations are derived from two upstream sources in the
read-only [`onionwarden`](https://github.com/1aeo/onionwarden) monitor:

- `onionwarden:lib/checks/kernel_state.sh` — its `REFERENCE` comment block
  defines the 25 security-relevant sysctls onionwarden tracks (CIS Debian 12 /
  RHEL 9 STIG / Linux kernel docs).
- onionwarden's snapshot reports (`snapshots/<host>/SNAPSHOT_RUN_REPORT.md` §3)
  — the live-vs-recommended table per snapshot.

We **pin** the values in this repo's role configs rather than reading
onionwarden's sources at runtime, so an upstream change to the reference list
can't silently change onionarmor's apply behaviour. The split is deliberate: see
[Architecture → Why a separate apply tool](architecture.md#why-a-separate-apply-tool).
