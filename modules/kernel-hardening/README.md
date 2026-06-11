# kernel-hardening

**Write the KSPP (Kernel Self-Protection Project) recommended sysctls to one
managed drop-in and load them — `dmesg`/`kptr`/`bpf`/`perf` restrictions, ASLR,
ptrace scope, kexec lockdown, and the standard network anti-spoofing set.**

This is the only onionarmor module that is **recommended-on by default**: every
setting here is very low risk and none of it changes the relay's externally
observable behaviour. It maps to the onionauditor **`kernel-sysctl`** category.

## Risk

**Very low.** These are read-restriction and anti-spoofing knobs, not behaviour
changes. No safety latch is needed (nothing here can lock you out or drop a tor
listener). `randomize_va_space=2` and the `net.*` defaults match what most
hardened Debian/Ubuntu baselines already ship.

## Quick start

```sh
# Apply (writes the drop-in + sysctl --system):
sudo onionarmor apply --module kernel-hardening

# See what would change first (no host changes):
sudo onionarmor apply --module kernel-hardening --dry-run

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module kernel-hardening

# Undo (removes the drop-in; already-live values persist until reboot):
sudo onionarmor revert --module kernel-hardening
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | off | Print the would-be drop-in + a before→target table per key. Changes nothing. |
| `--verify` / `--no-verify` | verify | Post-apply, confirm each live value matches the drop-in. Verification is authoritative: a noisy `sysctl --system` (an unrelated drop-in failing) does not fail the apply if our keys all match. |
| `-h`, `--help` | — | Module help. |

## Managed sysctls

Written to `/etc/sysctl.d/99-onionarmor-kernel-hardening.conf`. Source:
<https://kspp.github.io/Recommended_Settings>.

| Key | Value | Why |
|---|---|---|
| `kernel.dmesg_restrict` | 1 | Hide the kernel ring buffer (KASLR leaks, addresses) from non-root. |
| `kernel.unprivileged_bpf_disabled` | 1 | No unprivileged `bpf()` — a large kernel attack surface. |
| `kernel.kptr_restrict` | 2 | Never expose kernel pointers via `/proc`/`seq_file`. |
| `kernel.perf_event_paranoid` | 3 | Disallow unprivileged `perf_event_open`. |
| `kernel.randomize_va_space` | 2 | Full ASLR (stack, mmap, brk, VDSO). |
| `kernel.yama.ptrace_scope` | 1 | Restrict `ptrace` to child processes only. |
| `kernel.kexec_load_disabled` | 1 | Block loading a new kernel via kexec (anti-persistence). |
| `net.core.bpf_jit_harden` | 2 | Harden the BPF JIT against spraying for all users. |
| `net.ipv4.tcp_syncookies` | 1 | SYN-flood mitigation. |
| `net.ipv4.conf.all.rp_filter` | 1 | Reverse-path filtering (anti-spoofing). |
| `net.ipv4/ipv6.conf.all.accept_source_route` | 0 | Drop source-routed packets. |
| `net.ipv4/ipv6.conf.all.accept_redirects` | 0 | Ignore ICMP redirects. |
| `net.ipv4.conf.all.send_redirects` | 0 | Never emit ICMP redirects. |
| `net.ipv4.conf.all.log_martians` | 1 | Log impossible-address packets. |

## What it does

1. Renders the KSPP set to a byte-deterministic drop-in (idempotent — a re-apply
   with no change rewrites nothing) and backs up any prior managed drop-in.
2. `sysctl --system` to load it into the running kernel.
3. Verifies every readable key's live value matches the target. A key absent on
   an older kernel (e.g. `kexec_load_disabled`) is a yellow warning, not a red.

`revert` backs up then removes the drop-in and reloads. Already-loaded sysctl
values stay live in the running kernel until a reboot — that is safe (these are
hardening values), and the summary says so rather than pretend a file removal
rolls back the running kernel.

## Threat model

Raises the cost of local privilege escalation and information disclosure: kernel
pointer/dmesg leaks that bypass KASLR, unprivileged BPF/perf attack surface,
ptrace-based credential theft between processes, kexec-based persistence, and
basic network spoofing/redirect attacks. It does **not** replace a LSM
(`mac-profile-install`) or `lockdown=integrity` (`onionarmor apply-lockdown`) —
it complements them.

## Tests

`tests/bats/` drives apply→audit→revert against a stub `sysctl` that emulates
kernel state through a flat key=value file: full-set render, the 16-key count,
idempotency, authoritative verification (a noisy `--system` still passes when
values match; `--no-verify` fails on a nonzero reload), drift detection, and the
apply→audit-green→revert→audit-red round trip.
