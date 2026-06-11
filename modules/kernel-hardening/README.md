# kernel-hardening

Write and load a **KSPP-recommended** (Kernel Self-Protection Project) sysctl
hardening drop-in. This is a **default-on, very-low-risk** module: pure security
uplift, applied at runtime and fully reversible without a reboot. It is
**recommended on by default** for every relay host — there is no confirmation
gate.

Source: <https://kspp.github.io/Recommended_Settings>

## What it does

Renders a managed drop-in at `/etc/sysctl.d/99-onionarmor-kernel-hardening.conf`
and loads it with `sysctl --system`. The drop-in sets these 15 keys:

| Key | Value | Effect |
| --- | --- | --- |
| `kernel.dmesg_restrict` | `1` | Only root can read the kernel ring buffer. |
| `kernel.unprivileged_bpf_disabled` | `1` | Block unprivileged BPF. |
| `kernel.kptr_restrict` | `2` | Hide kernel pointers from `/proc`. |
| `kernel.perf_event_paranoid` | `3` | Restrict `perf_event_open`. |
| `net.ipv4.tcp_syncookies` | `1` | SYN-flood protection. |
| `kernel.randomize_va_space` | `2` | Full ASLR. |
| `kernel.yama.ptrace_scope` | `1` | Restrict `ptrace` to child processes. |
| `kernel.kexec_load_disabled` | `1` | Disable loading a new kernel via kexec. |
| `net.core.bpf_jit_harden` | `2` | Harden the BPF JIT against spraying. |
| `net.ipv4.conf.all.rp_filter` | `1` | Strict reverse-path filtering. |
| `net.ipv4.conf.all.accept_source_route` | `0` | Drop source-routed IPv4 packets. |
| `net.ipv6.conf.all.accept_source_route` | `0` | Drop source-routed IPv6 packets. |
| `net.ipv4.conf.all.accept_redirects` | `0` | Ignore ICMP redirects. |
| `net.ipv4.conf.all.send_redirects` | `0` | Never send ICMP redirects. |
| `net.ipv4.conf.all.log_martians` | `1` | Log impossible-address packets. |

## Risk

**Very low.** Every key is a runtime sysctl with a conservative hardened value
recommended upstream by KSPP. There is no kernel rebuild, no boot-time change,
and no service restart. The change takes effect immediately and is undone by
`revert` (or a reboot). Recommended on by default.

## Usage

```sh
onionarmor apply  --module kernel-hardening            # write + load the drop-in
onionarmor apply  --module kernel-hardening --dry-run  # preview, change nothing
onionarmor audit  --module kernel-hardening            # green/yellow/red status
onionarmor revert --module kernel-hardening            # remove the drop-in
```

### Flags (apply)

- `--dry-run` — print the rendered drop-in plus a before(live)/after(desired)
  table of every key. Writes nothing; never calls `sysctl --system`.
- `--verify` / `--no-verify` — post-apply, read each key back with `sysctl -n`
  and compare to the KSPP target (default: verify). With verification on, a
  noisy nonzero `sysctl --system` exit does **not** fail the apply as long as the
  live values all match (another drop-in on the host may be the cause of the
  noise). With `--no-verify`, the reload exit code is the only success signal: a
  nonzero reload exits `2`.
- `-h`, `--help` — usage.

## Lifecycle

- **apply** is idempotent: if the drop-in already byte-matches the rendered
  content and (when verifying) the live values already match, it prints
  `already current` and exits `0` without reloading. Any pre-existing drop-in is
  backed up to `/var/lib/onionarmor/kernel-hardening/backup.conf` first.
- **audit** is read-only. A missing drop-in is a single yellow "not applied"
  check; otherwise one check per key (green on match, red on drift, yellow if the
  key is unreadable on this kernel). Exits non-zero on any red.
- **revert** removes the drop-in (restoring the backup if one exists) and
  reloads. The KSPP keys keep their hardened runtime values until a reboot — this
  module does not forcibly un-harden the live kernel.
- `ONIONARMOR_SKIP_RELOAD=yes` leaves the live kernel untouched in both apply and
  revert.

## Environment overrides

Every command and path is env-overridable (the bats suite relies on this):

| Variable | Default |
| --- | --- |
| `ONIONARMOR_SYSCTL_CMD` | `sysctl` |
| `ONIONARMOR_SYSCTL_DIR` | `/etc/sysctl.d` |
| `ONIONARMOR_KH_DROPIN_NAME` | `99-onionarmor-kernel-hardening.conf` |
| `ONIONARMOR_KH_STATE_DIR` | `/var/lib/onionarmor/kernel-hardening` |
| `ONIONARMOR_SKIP_RELOAD` | unset (set `yes` to skip the live reload) |
