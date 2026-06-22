# conntrack-tuning

Size the kernel connection tracker (`nf_conntrack`) for exit-relay load so the
conntrack table cannot pin full and start dropping packets host-wide.

## Why this module exists

A relay running [tailscale](https://tailscale.com/) (which installs nftables
`ct state` rules) loads the kernel's `nf_conntrack` connection tracker with the
kernel-default ceiling `nf_conntrack_max = 262144`. Under typical exit-relay
load — 500k+ established TCP connections — that fixed-size table pins full and
the kernel begins dropping **new** packets host-wide. The symptom signature
observed on the affected host (`relay-guard` in this codebase):

- DNS lookups time out — including localhost UDP queries over `lo` (e.g. a local
  `dig`), which makes it look like the resolver is broken when it is not.
- ssh handshakes fail (~66% packet loss to/from the box).
- tor circuit-build failures spike.
- `dmesg` shows `nf_conntrack: table full, dropping packet`.
- `nf_conntrack_count` sits pinned at `nf_conntrack_max`.

The tracker is loaded **only** on hosts that run a stateful-firewall stack such
as tailscale. Fleet hosts without it never load `nf_conntrack`, so they are not
exposed today — but the fix belongs in place pre-emptively in case tailscale
rolls to additional hosts. This module is therefore a graceful **no-op audit
(n/a)** where the tracker is not loaded, while `apply` still writes the
persistence drop-ins so the correct sizing is ready the moment the tracker loads.

## What it changes

Two persistence drop-ins:

| File | Contents |
| --- | --- |
| `/etc/sysctl.d/99-conntrack-tuning.conf` | `net.netfilter.nf_conntrack_max = 2097152`<br>`net.netfilter.nf_conntrack_tcp_timeout_established = 86400` |
| `/etc/modprobe.d/nf_conntrack.conf` | `options nf_conntrack hashsize=524288` |

- **`nf_conntrack_max = 2097152`** — an 8× larger ceiling (vs the 262144
  default), comfortably above the established-connection working set of a busy
  exit relay.
- **`nf_conntrack_tcp_timeout_established = 86400`** — 1 day, down from the
  kernel's wasteful (and dangerous) 5-day default. Stale flows otherwise hold
  table slots for days, inflating the working set for no benefit.
- **`hashsize = 524288`** — roughly `max / 4`, keeping the average hash-bucket
  chain short. `hashsize` takes effect only when `nf_conntrack` is **(re)loaded**
  (typically at the next reboot); the two sysctls load immediately.

`apply` is idempotent (byte-identical drop-ins are left untouched), backs up any
pre-existing drop-in before overwriting, loads the sysctls via
`sysctl --system`, and verifies the live values. `revert` removes the managed
drop-ins (restoring a prior backup if one existed) and reloads; it deliberately
does **not** forcibly shrink the live table, which would be disruptive on a busy
host — the runtime ceiling reverts naturally at the next reboot.

## Usage

```sh
onionarmor audit  --module conntrack-tuning            # read-only status
onionarmor apply  --module conntrack-tuning [--dry-run]
onionarmor revert --module conntrack-tuning [--dry-run]
```

### Audit checks

| Check | Pass condition |
| --- | --- |
| `nf_conntrack_max` | live `>= 2097152` |
| `tcp_timeout_established` | live `<= 86400` |
| `utilization` | `nf_conntrack_count / nf_conntrack_max < 70%` (early-warning band — over it is a **warn**, not a failure) |
| `sysctl drop-in` | `/etc/sysctl.d/99-conntrack-tuning.conf` present with both `net.netfilter.*` lines |
| `modprobe hashsize` | `/etc/modprobe.d/nf_conntrack.conf` present with `options nf_conntrack hashsize=...` |

Severity follows the shared onionarmor reporter: green/yellow exit 0, any red
exits 1. On a host where `nf_conntrack` is not loaded the audit prints a single
`n/a` line and exits 0. A live key that cannot be read, or a threshold override
that is not a positive integer, is reported **`unscoreable` (yellow)** — never a
silent green pass, and never a hard failure on what amounts to operator error.

### Tuning the thresholds

Every boundary is an overridable env var (defaults shown):

```
ONIONARMOR_CT_MIN_MAX=2097152            # nf_conntrack_max target
ONIONARMOR_CT_MAX_TCP_ESTABLISHED=86400  # established-flow timeout ceiling (s)
ONIONARMOR_CT_UTIL_WARN_PCT=70           # utilization warn band (%)
ONIONARMOR_CT_HASHSIZE=524288            # modprobe hash-bucket count
```

## Manual remediation (without onionarmor)

If you need to apply the fix by hand on `relay-guard`, write both drop-ins in a
single `sudo bash -c '...'` invocation — a single command so it does not race
against `sudo`'s password prompt the way a multi-line heredoc block would — then
reload:

```sh
sudo bash -c 'cat > /etc/sysctl.d/99-conntrack-tuning.conf <<EOF
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
EOF
cat > /etc/modprobe.d/nf_conntrack.conf <<EOF
options nf_conntrack hashsize=524288
EOF
sysctl -p /etc/sysctl.d/99-conntrack-tuning.conf'
```

`hashsize` applies on the next `nf_conntrack` load — reboot (or
`rmmod`/`modprobe`, only when safe) to realize it. The `nf_conntrack_max` and
timeout changes take effect immediately from the `sysctl -p` above.
