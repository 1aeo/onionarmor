# Module: `kernel-reserved-ports`

**Reserve the relay's loopback service ports from the kernel's ephemeral source-port pool, so an outbound connection can never steal a port a tor instance needs to bind.**

`kernel-reserved-ports` writes `net.ipv4.ip_local_reserved_ports` as a `sysctl.d`
drop-in covering every loopback `MetricsPort` / `ControlPort` / `SocksPort` /
`DNSPort` / `TransPort` / `HTTPTunnelPort` a relay host exposes. The ports it
reserves are **auto-detected from your torrc files** (`--auto`) and/or given
explicitly (`--reserved-range`).

> **This is operational-reliability hardening, not a security control per se.**
> But on a relay fleet, availability *is* part of the threat model: a tor
> instance that can't bind its `MetricsPort` is a relay that doesn't come up,
> and fewer relays means less capacity and weaker network-level anonymity. See
> [Threat model](#threat-model).

## The problem (observed in production)

Linux chooses the **source port** of an outbound connection from the *ephemeral*
range `net.ipv4.ip_local_port_range` — by default roughly `32768-60999`. That
allocation is global to the host. If a tor instance binds a **listener** on
loopback inside that range — say `MetricsPort 127.0.0.1:48082` — the kernel is
free to hand `48082` to a *different* tor instance as the source port of one of
its outbound connections. When the first instance (re)starts and tries to bind
`48082`, the port is already in use and the bind fails. The relay doesn't start.

We hit exactly this on **`relay-host-5`**: `tor@instance-1`'s `MetricsPort 48082`
intermittently failed to bind because another of the ~hundreds of co-resident
tor instances had grabbed `48082` as an ephemeral source port for an outbound
socket. It is racy and density-dependent — it shows up precisely on the busy,
many-instance hosts you least want flapping.

The fix is to remove those loopback service ports from the ephemeral pool:

```
net.ipv4.ip_local_reserved_ports = 48001-48249,29000-29299
```

The kernel will then never select a reserved port as an ephemeral source port,
while tor can still bind it as a listener. (Reserving a port that already sits
*outside* the ephemeral range is harmless — it simply has no effect.)

## Quick start

```sh
# Auto-detect the relay's loopback tor ports and reserve them:
sudo onionarmor apply --module kernel-reserved-ports --auto

# See exactly what it would do first — changes nothing:
sudo onionarmor apply --module kernel-reserved-ports --auto --dry-run

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module kernel-reserved-ports --auto

# Undo (removes the drop-in, clears the runtime reservation, backs it up):
sudo onionarmor revert --module kernel-reserved-ports
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--auto` | off | **Headline.** Auto-detect loopback tor ports from torrc and reserve the compact range(s) that cover them. |
| `--reserved-range <start-end>` | — | Reserve an explicit range. Repeatable; comma-separated lists accepted: `--reserved-range 48001-48249,29000-29299`. |
| `--auto-buffer <N>` | `0` | Widen each **auto-detected** range by `N` ports on each side (headroom for fleet growth). `48001-48245` with `--auto-buffer 50` → `47951-48295`. |
| `--listen-ip <ip>` | all loopback | Restrict `--auto` to ports bound to this exact IP. Default covers `127.0.0.0/8` and `::1`. |
| `--cluster-gap <N>` | `256` | Auto-detect: fold ports within `N` of each other into one compact range. Bands farther apart stay separate reservations. |
| `--min-port <N>` | `1024` | Ignore detected ports below `N` (well-known ports never need reserving). |
| `--dry-run` | off | Print the would-be drop-in + planned `sysctl --system` call + before/after sysctl values. Changes nothing. |
| `--verify` / `--no-verify` | verify | After apply, confirm the live sysctl value **and** `/proc/sys/net/ipv4/ip_local_reserved_ports` match the drop-in. |

At least one of `--auto` / `--reserved-range` is required for `apply`.

### How `--auto` works

1. Globs `/etc/tor/instances/*/torrc`, `/run/tor-instances/*.defaults`,
   `/etc/tor/torrc.all`, and `/etc/tor/torrc`.
2. Parses every `MetricsPort|ControlPort|SocksPort|DNSPort|TransPort|HTTPTunnelPort`
   line, extracting `<ip>:<port>` (also `[::1]:<port>` and bare `<port>`, which
   tor binds on `127.0.0.1`).
3. Keeps only loopback ports (or those matching `--listen-ip`), dropping
   anything below `--min-port`.
4. Groups them into **compact ranges** (so 200 instances become a single
   `48001-48200`, not a 200-element list), optionally widened by `--auto-buffer`.
5. Emits one `<min>-<max>` reservation per disjoint band.

## Customization examples

```sh
# 1. Default — auto-detect from torrc:
sudo onionarmor apply --module kernel-reserved-ports --auto

# 2. Manual override (operator with a non-standard layout):
sudo onionarmor apply --module kernel-reserved-ports --reserved-range 9050-9090

# 3. Mixed — auto-detect tor ports + a manual extra band for Prometheus:
sudo onionarmor apply --module kernel-reserved-ports --auto --reserved-range 9090-9099

# 4. Headroom for fleet growth (widen each auto range by 50 ports/side):
sudo onionarmor apply --module kernel-reserved-ports --auto --auto-buffer 50

# 5. Audit only — report current state vs. the auto-detected expectation:
sudo onionarmor audit --module kernel-reserved-ports --auto

# 6. Revert:
sudo onionarmor revert --module kernel-reserved-ports
```

## What `audit` checks

`audit` is read-only and exits non-zero if any check is **red**:

1. **drop-in present** — `/etc/sysctl.d/99-onionarmor-reserved-ports.conf` exists
   and declares `net.ipv4.ip_local_reserved_ports`.
2. **runtime matches drop-in** — the live sysctl value equals the drop-in
   (catches a host that needs `sysctl --system`, or a value changed out from
   under the file).
3. **tor ports covered** *(only with `--auto`)* — every loopback tor port the
   torrc files currently declare falls inside the reservation. If new instances
   were added after the last apply, this turns **red** and names the uncovered
   band — *reservation drift*.

## Revert

`revert`:

1. backs the drop-in up to
   `/var/lib/onionarmor/kernel-reserved-ports/backup.conf`,
2. removes the drop-in,
3. clears the runtime reservation (`sysctl -w net.ipv4.ip_local_reserved_ports=`)
   and reloads — because the kernel keeps the live value until something resets
   it; removing the file alone is not enough until a reboot.

## Threat model

**What this defends:** relay **availability** on dense, many-instance hosts.
A failed-to-bind tor instance is a relay that silently drops out of the network.
Reserving its loopback ports removes a class of intermittent, density-dependent
bind failures (the `relay-host-5` / `MetricsPort 48082` incident).

**Why it's in a hardening tool even though it isn't a classic security control:**
relay capacity and uptime are anonymity-relevant. The Tor network's anonymity
set is a function of how much honest capacity is reliably online; a guard/relay
that flaps under load weakens that, and degraded capacity is exactly what an
availability-focused adversary wants. Treating reliable bind-up as part of the
posture is consistent with onionarmor's role.

**What it does _not_ do:**

- It does **not** firewall, authenticate, or encrypt anything on those ports —
  bind `MetricsPort`/`ControlPort` to loopback and protect them at the
  application layer as you would anyway.
- It does **not** stop a *local* process from `connect()`-ing to a reserved
  loopback port; reservation only governs the kernel's **ephemeral source-port**
  selection, not who may talk to a listener.
- It is **not** a substitute for choosing service ports outside the ephemeral
  range in the first place — it's the belt-and-suspenders for fleets that
  can't easily renumber.

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/sysctl.d/99-onionarmor-reserved-ports.conf` | the managed drop-in (the reservation) |
| `/var/lib/onionarmor/kernel-reserved-ports/backup.conf` | drop-in backup, written by `revert` |
| `net.ipv4.ip_local_reserved_ports` (sysctl) | the live kernel reservation |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against a sandbox.

## Tests

```sh
bats modules/kernel-reserved-ports/tests/bats/
```

The offline suite stubs `sysctl` (emulating the kernel's
`ip_local_reserved_ports` through a fake `/proc` file) and builds sandbox torrc
trees, covering auto-detection, range compaction, disjoint bands, `--auto-buffer`,
the loopback filter, manual/combined ranges, dry-run, the audit drift detector,
and revert (removal + backup + runtime reset).
