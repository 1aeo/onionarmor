# Module: `firewall-default-deny`

**Default-DENY inbound via UFW — drop scan SYNs (no kernel RST, no onionleak flow), allow only the detected service listeners. With a 5-minute SSH safety latch.**

`firewall-default-deny` puts inbound traffic under `ufw default deny incoming`
while keeping outbound open (tor makes many outbound connections). It inventories
the host's actual TCP listeners, allows only the ones it recognises (SSH —
auto-detected from `sshd_config`; tor ORPort/DirPort; BGP — restricted to peers),
and **denies everything else**. Before it enables the firewall it schedules an
`at` job to auto-disable in 5 minutes, so a wrong SSH-port guess can never lock
you out.

> ### Why this exists
> From the *almostopen* residual-unvalidated investigation: **69% of unvalidated
> flows are kernel RST replies** to scans of closed / non-listener ports. A
> default-deny inbound firewall silently **drops** those SYNs — the kernel emits
> no RST, so no flow appears in onionleak capture and the inbound attack surface
> shrinks at the same time. This module closes that finding.

## Quick start

```sh
# ALWAYS dry-run first — see the exact rules + which listeners would be denied:
sudo onionarmor apply --module firewall-default-deny --dry-run

# Apply (schedules a 5-min safety latch, then enables ufw):
sudo onionarmor apply --module firewall-default-deny
#   ... confirm your SSH session still works, THEN cancel the latch it prints:
#   atrm <job>

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module firewall-default-deny

# Undo (disable + reset ufw — RE-EXPOSES closed ports):
sudo onionarmor revert --module firewall-default-deny
```

## ⚠️ The 5-minute SSH safety latch

The single biggest risk of a default-deny firewall is **locking yourself out of
SSH** (wrong port detected, an allow rule that didn't take, a typo). To make that
non-fatal, `apply` — *before* enabling ufw — runs:

```sh
echo 'ufw disable && systemctl restart ssh' | at now + 5 minutes
```

and prints the exact command to cancel it:

```
atrm <job>          # or:  atrm $(atq | head -1 | awk '{print $1}')
```

**Workflow:** apply → confirm your SSH session is still alive (open a second
session to be sure) → `atrm <job>` to keep the firewall. If you got locked out,
do nothing — in ≤5 minutes the latch disables ufw and restarts ssh, and you're
back in. Tune with `--latch-minutes`, or skip it with `--no-safety-latch` **only
if you have out-of-band console access**. Requires the `at` package (apply errors
with an install hint if it's missing).

## What gets an allow rule

`apply` runs `ss -tlnH` and, for each **non-loopback** TCP listener:

| Listener | Rule |
|---|---|
| SSH port (from `sshd_config`, **not** assumed 22 — the fleet uses 33311 on some hosts) | `allow <port>/tcp` |
| 80 / 443 (tor DirPort / ORPort, ACME) | `allow <port>/tcp` |
| BGP `179` | **restricted** — `allow from <peer> …` per FRR neighbor, else `allow to <bgpd-bind-ip> …` from `/etc/frr/daemons`; if neither is known, **denied + warned** |
| loopback (`127.0.0.0/8`, `::1`) | **skipped** — never firewalled (this is what keeps it off `kernel-reserved-ports`' loopback metrics ports) |
| anything else | **denied** + warned; re-run with `--allow <port>` to expose it |

Plus the always-on baseline: `default deny incoming`, `default allow outgoing`,
`allow in on lo`, and `IPV6=yes` in `/etc/default/ufw` (set **before** enable so
rules cover v4+v6).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--allow <port[/proto]>` | — | Allow an extra inbound port (repeatable). Required for any listener not auto-recognised. |
| `--ssh-port <n>` | from `sshd_config` | Override the detected SSH port. |
| `--no-ipv6` | ipv6 on | Do not enable UFW IPv6. |
| `--no-safety-latch` | latch on | Skip the auto-disable latch (**console access required**). |
| `--latch-minutes <n>` | `5` | Latch delay. |
| `--dry-run` | off | Print the plan + rule manifest + denied listeners. Changes nothing. |
| `--verify` / `--no-verify` | verify | Post-apply: confirm ufw is active. |

## What `audit` checks

Read-only; exits non-zero if any check is **red**:

1. **ufw active** — red if inactive (default-deny not in force).
2. **default policy** — `deny (incoming)` / `allow (outgoing)`.
3. **IPv6 enabled** — `IPV6=yes`; red if a default-deny v4 firewall leaves v6 open.
4. **rule count** — number of active allow rules.
5. **listeners + drift** — the current non-loopback listener set, and any listener
   with **no** allow rule (yellow: being denied — `--allow` to expose) plus whether
   the stored manifest still matches the host.
6. **safety latch** — yellow while an `at` auto-disable job is still pending
   (reminder to cancel it), green once cancelled/expired.

## Revert

`revert` cancels any pending safety latch, `ufw disable && ufw reset`, and removes
the manifest. ufw is left installed. **This re-exposes all closed ports to kernel
RST emission** — scans will again produce onionleak flows; the command says so.

## Coordination with other modules

- **`bgp-hardening`** — reads the same FRR signals (`neighbor` peers, the
  `bgpd_options -A/-l` bind) to scope the `179` rule, so the two agree. If you run
  `bgp-hardening`'s own `tcp/179` firewall, the rules are compatible (both restrict
  179 to peers); review for duplicates.
- **`kernel-reserved-ports`** — F skips loopback entirely, so it never touches the
  loopback metrics/control ports that module reserves. No interaction.
- **`dns-posture`** — DNS is **outbound** (default allow), so F does not affect it.

## Front-end support

UFW only, for now. If `ufw` is **not** installed, `apply` **errors** with an
install hint (`apt install ufw`) rather than silently installing it (ufw pulls
`iptables-persistent` and friends) or doing a fragile raw-`nftables` fallback. A
raw nftables/iptables back-end is a documented future addition.

## Files this module manages

| Path | Purpose |
|---|---|
| UFW configuration (`/etc/ufw/*`, via the `ufw` CLI) | the live rule set + default policies |
| `/etc/default/ufw` (`IPV6=yes`) | enable v6 filtering |
| `/var/lib/onionarmor/firewall-default-deny/rules.manifest` | the intended rule set (idempotency + audit drift) |
| `/var/lib/onionarmor/firewall-default-deny/safety-latch.job` | the pending `at` job id |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against stub `ss`/`ufw`/`at`.

## Tests

```sh
bats modules/firewall-default-deny/tests/bats/
```

The offline suite stubs `ss`, a **stateful** `ufw` (active flag, default
policies, rule list), and `at`/`atq`/`atrm`, covering: empty listener set →
SSH-only + latch; known-safe 80/443; **loopback ports skipped**; **BGP/179
restricted** from a fixture `/etc/frr/daemons` (and per-peer from neighbors);
unknown listener denied + `--allow`; SSH non-22 detection; IPv6 enable;
idempotency; the **safety latch** (scheduled + cancel-instruction printed + audit
pending state); and the apply→audit→revert→audit cycle. `docker.bats` adds an
**opt-in** real-`ufw` `debian:bookworm` check (skipped unless
`ONIONARMOR_DOCKER_TESTS=1`; a full enable cycle needs `--cap-add=NET_ADMIN`).

---

**See also:** [Modules overview](../../docs/modules.md) · [`bgp-hardening`](../bgp-hardening/README.md) · [`kernel-reserved-ports`](../kernel-reserved-ports/README.md) · [main README](../../README.md)
