# Module: `bgp-hardening`

**Apply safe defaults to an FRR `bgpd` that takes a full feed from a single trusted transit peer — without giving up that full feed.**

`bgp-hardening` closes the four gaps onionwarden's BGP audit surfaced across the
fleet, while *respecting the operator's deliberate constraints* (full feed from
the trusted peer, no TCP-MD5, no maximum-prefix). It:

1. **binds `bgpd`'s listener** to a specific peer-facing IP instead of `0.0.0.0` / `[::]`,
2. **restricts inbound `tcp/179`** at the firewall to the known peer IP(s),
3. **validates inbound origins with RPKI** (Routinator) — drops `INVALID`, keeps `VALID` + `UNKNOWN`, and
4. optionally enables **GTSM / `ttl-security`** (requires peer cooperation).

Everything auto-detects from `/etc/frr` (`bgp router-id`, `neighbor … remote-as`)
and every default is overridable.

## The audit context (why this module exists)

onionwarden's BGP posture check found, across **relay-host-3 / relay-host-5 /
relay-host-6**:

- `bgpd` listening on **`0.0.0.0:179`** (any interface) on every host, and
- **no firewall restriction** on `tcp/179` — anyone who can route a packet to the
  host could open a BGP TCP session attempt.

The peer (upstream-provider) is trusted and gives a full table, so the operator does
**not** want to switch to a default-only filter, enforce TCP-MD5 (the peer
doesn't offer it), or cap `maximum-prefix`. That leaves listener-bind +
firewall + RPKI as the high-value, low-disruption hardening — which is exactly
what this module does.

## Quick start

```sh
# Default: auto-detect bind IP + peers from /etc/frr and harden:
sudo onionarmor apply --module bgp-hardening

# Preview only — change nothing:
sudo onionarmor apply --module bgp-hardening --dry-run

# Status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module bgp-hardening

# Undo (restores daemons, drops firewall, disables but keeps Routinator):
sudo onionarmor revert --module bgp-hardening
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--bind-ip <ip>` | auto (`bgp router-id`) | bgpd listener bind IP (`-l` in `bgpd_options`). |
| `--no-bind-fix` | — | Skip the listener-bind step. |
| `--peer-ip <ip>` | auto (neighbor lines) | Known peer IP(s); repeatable / comma-separated. |
| `--firewall <nftables\|ufw>` | `nftables` | Firewall to manage for `tcp/179`. |
| `--no-firewall` | — | Skip the firewall step. |
| `--enable-rpki` / `--no-enable-rpki` | enable | Install/use Routinator + validate inbound. |
| `--rpki-source <url>` | the 5 RIR TALs | Extra RPKI repo URL; repeatable. |
| `--enable-gtsm` + `--gtsm-hops <N>` | off | Set `ttl-security hops <N>` per neighbor (peer must cooperate). |
| `--dry-run` | — | Print the planned changes; mutate nothing. |

## Customization examples

```sh
# 1. Default auto-detect:
sudo onionarmor apply --module bgp-hardening

# 2. Custom peer IPs (multi-homed peer / override auto-detect):
sudo onionarmor apply --module bgp-hardening --peer-ip 192.0.2.1,198.51.100.1

# 3. With GTSM (peer cooperation confirmed):
sudo onionarmor apply --module bgp-hardening --enable-gtsm --gtsm-hops 3

# 4. RPKI-only (skip the listener-bind, just enable validation):
sudo onionarmor apply --module bgp-hardening --no-bind-fix --enable-rpki

# 5. Audit only:
sudo onionarmor audit --module bgp-hardening
```

## What `apply` does, step by step

1. **Listener bind** — adds `-l <bind-ip>` to `bgpd_options` in `/etc/frr/daemons`
   (auto from `bgp router-id`, or `--bind-ip`). The original `daemons` file is
   backed up once to `…/bgp-hardening/daemons.bak` before the first edit.
2. **Firewall** — installs a dedicated nftables table `inet onionarmor_bgp` that
   `accept`s `tcp/179` from the known peer(s) and `drop`s it from everywhere
   else (atomic flush-and-recreate, so re-apply is idempotent). `--firewall ufw`
   uses additive `ufw` rules instead.
3. **RPKI** — installs + starts Routinator (via apt) if it isn't already running,
   then configures FRR's `rpki` cache (`127.0.0.1:3323`) and an inbound
   route-map `ONIONARMOR-RPKI-IN` that **denies `rpki invalid`** and **permits
   everything else**. This preserves the full feed (it is *not* a switch to a
   default-only filter — see *Out of scope*).
4. **GTSM** *(opt-in)* — sets `neighbor <ip> ttl-security hops <N>` per neighbor.
5. **Reload** — `systemctl reload frr` (graceful; the FIB/forwarding plane is
   preserved across the reload). A `bgpd_options` (`-l`) change is picked up when
   bgpd restarts; FRR's graceful restart keeps the FIB across that.

## What `audit` checks

`audit` is read-only and exits non-zero if any check is **red**:

1. **listener bind** — `bgpd`'s `tcp/179` listener is bound to a specific IP
   (red on `0.0.0.0` / `[::]`).
2. **firewall tcp/179** — the managed firewall restricts `tcp/179` to the known
   peer(s) with a default drop (yellow if a known peer isn't in the accept set).
3. **RPKI validation** — Routinator is active **and** FRR is configured to query
   it (red if configured-but-validator-down; yellow if this module hasn't
   configured it).
4. **FRR version** — *advisory only* (always yellow at worst): warns when the
   running FRR is on the fleet's CVE-advisory list (e.g. `8.4.4`, `10.5.0`) or
   below the fleet minimum, so version drift is visible.

## Revert

`revert` restores the backed-up `/etc/frr/daemons`, deletes the managed firewall
rules, removes the FRR `rpki` cache + `ONIONARMOR-RPKI-IN` route-map, and
**disables** Routinator (it is left *installed*, not purged). FRR is reloaded.

## Threat model

**Defends:**

- **Listener bind** — defense-in-depth even with a single trusted peer: a
  `bgpd` on `0.0.0.0` accepts connection *attempts* from any source that can
  route to the host (scanners, spoofed sources, other interfaces). Binding to
  the peer-facing IP shrinks that to one path.
- **Firewall `:179`** — the kernel drops BGP SYNs from anything but the known
  peer before they reach `bgpd`, blunting `tcp/179` scanning and resource
  exhaustion from non-peers.
- **RPKI** — validates the *origin AS* of inbound prefixes against signed ROAs
  and drops `INVALID` routes (route-origin hijacks / fat-finger mis-originations)
  while keeping the full feed.
- **GTSM** *(optional)* — `ttl-security` makes off-path spoofing of the BGP
  session harder, but **requires the peer to set a matching TTL** — hence opt-in.

**Does _not_ defend against / out of scope (by operator constraint):**

- **TCP-MD5 / TCP-AO session authentication** — the peer (upstream-provider) does not
  offer it, so it is *not* enforced. The firewall `:179` restriction is the
  equivalent on-path mitigation here.
- **`maximum-prefix`** — *not set*: the operator wants an unbounded feed for
  future flexibility. (A run-away peer table is therefore not capped — a
  deliberate trade-off.)
- **Inbound prefix filtering** — the full-table accept policy (`ALLOW_ALL_IN`)
  is **kept**. RPKI only removes `INVALID`s; this module never installs a
  restrictive default-only inbound filter.
- A **malicious-but-valid-ROA** origin, path manipulation by the trusted peer
  itself, or data-plane attacks — all out of scope.

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/frr/daemons` (`bgpd_options`) | listener bind (`-l <ip>`) |
| `/var/lib/onionarmor/bgp-hardening/daemons.bak` | one-time backup, restored by `revert` |
| nftables table `inet onionarmor_bgp` | the `tcp/179` peer allow-list + default drop |
| FRR `rpki` cache + route-map `ONIONARMOR-RPKI-IN` | inbound origin validation |
| `/var/lib/onionarmor/bgp-hardening/rpki.applied` | marker that FRR RPKI config is installed |

Every path and external command (`vtysh`, `nft`, `ufw`, `systemctl`, `ss`,
`apt-get`) is overridable via environment variables (see `lib.sh`) so the bats
suite drives the whole module against a sandbox with stub binaries.

## Tests

```sh
bats modules/bgp-hardening/tests/bats/
```

Offline suite (FRR/nft/systemctl/ss/apt all stubbed): listener-bind, peer
auto-detect, firewall rule + default drop, idempotency, dry-run, RPKI
install-once, GTSM `ttl-security`, audit wildcard-vs-specific bind, RPKI
up/down, FRR version advisory, and revert (daemons restore + firewall removal +
validator disable).
