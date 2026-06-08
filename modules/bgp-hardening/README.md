# Module: `bgp-hardening`

**Bind an FRR `bgpd` listener to a specific peer-facing IP — the one high-value fix for a single-homed stub-AS relay — with firewall, RPKI, and GTSM offered as opt-in extras.**

`bgp-hardening` addresses what onionwarden's BGP audit surfaced across the fleet
while *respecting the operator's deliberate constraints* (full feed from a single
trusted transit peer, no TCP-MD5, no `maximum-prefix`). By default it does **one
thing**:

- **binds `bgpd`'s listener** to a specific peer-facing IP instead of `0.0.0.0` / `[::]`.

Three further controls are **opt-in**, because their value depends on topology
the fleet doesn't have (see [When NOT to use RPKI](#when-not-to-use-rpki)):

- `--enable-firewall` — restrict inbound `tcp/179` to the known peer IP(s) (nftables),
- `--enable-rpki` — install Routinator + RPKI-validate inbound (drop `INVALID`, keep `VALID` + `UNKNOWN`),
- `--enable-gtsm` — GTSM / `ttl-security` (requires peer cooperation).

Everything auto-detects from `/etc/frr` (`bgp router-id`, `neighbor … remote-as`)
and every default is overridable.

## The audit context (why this module exists)

onionwarden's BGP posture check found, across **relay-host-3 / relay-host-5 /
relay-host-6**:

- `bgpd` listening on **`0.0.0.0:179`** (any interface) on every host, and
- no firewall restriction on `tcp/179`.

The peer (upstream-provider) is trusted and gives a full table, so the operator does
**not** want a default-only filter, TCP-MD5 (the peer doesn't offer it), or a
`maximum-prefix` cap. The listener bind is the unambiguous win and is applied by
default; the rest are opt-in defense-in-depth.

## Quick start

```sh
# Default: bind the bgpd listener to a specific peer-facing IP (auto-detected):
sudo onionarmor apply --module bgp-hardening

# Preview only — change nothing:
sudo onionarmor apply --module bgp-hardening --dry-run

# Status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module bgp-hardening

# Undo (restores daemons; drops any opt-in firewall/RPKI you enabled):
sudo onionarmor revert --module bgp-hardening
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--bind-ip <ip>` | auto (`bgp router-id`) | bgpd listener bind IP (`-l` in `bgpd_options`). |
| `--no-bind-fix` | — | Skip the listener-bind step. |
| `--peer-ip <ip>` | auto (neighbor lines) | Known peer IP(s); repeatable / comma-separated. |
| `--enable-firewall` | **off** | Restrict `tcp/179` to the known peer(s) with nftables. |
| `--enable-rpki` | **off** | Install/use Routinator + RPKI-validate inbound. |
| `--no-enable-rpki` | (default) | Leave RPKI alone. |
| `--rpki-source <url>` | the 5 RIR TALs | Extra RPKI repo URL; repeatable. |
| `--enable-gtsm` + `--gtsm-hops <N>` | off | Set `ttl-security hops <N>` per neighbor (peer must cooperate). |
| `--dry-run` | — | Print the planned changes; mutate nothing. |

> **Why are firewall and RPKI off by default?** For a single-homed stub AS the
> listener bind is the change that actually reduces attack surface for free. The
> firewall is sound defense-in-depth but was deferred for fleet rollout; RPKI on
> *inbound* routes changes no forwarding decision on a stub (below). Both are one
> flag away when you want them.

## Customization examples

```sh
# 1. Default — listener bind only (the stub-AS recommendation):
sudo onionarmor apply --module bgp-hardening

# 2. Custom peer IPs (override auto-detect) + firewall:
sudo onionarmor apply --module bgp-hardening --enable-firewall --peer-ip 192.0.2.1,198.51.100.1

# 3. With GTSM (peer cooperation confirmed):
sudo onionarmor apply --module bgp-hardening --enable-gtsm --gtsm-hops 3

# 4. Opt into RPKI as well (only if your topology benefits — see below):
sudo onionarmor apply --module bgp-hardening --enable-rpki

# 5. Audit only:
sudo onionarmor audit --module bgp-hardening
```

## What `apply` does, step by step

1. **Listener bind** *(default)* — adds `-l <bind-ip>` to `bgpd_options` in
   `/etc/frr/daemons` (auto from `bgp router-id`, or `--bind-ip`). The original
   `daemons` file is backed up once to `…/bgp-hardening/daemons.bak`. Because
   `bgpd -l` implies `--no_kernel`, the module also issues `no bgp no-rib` so
   learned routes still install into the kernel. A bgpd_options change requires a
   **restart** (graceful — FRR keeps the FIB) for the new bind to take effect.
2. **Firewall** *(opt-in: `--enable-firewall`)* — installs a dedicated nftables
   table `inet onionarmor_bgp` that `accept`s `tcp/179` from the known peer(s)
   and `drop`s it from everywhere else (atomic flush-and-recreate, idempotent).
   *(`ufw` support is deferred for this PR.)*
3. **RPKI** *(opt-in: `--enable-rpki`)* — installs + starts Routinator, then
   configures FRR's `rpki` cache (`127.0.0.1:3323`) and an inbound route-map
   `ONIONARMOR-RPKI-IN` that **denies `rpki invalid`** and **permits everything
   else** (preserves the full feed; *not* a default-only filter).
4. **GTSM** *(opt-in: `--enable-gtsm`)* — sets `neighbor <ip> ttl-security hops <N>`.

## What `audit` checks

`audit` is read-only and exits non-zero only on a **red**:

1. **listener bind** *(required)* — bound to a specific IP; **red** on `0.0.0.0` / `[::]`.
2. **firewall tcp/179** *(optional)* — **green when not configured** (it's opt-in
   defense-in-depth); red only if an opted-in firewall is broken (missing the
   default drop); yellow if a known peer isn't in the accept set.
3. **RPKI validation** *(optional)* — **green when not configured** (minimal value
   for a stub AS); red only if you opted in and the validator is down.
4. **FRR version** — *advisory only* (yellow at worst): warns when the running FRR
   is on the fleet's CVE-advisory list (e.g. `8.4.4`, `10.5.0`) or below the
   fleet minimum.

So the default stub-AS posture (listener bind only) audits **all green**.

## Revert

`revert` restores the backed-up `/etc/frr/daemons`, removes the `no bgp no-rib`
override, and undoes whatever opt-in extras were applied: drops the nftables
table, removes the FRR `rpki` cache + `ONIONARMOR-RPKI-IN` route-map, removes
GTSM config, and **disables** Routinator *only if this module enabled it* (left
*installed*, not purged). FRR is restarted (if daemons changed) or reloaded.

## Threat model

**Defends:**

- **Listener bind** *(default)* — defense-in-depth even with a single trusted
  peer: a `bgpd` on `0.0.0.0` accepts connection *attempts* from any source that
  can route to the host. Binding to the peer-facing IP shrinks that to one path.
- **Firewall `:179`** *(opt-in)* — the kernel drops BGP SYNs from non-peers
  before they reach `bgpd`, blunting `tcp/179` scanning and exhaustion.
- **RPKI** *(opt-in)* — drops `INVALID` inbound origins (route-origin hijacks /
  mis-originations) while keeping the full feed — **but see the caveat below**.
- **GTSM** *(opt-in)* — raises the bar for off-path session spoofing, but
  **requires the peer to set a matching TTL**.

### When NOT to use RPKI

> RPKI validation has minimal value for single-homed stub AS deployments where
> all routes (default or specific) resolve to the same next-hop. If your relay
> has only one upstream peer and doesn't forward traffic (`no ip forwarding`),
> the validator and rpki-route-map add operational complexity without changing
> forwarding behavior. The exception is multi-homed setups where INVALID routes
> from one upstream could divert traffic to a hijacker via a different upstream.
> Use `--enable-rpki` only if your topology genuinely benefits.

The 1aeo fleet hosts are single-homed stub ASes, so inbound RPKI is **off by
default** here.

### The RPKI work that *does* matter for a stub AS: publish your own ROAs

The genuinely useful RPKI action for a stub-AS operator is the *opposite*
direction — publishing ROAs for the prefixes **you** announce, so that *other*
networks doing RPKI don't drop your legitimate announcements. That is an
operator-level action at your **RIR / IP-holder portal**, not a host config.

Use the bundled [`bin/check-own-roa-status`](../../bin/check-own-roa-status)
helper to verify your ROAs (it only *reports* — it changes nothing, and is never
invoked by `apply`/`audit`):

```text
$ check-own-roa-status
RPKI status of announced prefixes (origin AS64512) via https://stat.ripe.net/data/rpki-validation/data.json

PREFIX               STATUS
-------------------- ------
192.0.2.0/24         VALID
192.0.2.0/24        VALID
192.0.2.0/24        VALID
192.0.2.0/24         VALID

OK: all 4 announced prefix(es) are RPKI-VALID. No action needed.
```

The **1aeo fleet is already RPKI-compliant** — all four announced /24s
(`192.0.2.0/24`, `192.0.2.0/24`, `192.0.2.0/24`, `192.0.2.0/24`, origin
AS64512, max-length 24) validate as **VALID**, so this helper has nothing to flag
for the fleet. It exists for other operators (and to catch future ROA drift).

**Does _not_ defend against / out of scope (by operator constraint):**

- **TCP-MD5 / TCP-AO session authentication** — the peer (upstream-provider) does not
  offer it, so it is *not* enforced. The opt-in `:179` firewall is the equivalent
  on-path mitigation.
- **`maximum-prefix`** — *not set*: the operator wants an unbounded feed.
- **Inbound prefix filtering** — the full-table accept policy (`ALLOW_ALL_IN`) is
  **kept**; even with `--enable-rpki`, only `INVALID`s are removed.
- A **malicious-but-valid-ROA** origin, path manipulation by the trusted peer
  itself, or data-plane attacks — all out of scope.

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/frr/daemons` (`bgpd_options`) | listener bind (`-l <ip>`) — always |
| `/var/lib/onionarmor/bgp-hardening/daemons.bak` | one-time backup, restored by `revert` |
| nftables table `inet onionarmor_bgp` | `tcp/179` peer allow-list + default drop *(only with `--enable-firewall`)* |
| FRR `rpki` cache + route-map `ONIONARMOR-RPKI-IN` | inbound origin validation *(only with `--enable-rpki`)* |
| `…/bgp-hardening/{rpki,routinator,gtsm,norib}.*` markers | track which opt-in pieces were applied, so `revert` only undoes what we did |

Every path and external command (`vtysh`, `nft`, `systemctl`, `ss`, `apt-get`)
is overridable via environment variables (see `lib.sh`) so the bats suite drives
the whole module against a sandbox with stub binaries.

## Tests

```sh
bats modules/bgp-hardening/tests/bats/
```

Offline suite (FRR/nft/systemctl/ss/apt stubbed): listener-bind, RPKI/firewall
**off-by-default** + **on-when-flagged**, peer auto-detect, firewall rule +
default drop, idempotency, dry-run, RPKI install-once, GTSM `ttl-security`, audit
wildcard-vs-specific bind, audit stays green without the optional controls, RPKI
up/down, FRR version advisory, revert (daemons restore + opt-in teardown), and
the `check-own-roa-status` helper.
