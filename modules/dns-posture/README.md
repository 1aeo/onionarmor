# Module: `dns-posture`

**Bring DNS resolution under a local, validating, DoT-only resolver — the same posture the 1aeo relay fleet runs.**

`dns-posture` installs and configures [`unbound`](https://www.nlnetlabs.nl/projects/unbound/) as a local resolver that:

- listens on `127.0.0.1:53` (+ `::1`),
- forwards **only over DNS-over-TLS (`:853`)** to a pinned set of upstreams (SNI-verified) — **no Do53 fallback**,
- **validates DNSSEC** using Debian's stock root trust anchor,
- pins `/etc/resolv.conf` at the local resolver, and
- **masks `systemd-resolved`** so nothing else answers on `127.0.0.53`.

It is the apply-side counterpart to the read-only drift checks in `onionwarden`. Every fleet default is overridable so operators with their own DNS opinion (Cloudflare-only, Mullvad-only, a LAN-shared resolver, DNSSEC off) can dial it in.

> Why a local resolver at all? On Ubuntu 24.04 the stock `systemd-resolved` falls over under sustained parallel DNS load (high CPU, hundreds of MB RSS, stops answering `127.0.0.53`). A local validating `unbound` with DoT upstreams is both more robust and a real privacy/integrity upgrade for a relay.

## Quick start

```sh
# Default fleet posture (DoT + DNSSEC + unbound, systemd-resolved masked):
sudo onionarmor apply --module dns-posture

# See exactly what it would do first — changes nothing:
sudo onionarmor apply --module dns-posture --dry-run

# Check status any time (green/yellow/red; non-zero exit if any red):
onionarmor audit --module dns-posture

# Undo everything (restores resolv.conf, unmasks systemd-resolved):
sudo onionarmor revert --module dns-posture
```

## Flags

Every fleet default is overridable. Defaults shown in **bold**.

| Flag | Default | Meaning |
|---|---|---|
| `--upstreams <list>` | the fleet set (below) | Comma-separated `<ip>@<port>#<sni>` DoT upstreams. |
| `--no-dnssec` | DNSSEC **on** | Disable DNSSEC validation (iterator-only). See trade-off below. |
| `--listen <addr>` | **`127.0.0.1`** | unbound listen address. `0.0.0.0` shares the resolver on the LAN. |
| `--listen-port <port>` | **`53`** | unbound listen port. |
| `--num-threads <n>` | **`4`** | unbound worker threads (Debian autodetect was unreliable on small VPS). |
| `--anchor-file <path>` | **`/var/lib/unbound/root.key`** | DNSSEC trust-anchor file. |
| `--bootstrap-anchor` / `--no-bootstrap-anchor` | **bootstrap** | Seed the anchor from the distro `root.key` if missing. |
| `--mask-resolved` / `--no-mask-resolved` | **mask** | Mask + stop `systemd-resolved`. |
| `--resolv-conf <path>` | **`/etc/resolv.conf`** | Which resolv.conf to manage. |
| `--immutable-resolv` | off | `chattr +i` the managed resolv.conf so nothing rewrites it. |
| `--dry-run` | off | Print the plan + rendered config, change nothing. |
| `--verify` / `--no-verify` | **verify** | Post-apply checks: `unbound-checkconf`, DoT-only `list_forwards`, DNSSEC `ad` flag. |

Default upstream set (all DoT `:853`, SNI-pinned):

```text
1.1.1.1@853#cloudflare-dns.com, 1.0.0.1@853#cloudflare-dns.com   # Cloudflare
9.9.9.9@853#dns.quad9.net, 149.112.112.112@853#dns.quad9.net     # Quad9
8.8.8.8@853#dns.google                                            # Google
94.140.14.14@853#dns.adguard-dns.com                              # AdGuard
194.242.2.2@853#dns.mullvad.net                                   # Mullvad
2620:fe::fe@853#dns.quad9.net                                     # Quad9 v6
2606:4700:4700::1111@853#cloudflare-dns.com                       # Cloudflare v6
```

## Examples for operators with their own DNS opinion

```sh
# Cloudflare only:
sudo onionarmor apply --module dns-posture \
  --upstreams '1.1.1.1@853#cloudflare-dns.com,1.0.0.1@853#cloudflare-dns.com'

# Mullvad only (privacy-focused, no-logging resolver):
sudo onionarmor apply --module dns-posture \
  --upstreams '194.242.2.2@853#dns.mullvad.net'

# Share the resolver with the LAN (bind all interfaces):
sudo onionarmor apply --module dns-posture --listen 0.0.0.0

# Audit only — never modifies the host:
onionarmor audit --module dns-posture

# Pin resolv.conf so nothing (DHCP, cloud-init) can rewrite it:
sudo onionarmor apply --module dns-posture --immutable-resolv

# Roll it all back:
sudo onionarmor revert --module dns-posture
```

## The duplicate-anchor footgun (why this module is careful)

DNSSEC needs **exactly one** `auto-trust-anchor-file` declaration. Debian's `unbound` package already ships one in `/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf`. Adding a *second* one (e.g. in a hand-rolled snippet) is what crashed three fleet hosts — `unbound` refuses to start and DNS goes dark.

This module is built around that lesson:

- `apply` **defers to the stock anchor file** when one is present and only declares its own when none exists, so there is always exactly one.
- Before it ever (re)starts `unbound`, `apply` counts `auto-trust-anchor-file` lines across `conf.d/` and **aborts** if it finds more than one — it will not ship a config that crashes the resolver.
- `audit` reports the anchor count as a first-class check: `1` = green, `0` = yellow (DNSSEC anchor absent), `>1` = **red** (duplicate).

There is a regression test for exactly this (`tests/bats/apply.bats`, `tests/bats/audit.bats`).

## What `audit` checks

`onionarmor audit --module dns-posture` reports green/yellow/red and exits non-zero if **anything is red**:

| Check | green | red |
|---|---|---|
| unbound active | `systemctl is-active unbound` = active | not active |
| single trust anchor | exactly 1 `auto-trust-anchor-file` | 2+ (duplicate) |
| resolv.conf pinned | real file with `nameserver <listener>` | a symlink, missing, or wrong target |
| systemd-resolved masked | `is-enabled` = masked | still active |
| forwarders DoT-only | every `forward-addr` is `@853` | a plaintext `:53` forwarder present |
| DNSSEC ad flag | `dig +dnssec` answer has the `ad` flag | no `ad` flag (validation not happening) |

(`single trust anchor` = 0 and `forwarders` = none are **yellow**, not red.)

## Threat model — honest about the limits

DoT + DNSSEC + a local validating resolver **does** defend against:

- **Passive network observers** — your recursive queries to the upstream are encrypted (DoT), so an on-path eavesdropper can't read which domains you resolve from the resolver↔upstream leg. (Note: the destination IP of the *eventual connection* is still visible; this protects the DNS query, not the subsequent TCP flow.)
- **On-path DNS tampering / MITM** — DoT authenticates the upstream by certificate + pinned SNI, and DNSSEC cryptographically validates the answer chain, so a man-in-the-middle can't silently forge or poison responses without detection.
- **An untrusted local/ISP resolver** — you stop using the network-provided resolver entirely; queries go to upstreams you chose.

It does **NOT** defend against:

- **A malicious-but-valid-PKI upstream.** If you forward to a resolver that has a valid cert for its SNI but chooses to lie or log, DoT still trusts it. DNSSEC catches *forged* answers for signed zones, but not unsigned zones, and not metadata logging. Choose upstreams you trust; `--upstreams` exists for exactly this.
- **Applications with hard-coded resolvers.** A program that talks to `8.8.8.8:53` directly (or ships its own DoH) bypasses your `resolv.conf` entirely. This module pins `resolv.conf`; it cannot intercept apps that ignore it. (`--immutable-resolv` only stops *rewrites* of the file, not apps that never read it.)
- **Browser DoH bypass.** Firefox/Chrome can be configured to do their own DNS-over-HTTPS to a vendor resolver, ignoring the system resolver. That's a browser-policy problem, not something a system resolver can prevent.
- **Traffic-analysis / SNI leakage on the actual connections.** This hardens DNS, not the connections you make afterward. The destination IP and (absent ECH) the TLS SNI of your real traffic remain visible.

In short: this raises the floor (no plaintext DNS, no unsigned tampering, no ISP resolver) but is not a substitute for trusting your upstream or for application-level privacy controls.

## Files this module manages

| Path | Role |
|---|---|
| `/etc/unbound/unbound.conf.d/99-onionarmor-dns-posture.conf` | the managed unbound snippet |
| `/var/lib/unbound/root.key` | DNSSEC trust anchor (bootstrapped if missing) |
| `/etc/resolv.conf` | rewritten as a real file pointing at the local resolver |
| `/var/lib/onionarmor/dns-posture/resolv.conf.bak` | one-time backup of the original resolv.conf |

`apply`, `audit` and `revert` all write to the tamper-evident onionarmor audit log (`/var/log/onionarmor/audit.log`).

## Tests

```sh
bats modules/dns-posture/tests/bats/
```

Fully offline — every external command is stubbed. Covers apply / audit / revert, the duplicate-anchor regression, idempotency, every flag, and the verification + failure paths.

---

**See also:** [Modules overview](../../docs/modules.md) · [Troubleshooting](../../docs/troubleshooting.md) · [main README](../../README.md)
