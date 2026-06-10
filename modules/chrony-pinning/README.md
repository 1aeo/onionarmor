# Module: `chrony-pinning`

**Pin the clock to a geographically + operationally diverse set of stratum-1 NTP sources via chrony — no single time authority can steer the relay alone.**

`chrony-pinning` writes a `sources.d` file pinning **four stratum-1 sources**
across three continents and four independent operators (NIST + USNO in the US,
PTB in the EU, NICT in APAC), plus **two stratum-2 pool-member fallbacks** and a
last-resort `pool.ntp.org`. It sets `makestep`, `rtcsync` and `leapsectz`, and
**masks `systemd-timesyncd`** so only chrony disciplines the clock.

> Accurate, hard-to-steer time is load-bearing for a Tor relay: consensus
> voting, descriptor validity, the `Valid-After`/`Valid-Until` windows, and TLS
> certificate validity all depend on it. An adversary who can skew one upstream
> time source should not be able to skew the relay's clock — source **diversity**
> is the defence. See [Threat model](#threat-model).

## Quick start

```sh
# See exactly what it would do first — changes nothing:
sudo onionarmor apply --module chrony-pinning --dry-run

# Apply (installs chrony if needed, writes sources, masks timesyncd):
sudo onionarmor apply --module chrony-pinning

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module chrony-pinning

# Undo (remove sources, restore systemd-timesyncd, stop chrony):
sudo onionarmor revert --module chrony-pinning
```

## The pinned source set

| Host | Operator | Region | Stratum |
|---|---|---|---|
| `time-a-g.nist.gov` | NIST | US | 1 |
| `tick.usno.navy.mil` | USNO | US | 1 |
| `ptbtime1.ptb.de` | PTB | EU (DE) | 1 |
| `ntp.nict.jp` | NICT | APAC (JP) | 1 |
| `2.pool.ntp.org` | NTP Pool | — | 2 (fallback) |
| `3.pool.ntp.org` | NTP Pool | — | 2 (fallback) |
| `pool pool.ntp.org` | NTP Pool | — | last-resort |

chrony prefers the lowest-stratum, best-measured sources, so the pinned
stratum-1 servers win whenever they are reachable; the stratum-2 and pool
entries only contribute when the pinned set is unreachable. The whole set is
**env-overridable** (`ONIONARMOR_CHR_STRATUM1`, `…_STRATUM2`, `…_POOL`) — see
`lib.sh`.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--no-mask-timesyncd` | mask | Leave `systemd-timesyncd` alone (default: disable + mask it). |
| `--makestep <v>` | `1.0 3` | chrony `makestep` (step the clock for the first N updates if off by > v). |
| `--leapsectz <tz>` | `right/UTC` | Leap-second source timezone. |
| `--offset-ms <n>` | `50` | **audit**: maximum acceptable \|offset\| in ms. |
| `--dry-run` | off | Print the plan + rendered config. Changes nothing. |
| `--verify` / `--no-verify` | verify | Post-apply: chrony active + ≥2 reachable stratum-1. |

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/chrony/sources.d/onionarmor-stratum1.sources` | the pinned `server`/`pool` lines |
| `/etc/chrony/conf.d/onionarmor-stratum1.conf` | `makestep` / `rtcsync` / `leapsectz` directives |
| `/var/lib/onionarmor/chrony-pinning/chrony.conf.orig` | backup of `chrony.conf`, only if apply had to add a `sourcedir`/`confdir` include block |

On a modern chrony (Debian/Ubuntu) `chrony.conf` already has `sourcedir
/etc/chrony/sources.d` and `confdir /etc/chrony/conf.d`. If yours does not, apply
appends a managed include block (backing up `chrony.conf` once) so the files are
actually read.

## What `audit` checks

Read-only; exits non-zero if any check is **red**:

1. **chrony active** — `systemctl is-active` for the chrony service.
2. **sources pinned** — the managed `.sources` file is present and matches the
   posture. (Yellow if managed but customised.)
3. **timesyncd masked** — `systemd-timesyncd` is masked; **red** if it is still
   enabled (a second daemon fighting over the clock). If apply was run with
   `--no-mask-timesyncd`, `audit` reports this check **yellow** (not enforced)
   instead of red — that yellow is expected and requires no operator action.
4. **stratum-1 reachable** — `chronyc -n sources` shows **≥2** reachable
   stratum-1 sources. **Yellow** at exactly 1 (no diversity), **red** at 0.
5. **offset within threshold** — `chronyc tracking`'s last offset is within
   `--offset-ms` (default 50 ms) of true time.

## Revert

`revert` removes the managed sources + conf files, restores `chrony.conf` from
backup if apply edited it, **unmasks + restarts `systemd-timesyncd`**, and stops
+ disables chrony (left installed). After revert the host is back to
`systemd-timesyncd` for time.

## Threat model

**What this defends:** clock-steering attacks and silent single-source drift. If
a relay trusts one upstream (or one country's authority), an attacker who can
MITM or compromise that source can walk the relay's clock — pushing it out of
the consensus validity window (dropping it from the network), or skewing TLS /
descriptor validity. Pinning four independent operators across three continents
means no single source — or single jurisdiction — can move the clock on its own;
chrony's selection rejects a falseticker that disagrees with the majority.

**Why mask `systemd-timesyncd`:** two time daemons disciplining the same clock
fight each other and produce nondeterministic offsets. Exactly one disciplinarian
(chrony) is the precondition for everything above.

**What it does _not_ do:**

- It does **not** enable **NTS** (authenticated NTP) by default — NIST/USNO/PTB
  do not all offer it. Add NTS-capable sources via `ONIONARMOR_CHR_STRATUM1` if
  your threat model needs authenticated time. *(Candidate follow-up.)*
- It does **not** firewall NTP (udp/123) — pair with your egress policy.
- It does **not** fix a broken RTC or a host with no network path to any source.

## Tests

```sh
bats modules/chrony-pinning/tests/bats/
```

The offline suite stubs `systemctl`, `apt-get`, `chronyd`, and a mock `chronyc`
that emits a realistic `-n sources` table and `tracking` block (reachable-source
count and offset controllable via env, using TEST-NET-1 addresses only). It
covers apply (sources/conf, diversity, timesyncd masking, install, the
`sourcedir`/`confdir` include path, idempotency, verify pass/fail), audit
(green/yellow/red + exit codes, offset threshold), and revert (file removal,
`chrony.conf` restore, timesyncd unmask, round-trip).

---

**See also:** [Modules overview](../../docs/modules.md) · [Troubleshooting](../../docs/troubleshooting.md) · [main README](../../README.md)
