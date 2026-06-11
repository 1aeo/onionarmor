# Module: `tor-config-baseline`

**Apply a baseline of safe torrc directives — statistics off, signing-key lifetime pinned, loopback-only Metrics/ControlPort — inside a clearly-delimited managed block on every tor instance, without ever touching operator-domain directives.**

`tor-config-baseline` appends a single bracketed **managed block** to each
instance's `torrc` and keeps it in sync. Everything it sets lives between two
literal markers:

```text
# >>> onionarmor tor-config-baseline (managed) >>>
SigningKeyLifetime 60 days
DirReqStatistics 0
ConnDirectionStatistics 0
ExtraInfoStatistics 0
MetricsPort 127.0.0.1:auto
ControlPort 127.0.0.1:auto
CookieAuthentication 1
CookieAuthFile /var/run/tor/control.authcookie
# <<< onionarmor tor-config-baseline (managed) <<<
```

It **never** edits anything outside that block, so an operator's hand-tuned
directives are left exactly as written. Apply backs up the original `torrc` once,
strips any stale managed block, then re-appends the freshly rendered one; if the
result is byte-identical it reports *already current* and does not reload.

> **Risk: medium.** Opt-in / default-off — run it explicitly. It reloads tor, and
> with `--confirm-offline-master-key` it changes signing-key behaviour (it assumes
> you have generated an offline master key), which is why that directive is gated
> behind an explicit flag.

## Quick start

```sh
# ALWAYS dry-run first — see the rendered block + added-vs-preserved per instance:
sudo onionarmor apply --module tor-config-baseline --dry-run

# Apply (edits each torrc's managed block, reloads each instance):
sudo onionarmor apply --module tor-config-baseline

# Check status (green/yellow/red; advisory findings are yellow):
onionarmor audit --module tor-config-baseline

# Undo (strip the block / restore the pre-apply backup, reload):
sudo onionarmor revert --module tor-config-baseline
```

## Instances

Per-instance trees are preferred: every `$ONIONARMOR_TCB_INSTANCES_DIR/<name>/torrc`
(default `/etc/tor/instances/<name>/torrc`) is managed independently and reloaded
with `systemctl reload tor@<name>`. When no instances directory exists, the module
falls back to the single `$ONIONARMOR_TCB_TORRC` (default `/etc/tor/torrc`) and
reloads the bare `tor` unit.

## What the managed block sets

| Directive | Behaviour |
|---|---|
| `SigningKeyLifetime 60 days` | pinned |
| `DirReqStatistics 0` | always |
| `ConnDirectionStatistics 0` | always |
| `ExtraInfoStatistics 0` | always |
| `MetricsPort 127.0.0.1:auto` | added **only** if the operator has no loopback MetricsPort. An existing loopback bind is preserved (none added); a **non-loopback** operator bind is left untouched and warned (a yellow finding) — we never move an operator's public bind. |
| `ControlPort 127.0.0.1:auto` | same preserve-if-loopback logic as MetricsPort. |
| `CookieAuthentication 1` + `CookieAuthFile …` | added only when a ControlPort is in effect (managed or pre-existing) **and** the torrc has neither `HashedControlPassword` nor `CookieAuthentication 1`. |
| `OfflineMasterKey 1` | emitted **only** with `--confirm-offline-master-key`; otherwise omitted with a one-line note. |

## Never touched (operator domain)

`ContactInfo`, `MyFamily`, `FamilyId`, `ExitRelay`, `SocksPort`, `ORPort`,
`DirPort`, `Nickname`, `Address` — these are left exactly as the operator wrote
them and never appear in the managed block.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--confirm-offline-master-key` | off | Also emit `OfflineMasterKey 1` (assumes an offline master key exists). |
| `--dry-run` | off | Print the rendered block + added-vs-preserved per instance. Changes nothing; never reloads. |
| `--verify` / `--no-verify` | verify | Post-apply: confirm the managed block is present and well-formed. |
| `-h`, `--help` | — | Usage. |

`ONIONARMOR_SKIP_RELOAD=yes` skips all reloads (symmetric in apply and revert).

## What `audit` checks

Read-only; this module's findings are advisory, so missing directives and a
non-loopback Metrics/ControlPort are **yellow**, not red. Per instance: one check
per managed directive (green when set in the block or satisfied by a pre-existing
loopback equivalent), the ControlPort auth posture, and `OfflineMasterKey`
(yellow/info when absent, since it is opt-in).

## Revert

`revert` restores each instance's pre-apply backup byte-for-byte when present,
else strips just the managed block, reloads each changed instance, and clears
module state. Best-effort and idempotent.

## Files this module manages

| Path | Purpose |
|---|---|
| `<instances-dir>/<name>/torrc` (or the single `/etc/tor/torrc`) | the managed block appended at the end |
| `/var/lib/onionarmor/tor-config-baseline/<instance>.torrc.bak` | the one-time pre-apply backup |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against a stub `systemctl`
and sandbox torrc trees, never touching the real host or tor.

## Tests

```sh
bats modules/tor-config-baseline/tests/bats/
```

The offline suite stubs `systemctl` (logging every `reload` call) and seeds
sandbox instance torrc trees, covering: block insertion with the stats/lifetime
directives; loopback MetricsPort preserved (no duplicate); a non-loopback bind
left untouched + warned; CookieAuth added when a ControlPort is in effect with no
auth; `OfflineMasterKey` gated behind `--confirm-offline-master-key`; operator
directives left untouched and outside the block; idempotency; per-instance
reloads; `--dry-run`; `ONIONARMOR_SKIP_RELOAD=yes`; and the apply → audit →
revert cycle restoring the torrc byte-for-byte.

---

**See also:** [Modules overview](../README.md) · [`kernel-reserved-ports`](../kernel-reserved-ports/README.md) · [main README](../../README.md)
