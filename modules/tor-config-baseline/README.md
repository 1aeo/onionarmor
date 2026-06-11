# tor-config-baseline

**Enforce a conservative config baseline on every tor instance's `torrc`:
offline master key, a short signing-key lifetime, loopback-only Metrics/Control
ports, cookie auth for an unauthenticated control port, and disabled relay
statistics — editing each `torrc` in place (with a backup) and reloading the
instance.**

It maps to the onionauditor **`tor-config`** category. Discovery mirrors
`kernel-reserved-ports`: every `*/torrc` under `$ONIONARMOR_TCB_INSTANCES_DIR`
(default `/etc/tor/instances`) plus a single `$ONIONARMOR_TCB_TORRC` (default
`/etc/tor/torrc`).

## Risk

**Medium — recommended-OFF by default.** This module mutates `torrc` and reloads
tor, and it sets `OfflineMasterKey 1`, which has real operational consequences:
the relay's signing key must be rotated and the ed25519 **master identity key
taken offline**. A bad edit can also lock you out of the control port or fail the
reload. Two protections apply:

1. **A `--confirm-offline-master-key` gate** — apply refuses to mutate without it
   (outside `--dry-run`).
2. **A 5-minute auto-revert safety latch** (shared `lib/safety_latch.sh`) — armed
   *before* any edit, so a broken `torrc` is automatically rolled back unless you
   confirm health and cancel it in time.

## Quick start

```sh
# Preview every per-instance change first (no host changes):
sudo onionarmor apply --module tor-config-baseline --dry-run

# Apply (REQUIRES the confirm flag; arms the auto-revert latch):
sudo onionarmor apply --module tor-config-baseline --confirm-offline-master-key

# ... confirm tor is healthy, THEN cancel the latch within 5 minutes:
sudo onionarmor apply --module tor-config-baseline --cancel-safety-latch

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module tor-config-baseline

# Undo (restore each torrc from backup + reload):
sudo onionarmor revert --module tor-config-baseline
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | off | Print, per instance, the plan of what would change. Changes nothing; exits 0. |
| `--confirm-offline-master-key` | off | **Required to mutate.** Without it (and not in `--dry-run`), apply dies with an explanation of the `OfflineMasterKey` impact. |
| `--no-safety-latch` | latch on | Skip the auto-revert latch (console access required — a broken edit will NOT be rolled back). |
| `--cancel-safety-latch` | — | Cancel a pending auto-revert latch and exit. |
| `--latch-minutes <N>` | 5 | Auto-revert delay in minutes. |
| `-h`, `--help` | — | Module help. |

## Managed settings

Enforced on every discovered `torrc` (added if missing, corrected if wrong):

| Setting | Value | Why |
|---|---|---|
| `OfflineMasterKey` | `1` | Keep the ed25519 master identity key offline; only a short-lived signing key lives on the host. |
| `SigningKeyLifetime` | `60 days` | Bound the blast radius of a stolen signing key. |
| `MetricsPort` | `127.0.0.1:auto` | Bind metrics to loopback only — **preserves** any existing localhost MetricsPort. |
| `ControlPort` | `127.0.0.1:auto` | Bind the control port to loopback only — **preserves** any existing localhost ControlPort. |
| `CookieAuthentication` + `CookieAuthFile` | `1` / `/var/run/tor/control.authcookie` | Added **only** when a `ControlPort` is set with no `CookieAuthentication` and no `HashedControlPassword`. |
| `DirReqStatistics` | `0` | Stop publishing directory-request statistics. |
| `ConnDirectionStatistics` | `0` | Stop publishing connection-direction statistics. |
| `ExtraInfoStatistics` | `0` | Stop publishing extra-info statistics. |

For `MetricsPort`/`ControlPort`, an existing binding to `127.x` / `::1` / a bare
port / `auto` is treated as a localhost listener and left untouched; the
`127.0.0.1:auto` line is added only when none is present.

## What it does

1. Discovers every instance `torrc` and a top-level `torrc`.
2. `--dry-run` prints a per-instance `add`/`set` plan and exits — no changes.
3. Otherwise, requires `--confirm-offline-master-key`, then **backs up every
   `torrc`** to `$ONIONARMOR_TCB_STATE_DIR/backups/`, renders a restore script,
   and **arms the auto-revert latch** (unless `--no-safety-latch`). If arming
   fails, it dies *before* editing anything.
4. Rewrites each `torrc` with `awk` to a temp file + `mv` (portable in-place
   edit): enforced keys are corrected/appended; the special Metrics/Control/cookie
   directives are appended only when absent. Idempotent — a re-apply with no
   change rewrites nothing.
5. Reloads each changed instance via `systemctl reload tor@<inst>`.

## Safety latch (auto-revert)

Before editing, the module stages a restore script (`cp` each backup back +
`systemctl reload tor@<inst>`) and schedules it via `at now + N min`. After
applying it prints the cancel commands, e.g.:

```text
*** AUTO-REVERT SAFETY LATCH ACTIVE — torrc edits will be rolled back in 5 minutes. ***
    atrm <jobid>
    onionarmor apply --module tor-config-baseline --cancel-safety-latch
```

Confirm every instance is healthy (control port reachable, reload clean), then
cancel within N minutes. If you do **not** cancel, each `torrc` is restored from
backup and reloaded automatically. `audit` reports a pending latch as a yellow
caution. `revert` cancels any pending latch first.

## Preserved settings

These operator lines are **never modified or removed** — they pass through the
rewriter verbatim:

`ContactInfo` · `MyFamily` · `FamilyId` · `ExitRelay` · `SocksPort`

## Threat model

Narrows what a compromised relay host exposes and what a stolen key buys an
attacker: the master identity key is kept offline (`OfflineMasterKey`) and the
on-host signing key is short-lived (`SigningKeyLifetime`), so key theft is
time-bounded and the relay's long-term identity survives. Binding `MetricsPort`
and `ControlPort` to loopback keeps them off the public internet, and cookie auth
closes an **unauthenticated control port** — the single most dangerous tor
misconfiguration (full relay control to anyone who can reach the port). Disabling
`DirReq`/`ConnDirection`/`ExtraInfo` statistics reduces the relay's published
metadata footprint. It does **not** manage the operator's identity, exit, or
family policy (those are preserved), and it is not a substitute for host firewall
(`firewall-default-deny`) or kernel hardening.

## Tests

`tests/bats/` drives apply→audit→revert against a sandbox `/etc/tor/instances`
tree with a stub `systemctl` (records each `reload tor@<inst>`) and `at`/`atrm`
stubs — fully offline, never touches real tor. Coverage (36 tests): the
`--confirm-offline-master-key` gate (refuse + no edits without it); enforced
settings added/corrected; an existing localhost MetricsPort preserved (not
duplicated); cookie auth added to an unauthenticated ControlPort but not to an
authenticated one; `ContactInfo`/`MyFamily`/`FamilyId`/`ExitRelay`/`SocksPort`
untouched; idempotency; per-instance reload; latch armed (jobid + staged
`restore.sh` + printed cancel cmd); `--no-safety-latch`; `--cancel-safety-latch`;
latch-arm-failure aborting before any edit; `--dry-run` changing nothing;
multi-instance + top-level torrc; audit RED→GREEN with the latch caution; revert
restore + round-trip; and audit-log lines.
