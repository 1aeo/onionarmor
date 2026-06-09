# Module: `systemd-hardening`

**Drop a systemd sandbox over the relay's service units — and auto-revert any unit that won't restart under it.**

`systemd-hardening` writes a `99-onionarmor-hardening.conf` `[Service]` drop-in
for each present relay unit — `tor@*.service`, `onionwarden.service`,
`onionleak-collector.service`, `onionleak-analyzer.service` — applying
`NoNewPrivileges`, `ProtectSystem=strict`, the kernel/cgroup/namespace
protections, a **minimal per-unit `CapabilityBoundingSet`**, and a **scoped
`ReadWritePaths`**. It then `daemon-reload`s and restarts only the affected
units.

> **Safety net.** After restarting each unit, apply polls `systemctl is-active`
> for up to **30s**. If the unit does not come up — the classic symptom of a
> `ReadWritePaths=` that is one directory too tight — apply **removes that unit's
> drop-in, reloads and restarts it**, and exits non-zero. A bad scoping decision
> can never leave a service down. See [Safety / auto-revert](#safety--auto-revert).

## Quick start

```sh
# Preview the units + every rendered drop-in — changes nothing:
sudo onionarmor apply --module systemd-hardening --dry-run

# Apply (writes drop-ins, restarts affected units, auto-reverts on failure):
sudo onionarmor apply --module systemd-hardening

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module systemd-hardening

# Undo (remove all drop-ins, reload, restart unsandboxed):
sudo onionarmor revert --module systemd-hardening
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--units <csv>` | autodetect | Harden exactly these units, skipping detection. e.g. `--units tor@0.service,onionwarden.service`. |
| `--no-restart` | off | Write drop-ins but do **not** `daemon-reload`/restart. **Disables the auto-revert safety net** — you restart and verify yourself. |
| `--dry-run` | off | Print the plan + every rendered drop-in. Changes nothing. |

### Unit detection

- **`tor@<inst>.service`** — every enabled instance found as a wants-symlink
  under `multi-user.target.wants` / `tor.target.wants`.
- **`onionwarden` / `onionleak-collector` / `onionleak-analyzer`** — included
  when a unit file for them exists.

A host with only some of these gets drop-ins only for what it actually runs.

## The hardening posture

Every managed unit gets the common directives:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native
```

Plus a **per-unit** capability set and writable-path scope:

| Unit class | `CapabilityBoundingSet=` | `ReadWritePaths=` (default) |
|---|---|---|
| `tor@*` | `CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE` | `/var/lib/tor /var/lib/tor-instances /run/tor /run/tor-instances /var/log/tor` |
| `onionwarden` | *(empty — drop all)* | `/var/lib/onionwarden /run/onionwarden /var/log/onionwarden` |
| `onionleak-collector` | `CAP_NET_RAW CAP_NET_ADMIN` | `/var/lib/onionleak /run/onionleak /var/log/onionleak` |
| `onionleak-analyzer` | *(empty — drop all)* | `/var/lib/onionleak /var/log/onionleak` |

Every capability set and path list is **overridable via environment variables**
(e.g. `ONIONARMOR_SH_TOR_RWPATHS`, `ONIONARMOR_SH_ONIONWARDEN_CAPS`) so an
operator can tune the scope without editing the module — see `lib.sh`.

> ### Open questions (need confirmation against the real units)
>
> The `ReadWritePaths=` defaults and `onionwarden`'s capability set are
> **conservative guesses** made without the real unit files in hand:
>
> - **tor instances** — confirm the actual `DataDirectory` / `PidFile` /
>   `ControlSocket` / `CacheDirectory` layout. If instances live under
>   `/var/lib/tor-instances/<name>`, the default covers it; bespoke layouts need
>   `ONIONARMOR_SH_TOR_RWPATHS` set.
> - **`onionwarden`** — does it need `CAP_NET_RAW` (raw sockets / pings) or no
>   capabilities at all? Default is **drop all**; widen via
>   `ONIONARMOR_SH_ONIONWARDEN_CAPS` if it fails to start (the safety net will
>   catch that and auto-revert in the meantime).
> - **onionleak** — confirm the collector/analyzer state + log dirs and whether
>   `MemoryDenyWriteExecute=yes` is compatible (JIT-using runtimes need it off).
>
> Until confirmed, roll out with the safety net **on** (the default) so a wrong
> guess self-heals.

## Safety / auto-revert

`apply` restarts each changed unit and waits up to
`ONIONARMOR_SH_RESTART_TIMEOUT` (default 30) seconds for `is-active`. On failure:

1. it removes **that unit's** drop-in,
2. `daemon-reload`s and restarts the unit,
3. logs `sh.apply.autorevert` and continues with the other units,
4. exits **2** so CI / the operator sees that some units could not be hardened.

The other units keep their (working) drop-ins — one unit's bad scope does not
roll back the whole fleet posture. A unit that will not even come back **without**
the drop-in is surfaced loudly for manual intervention.

`--no-restart` skips all of this by design: the drop-ins are written but inert,
and you own restarting + verifying them.

## What `audit` checks

Per present unit, read-only; exits non-zero if any check is **red**:

1. **drop-in present** — `…/<unit>.d/99-onionarmor-hardening.conf` exists, is
   onionarmor-managed, and matches the rendered posture (a `sha256` is shown).
   Red on missing / drifted / foreign.
2. **effective directives** — `systemctl show <unit>` confirms the key
   protections are actually in force (`NoNewPrivileges=yes`,
   `ProtectSystem=strict`, `ProtectHome=yes`, `ProtectKernelTunables/Modules`,
   `RestrictNamespaces`, `MemoryDenyWriteExecute`).
3. **CapabilityBoundingSet** — the effective value is reported against the policy.

## Revert

`revert` scans the drop-in root for our managed drop-ins (so it cleans up even
units that are no longer autodetected — e.g. a since-disabled tor instance),
removes each, `daemon-reload`s, and restarts the affected units unsandboxed. A
foreign drop-in of the same name is left untouched.

## Threat model

**What this defends:** blast radius after a service compromise. If `tor`,
`onionwarden`, or an onionleak daemon is exploited, the sandbox denies the
attacker the easy next steps — no new privileges, a read-only filesystem outside
a tiny writable scope, no kernel-tunable/module tampering, no raw access to
devices or other namespaces, and a capability set trimmed to what the daemon
actually needs.

**Why per-unit scoping:** a blanket policy either breaks daemons (too tight) or
grants too much (too loose). Scoping `CapabilityBoundingSet` / `ReadWritePaths`
per unit gives each the least privilege it can run with — at the cost of needing
the right paths, which is exactly what the auto-revert net de-risks.

**What it does _not_ do:**

- It does **not** replace the units' own `User=`/`Group=` — it layers on top.
- It does **not** apply a `SystemCallFilter=` allow-list (high breakage risk
  without per-binary syscall profiling); only `SystemCallArchitectures=native`.
- It does **not** protect a unit you run with `--no-restart` until you restart it.

## Files this module manages

| Path | Purpose |
|---|---|
| `/etc/systemd/system/<unit>.d/99-onionarmor-hardening.conf` | the managed per-unit sandbox drop-in |
| `/var/lib/onionarmor/systemd-hardening/` | module state dir |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against fixture unit files
and a fake `systemctl`.

## Tests

```sh
bats modules/systemd-hardening/tests/bats/
```

The offline suite uses fixture unit files in
`tests/fixtures/systemd-units/` and a fake `systemctl` (with failure injection)
to cover detection, per-unit caps/paths, idempotency, `--units`, `--no-restart`,
audit (effective-directive checks + drift), revert (discovery + cleanup), and —
critically — both **auto-revert** paths: a unit that recovers once its drop-in is
removed, and a unit that stays down (surfaced for manual fix).

---

**See also:** [Modules overview](../../docs/modules.md) · [Troubleshooting](../../docs/troubleshooting.md) · [main README](../../README.md)
