# Modules

Beyond the sysctl [roles](roles.md), onionarmor ships **modules** —
self-contained hardening postures you apply with `--module`. Each module is the
same three-verb shape as the rest of the tool: **apply**, **audit**, **revert**.

```sh
onionarmor list-modules                                # discover installed modules
sudo onionarmor apply  --module dns-posture --dry-run  # preview, change nothing
sudo onionarmor apply  --module dns-posture            # apply the posture
onionarmor      audit  --module dns-posture            # green/yellow/red status
sudo onionarmor revert --module dns-posture            # undo it
```

Run `onionarmor apply --module <name> --help` for that module's own flags.

## The module catalog

| Module | What it does | Risk | Needs | Docs |
|---|---|---|---|---|
| `dns-posture` | Local validating DoT resolver (`unbound` + DNSSEC); masks `systemd-resolved`, pins `resolv.conf`. | Medium — replaces the system resolver (clean revert). | `unbound` (auto-installed) | [README](../modules/dns-posture/README.md) |
| `kernel-reserved-ports` | Reserve the relay's loopback tor ports from the kernel ephemeral source-port pool, so an outbound connection can't steal a port tor needs to bind. | Low — one sysctl drop-in, fully reversible. | reads your torrc (`--auto`) | [README](../modules/kernel-reserved-ports/README.md) |
| `bgp-hardening` | Bind FRR `bgpd` to a specific peer-facing IP (not `0.0.0.0`); opt-in `tcp/179` firewall, RPKI, GTSM. | Medium — restarts `bgpd` (graceful, keeps the FIB). | FRR (`/etc/frr`) | [README](../modules/bgp-hardening/README.md) |

Each module's README has its flags, customization examples, threat model, and
the exact files it manages. **Start with the dry-run** — every module prints its
full plan and changes nothing until you drop `--dry-run`.

## How a module works

A module lives under `modules/<name>/` and provides:

```
modules/<name>/
  apply.sh       # apply the posture
  audit.sh       # report green/yellow/red status (read-only)
  revert.sh      # undo it
  lib.sh         # shared helpers (every path + external command env-overridable)
  README.md      # flags, examples, threat model, managed files
  tests/bats/    # offline suite — external commands stubbed
```

The registry is a **directory scan**, not a manifest: a directory is a module
iff it has those three action scripts. `list-modules` reads each module's
one-line description straight from the `# MODULE:` header in `apply.sh`, so there
is no manifest file to drift from the real scripts. See
[`lib/module.sh`](../lib/module.sh) for the dispatch convention.

`apply --module <name>` and the role-based `apply --role <name>` are distinct
paths — `--module` routes to the module, everything else is unchanged. Module
`apply`/`audit`/`revert` all write to the same audit log
(`/var/log/onionarmor/audit.log`) as the role-based commands.

## Reading `audit` output

Every module's `audit` reports each check as **green / yellow / red** and exits
non-zero if **anything is red** — so it drops cleanly into a monitoring cron or
CI gate.

| Colour | Meaning |
|---|---|
| 🟢 green | check passed / posture in place. |
| 🟡 yellow | advisory — not applied, or a non-fatal gap (exit stays `0`). |
| 🔴 red | the posture is broken or drifted (exit non-zero). |

What's green vs yellow vs red is module-specific; each module README has the
exact table. A control that is *opt-in* (e.g. `bgp-hardening`'s firewall) audits
**green when you never enabled it** — absence of an opt-in extra is not a
failure.

## Writing a new module

To add one, create `modules/<name>/` with the four files above and an offline
bats suite. The roadmap (Phase 2) generalizes the same `apply`/`audit`/`revert`
convention to apparmor, systemd-sandbox, and nftables-egress. Conventions to
follow:

- `apply.sh` starts with a `# MODULE: <one-line description>` header (this is
  what `list-modules` prints).
- Make every path and external command overridable via environment variables in
  `lib.sh`, so the bats suite can drive the whole module against a sandbox with
  stub binaries.
- `apply` must be idempotent and support `--dry-run`; `audit` must be read-only;
  `revert` must back up before it removes anything.
- Back every behaviour with an offline bats suite (stub all externals).
