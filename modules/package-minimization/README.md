# Module: `package-minimization`

**Remove the build toolchain + debug tooling from a production relay — smaller attack surface, fully reversible by reinstalling on demand.**

`package-minimization` removes packages a production tor relay does not need at
runtime but that an attacker who lands a shell would love to find: a compiler to
build a rootkit, a debugger to inspect the process, a packet sniffer to read
traffic. Removing them shrinks the post-exploitation surface. Everything it
removes is reinstallable with one `revert`, so the posture is reversible.

**Risk: low. DEFAULT-ON** — recommended on by default for production relays;
**skipped automatically on `build-host` / `ci` roles** (which legitimately need a
toolchain). The interactive confirmation prompt is the safety rail before any
removal.

## Target package set

```
gcc g++ make cmake build-essential
tcpdump nc netcat-openbsd netcat-traditional
strace ltrace gdb
python3-dev
```

Only the packages **actually installed** are removed; the rest are ignored. The
exact set is overridable via `ONIONARMOR_PM_PACKAGES`.

## Quick start

```sh
# ALWAYS dry-run first — see what would be removed + the reclaimable size:
sudo onionarmor apply --module package-minimization --dry-run

# Apply (prompts for confirmation before removing):
sudo onionarmor apply --module package-minimization
#   ...or skip the prompt:
sudo onionarmor apply --module package-minimization --yes

# Check status (advisory green/yellow; never red):
onionarmor audit --module package-minimization

# Undo — reinstall exactly what was removed:
sudo onionarmor revert --module package-minimization
```

## Role gating

The host role is read from the `role=` line in `/etc/onionarmor/role.conf`
(overridable via `ONIONARMOR_PM_ROLE_FILE`):

| Role | Behaviour |
|---|---|
| `build-host`, `ci` | **SKIP** — these legitimately need a toolchain; nothing is removed, exit 0. |
| `relay-mid`, `relay-guard`, `relay-exit` | **proceed** — the toolchain is removable on a relay. |
| unset / other | **proceed** — same as a relay. |

The detected role is stated in every command's output.

## Flags (`apply`)

| Flag | Default | Meaning |
|---|---|---|
| `--yes`, `--assume-yes` | prompt | Skip the interactive confirmation. |
| `--dry-run` | off | Print the removable packages + reclaimable size. Changes nothing. |
| `--verify` / `--no-verify` | verify | Post-apply: re-query each removed package is gone (exit 2 if any survive). |

## What `audit` checks

Read-only; findings are **advisory** (this module produces no reds):

1. **host role** — the detected role (green), or **toolchain retained** (green)
   on `build-host` / `ci`.
2. **per package** — green if absent, **yellow** "removable: `<pkg>` (`<size>`)"
   if present.
3. **reclaimable** — total size of the removable packages.

It ends with the shared green/yellow verdict (exit 0).

## Revert

`revert` reinstalls the exact set recorded at apply time (from
`removed.list`) via `apt-get install -y`, then clears the list on success. An
empty or missing list is a clean no-op.

## `ONIONARMOR_SKIP_RELOAD`

`ONIONARMOR_SKIP_RELOAD=yes` means **do not actually invoke apt** — symmetric in
apply and revert. `apply` still computes the removable set and records it;
`revert` reports what it would reinstall. Useful for staging / inspection.

## Files this module manages

| Path | Purpose |
|---|---|
| Installed packages (via `apt-get`) | the removed / reinstalled toolchain |
| `/var/lib/onionarmor/package-minimization/removed.list` | the recorded removed set, for `revert` |

Every path and external command is overridable via environment variables (see
`lib.sh`) so the bats suite drives the whole module against stub `dpkg-query` /
`apt-get`, never touching the real host.

## Coordination with other modules

Independent of the network/kernel posture modules — it touches the installed
package set only, not listeners, sysctl, or firewall rules.

## Tests

```sh
bats modules/package-minimization/tests/bats/
```

The offline suite stubs `dpkg-query` and `apt-get` against a fake
installed-package DB in a sandbox, covering: removal of installed targets +
`removed.list` recording; `build-host` / `ci` skip; `--dry-run` (no changes);
the default-no confirm abort; nothing-installed and idempotent re-runs; the
`SKIP_RELOAD` plan-only path; audit advisory yellows / all-green / retained; and
the apply → revert reinstall cycle.

---

**See also:** [Modules overview](../README.md) · [`firewall-default-deny`](../firewall-default-deny/README.md) · [`kernel-reserved-ports`](../kernel-reserved-ports/README.md)
