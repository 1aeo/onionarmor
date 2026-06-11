# package-minimization

**Purge build/debug/network-analysis tools that have no place on a hardened Tor
relay — compilers, debuggers, packet sniffers, tracers. Each expands the local
attack surface and aids post-exploitation; this module removes the installed
ones (only on the operator's explicit `--confirm`).**

It maps to the onionauditor **`package-hygiene`** category.

## Risk

**Low**, but **recommended-OFF by default**. Removal is destructive (a `purge`
deletes the package and its config) and cannot be auto-reversed, so apply
**refuses** to remove anything without `--confirm`. No safety latch is needed —
nothing here can lock you out or drop a tor listener; the worst case is having
to `apt-get install` a tool back. A host whose declared role is `build-host`
legitimately needs these toolchains, so the module **skips** it entirely there.

## Quick start

```sh
# Preview what would be removed + the reclaimable space (no host changes):
sudo onionarmor apply --module package-minimization --dry-run

# Actually purge the installed removable tools (required confirm):
sudo onionarmor apply --module package-minimization --confirm

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module package-minimization

# Print the exact reinstall command for whatever was removed:
onionarmor revert --module package-minimization
```

A bare `apply` with neither `--dry-run` nor `--confirm` **refuses** and removes
nothing, so packages can never be stripped silently.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | off | List the installed removable packages and the disk space (KiB/MiB) that would be reclaimed. Changes nothing. Exits 0. |
| `--confirm` | off | Actually `apt-get purge -y` the present removable packages and record them for revert. Without this (and without `--dry-run`) apply refuses. |
| `-h`, `--help` | — | Module help. |

## Removed packages

The default removable set (override with `ONIONARMOR_PKG_REMOVE_LIST`):

| Package(s) | Why it has no place on a relay |
|---|---|
| `gcc` `g++` `make` `cmake` `build-essential` | A toolchain lets an attacker compile a rootkit/exploit in place. |
| `gdb` | Attach to and inspect/patch a running `tor` process. |
| `strace` `ltrace` | Trace syscalls/library calls of `tor` — secrets, descriptors. |
| `tcpdump` | Sniff local traffic (deanonymisation aid). |
| `nc` `netcat-openbsd` `netcat-traditional` | Ad-hoc reverse shells / data exfil. |
| `python3-dev` | Pulls headers/toolchain for building native modules. |

Only packages that are **actually installed** are ever touched — detected via
`dpkg-query`. The four **critical** post-exploitation tools (`gcc`, `gdb`,
`tcpdump`, `strace`) drive the audit's RED verdict; the rest are YELLOW.

## What it does

1. Queries `dpkg-query` for which of the removable set is installed (read-only).
2. `--dry-run` prints that present subset and a reclaim estimate (summed
   `${Installed-Size}` in KiB) and exits — no changes.
3. With `--confirm` (and not on a `build-host`), `apt-get purge -y` the present
   subset in one call, then records the removed names to
   `/var/lib/onionarmor/package-minimization/removed.list` so revert can quote
   them back. Idempotent: a re-run finds nothing left and is a clean no-op.

### Role skip

If `/etc/onionarmor/role.conf` declares `role=build-host` (the skip role is
overridable via `ONIONARMOR_PKG_SKIP_ROLE`), apply prints a skip message and
removes nothing, and audit reports a single **yellow "skipped (build-host
role)"** rather than flagging the toolchains — a build host is supposed to have
them.

### Audit meaning

- **GREEN** — none of the removable packages are installed.
- **YELLOW** — only non-critical removables are present (e.g. `make`, `cmake`),
  or the host is a `build-host` (intentional skip). Exit 0.
- **RED** — a critical post-exploitation tool (`gcc`/`gdb`/`tcpdump`/`strace`)
  is still installed. Exit 1.

Audit also prints the total reclaimable size. It is strictly read-only.

## Reinstall / revert note

You **cannot** un-purge a package — the bits are gone. `revert` is therefore
best-effort and honest: it makes **no** host changes itself and instead prints
the exact `apt-get install -y <list>` command to reinstall whatever this module
recorded removing (read from `removed.list`), then explains that purge is not
auto-reversible. With no removal on record it says so and exits clean.

## Threat model

Shrinks the **post-exploitation** surface available to an attacker who has
already obtained a (possibly unprivileged) shell on the relay: no in-place
compiler to build a rootkit, no `gdb` to attach to `tor`, no `strace`/`ltrace`
to lift secrets or descriptors from the running process, no `tcpdump` to sniff
traffic for deanonymisation, no `netcat` for ad-hoc reverse shells or exfil. It
does **not** prevent initial compromise and is not a substitute for the
kernel/MAC/network modules — it removes convenient tooling, complementing them.

## Tests

`tests/bats/` drives apply→audit→revert against a stub `dpkg-query` (a
controllable installed set + per-package KiB sizes) and a stub `apt-get` (records
purge/install args, never touches the host), with a sandboxed
`ONIONARMOR_ETC_DIR` role file and state dir. Coverage (27 tests): `bash -n`;
dry-run lists present removables + reclaim estimate and changes/purges nothing;
a bare apply without `--confirm` refuses (no purge, no state); `--confirm` purges
exactly the installed removables (asserting the apt args), ignores non-removable
and not-installed packages, and records the removed set; idempotent re-run;
`build-host` role skips (no purge) in apply and reports yellow in audit; audit
RED on critical tools / GREEN when none / YELLOW on non-critical; revert prints
the reinstall command from recorded state and stays read-only; the
apply→audit-green→revert round trip; and the audit-log lines.
