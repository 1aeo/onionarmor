# onionarmor modules

A **module** is a self-contained hardening posture under `modules/<name>/`. The
registry is a plain directory scan (see `lib/module.sh`): a directory is a valid
module **iff** it contains `apply.sh`, `audit.sh`, and `revert.sh`. No manifest,
no YAML.

```text
modules/<name>/
  apply.sh          # apply the posture (must support --dry-run); first
                    #   `# MODULE: <text>` comment is the list-modules description
  audit.sh          # green/yellow/red status; exits non-zero if any check is red
  revert.sh         # undo the posture, restoring prior state
  lib.sh            # shared helpers sourced by all three actions
  README.md         # flags, examples, threat model
  tests/bats/       # module bats suite (self-contained, offline)
```

Operators drive every module through the same CLI dispatch:

```sh
onionarmor apply  --module <name> [module opts]
onionarmor audit  --module <name> [module opts]
onionarmor revert --module <name> [module opts]
onionarmor list-modules
```

## The skeleton

Every action script bootstraps identically:

```bash
#!/usr/bin/env bash
# MODULE: one-line description (apply.sh only).
set -euo pipefail
_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"
<name>_parse_flags "$@"
```

`lib.sh` locates and sources the repo's `lib/common.sh`, then defines the
module's overridable commands/paths, flag defaults, `<name>_parse_flags`, and
render helpers. EVERY external command and filesystem path must be env-var
overridable so the bats suite drives the module against a sandbox with stub
binaries, never touching the real host.

## Shared helpers (from `lib/common.sh`)

Reuse these instead of re-implementing them per module:

- `info` / `warn` / `die` — stdout / stderr / stderr+exit logging.
- `audit_log <action> <details>` — append a tab-separated audit line.
- `audit_fail_die` / `audit_fail_warn` — log a `.fail` then die / warn.
- `oa_status_check <green|yellow|red> <label> <detail>` — one audit status line.
- `oa_status_summary "<red message>"` — print the verdict and exit (0 for
  green/yellow, 1 if any check was red). Call once at the end of `audit.sh`.
- `oa_write_if_changed <path> <content>` — atomic write-if-different; returns 0
  when written, 1 when already current (use as an `if` condition under `set -e`).
- `<name>_need_val "$1" "$#"` — guard a value-taking flag's `shift 2`; define a
  thin per-module wrapper so the error names your module (see existing modules).

## Lifecycle policy

- **apply** is idempotent and supports `--dry-run`; it backs up any file it
  replaces and fails closed on a mandatory step, exiting non-zero on verify
  problems.
- **audit** is read-only — it never mutates host state.
- **revert** is best-effort: it restores backups, keeps ownership markers when a
  step fails so a re-run retries, and summarises what it did.
- `ONIONARMOR_SKIP_RELOAD=yes` must leave the live kernel/services untouched
  (symmetric in apply and revert).
