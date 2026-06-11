#!/usr/bin/env bash
# revert.sh — "undo" the package-minimization posture. You CANNOT un-purge a
# package: the bits are gone. The honest best-effort revert is to print the exact
# `apt-get install <list>` the operator can run to reinstall whatever this module
# removed, reading that list from the module's state dir (written at apply time).
#
# This script makes NO host changes by itself — it prints the reinstall command
# and explains that removal is not auto-reversible.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pkg_parse_flags "$@"

state=$(pkg_state_file)

audit_log pkg.revert.start "state=$state"

# ---------------------------------------------------------------------------
# No record of a removal -> nothing to reinstall.
# ---------------------------------------------------------------------------
if [ ! -s "$state" ]; then
  audit_log pkg.revert.done "removed=0"
  cat <<EOF

[package-minimization] revert.
  No removal on record ($state is absent/empty) — nothing to reinstall.

If you removed packages by hand, reinstall them with:
  sudo $ONIONARMOR_PKG_APT install -y <package> ...
EOF
  exit 0
fi

removed=$(grep . "$state" | sort -u)
removed_count=$(printf '%s\n' "$removed" | grep -c . || true)
install_cmd="$ONIONARMOR_PKG_APT install -y $(printf '%s\n' "$removed" | tr '\n' ' ')"
# Collapse any double spaces the trailing newline-to-space conversion introduced.
install_cmd=$(printf '%s' "$install_cmd" | tr -s ' ')

audit_log pkg.revert.done "removed=$removed_count state=$state"

cat <<EOF

[package-minimization] revert (best-effort — removal is NOT auto-reversible).

This module purged the following $removed_count package(s) (recorded at apply
time in $state):

$(printf '%s\n' "$removed" | sed 's/^/  - /')

A purge deletes the package and its config; it cannot be auto-reversed. To
reinstall the exact set above, run:

  sudo $install_cmd

After reinstalling, you may also want to clear the removal record so a future
audit/revert no longer treats these as previously-removed:

  rm -f $state
EOF
