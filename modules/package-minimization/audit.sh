#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the package-minimization posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# Checks (read-only via the overridable dpkg-query):
#   - On a build-host role: a single yellow "skipped" line (toolchains are
#     expected there); audit never goes red.
#   - Otherwise: list each removable package that is still installed. A
#     "critical" debug tool still present (gcc/gdb/tcpdump/strace) -> RED; any
#     other removable still present -> YELLOW. None present -> GREEN.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pkg_parse_flags "$@"

info "package-minimization audit"
printf '\n'

# --- build-host role: report the intentional skip, never go red -----------
skip=$(pkg_skip_role)
if [ -n "$skip" ]; then
  oa_status_check yellow "role skip" "host role is '$skip' — package removal skipped (build host needs toolchains)"
  oa_status_summary "n/a"
fi

present=$(pkg_present_list)
present_count=$(printf '%s\n' "$present" | grep -c . || true)

# --- per-package presence -------------------------------------------------
# NB: read from a here-doc, NOT a pipe — `oa_status_check` mutates the shared
# `_oa_status_worst` accumulator, which a pipeline subshell would discard.
if [ "$present_count" -eq 0 ]; then
  oa_status_check green "removable packages" "none installed — host is minimal"
else
  while read -r p; do
    [ -n "$p" ] || continue
    sz=$(pkg_human_kib "$(pkg_installed_size_kib "$p")")
    if pkg_is_crit "$p"; then
      oa_status_check red "$p" "INSTALLED ($sz) — critical post-exploitation tool, purge it"
    else
      oa_status_check yellow "$p" "installed ($sz) — removable build/debug tool"
    fi
  done <<EOF
$present
EOF
fi

# --- reclaimable total (informational) ------------------------------------
if [ "$present_count" -gt 0 ]; then
  reclaim_kib=$(printf '%s\n' "$present" | pkg_reclaim_kib)
  info "reclaimable: $(pkg_human_kib "$reclaim_kib") across $present_count package(s) — run: onionarmor apply --module package-minimization --confirm"
fi

oa_status_summary "one or more critical post-exploitation tools are still installed — purge them"
