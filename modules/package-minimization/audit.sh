#!/usr/bin/env bash
# audit.sh — green/yellow status of the package-minimization posture. Read-only;
# never changes host state. Findings are advisory: a present toolchain package is
# a yellow ("removable"), not a red. On build-host / ci roles the toolchain is
# retained by design, reported green/info.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pm_parse_flags "$@"

role=$(pm_role)
role_label=${role:-unset}

info "package-minimization audit"
printf '\n'

# ---------------------------------------------------------------------------
# build-host / ci legitimately retain a toolchain — report and stop (green).
# ---------------------------------------------------------------------------
if pm_role_is_skip "$role"; then
  oa_status_check green "toolchain retained" "role=$role_label legitimately needs a toolchain (module skipped)"
  oa_status_summary "package-minimization posture broken"
fi

oa_status_check green "host role" "role=$role_label (toolchain is removable on a relay)"

# ---------------------------------------------------------------------------
# Per-target package: green if absent, yellow advisory if present.
# ---------------------------------------------------------------------------
total_kib=0
present=0
for pkg in $ONIONARMOR_PM_PACKAGES; do
  if pm_pkg_installed "$pkg"; then
    sz=$(pm_pkg_size "$pkg")
    total_kib=$((total_kib + sz))
    present=$((present + 1))
    oa_status_check yellow "package: $pkg" "removable: $pkg ($(pm_human_kib "$sz"))"
  else
    oa_status_check green "package: $pkg" "absent"
  fi
done

if [ "$present" -gt 0 ]; then
  oa_status_check yellow "reclaimable" "$present package(s) removable, total $(pm_human_kib "$total_kib") — apply to remove"
else
  oa_status_check green "reclaimable" "no target build/debug packages installed"
fi

oa_status_summary "package-minimization posture broken"
