#!/usr/bin/env bash
# revert.sh — reinstall the build/debug toolchain that apply removed, restoring
# the prior state. Reads the recorded set from removed.list and reinstalls it via
# apt. Best-effort; clears the list on success. An empty/missing list is a clean
# no-op.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pm_parse_flags "$@"

removed_path=$(pm_removed_path)

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${PM_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header package-minimization revert
  if [ -f "$removed_path" ]; then
    pkgs=$(tr '\n' ' ' < "$removed_path" | tr -s ' ' | sed 's/^ *//;s/ *$//')
    if [ -n "$pkgs" ]; then
      if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
        # SKIP_RELOAD: apt is not invoked, so nothing is reinstalled and the
        # recorded set is kept (matches the live revert).
        oa_would "(SKIP_RELOAD) not invoke apt — would reinstall: $pkgs"
        oa_would "keep recorded set $removed_path (no apt run)"
      else
        oa_would "reinstall via '$ONIONARMOR_PM_APT install -y': $pkgs"
        oa_would "clear recorded set $removed_path (on successful reinstall)"
      fi
    else
      oa_would "nothing to reinstall — removed.list is empty ($removed_path)"
    fi
  else
    oa_would "nothing to reinstall — no recorded removals at $removed_path"
  fi
  exit 0
fi

audit_log pm.revert.start "list=$removed_path"

# ---------------------------------------------------------------------------
# Nothing recorded => nothing to reinstall.
# ---------------------------------------------------------------------------
if [ ! -f "$removed_path" ]; then
  info "package-minimization: no removed.list at $removed_path — nothing to reinstall"
  audit_log pm.revert.done "reinstalled=0 reason=no-state"
  printf '\n[package-minimization] reverted: nothing to do (no recorded removals).\n'
  exit 0
fi

pkgs=$(tr '\n' ' ' < "$removed_path" | tr -s ' ' | sed 's/^ *//;s/ *$//')
if [ -z "$pkgs" ]; then
  info "package-minimization: removed.list is empty — nothing to reinstall"
  rm -f "$removed_path" 2>/dev/null || true
  audit_log pm.revert.done "reinstalled=0 reason=empty-list"
  printf '\n[package-minimization] reverted: nothing to do (empty removed.list).\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# Reinstall via a single apt-get call. Honour ONIONARMOR_SKIP_RELOAD=yes to mean
# "do not actually invoke apt" (symmetric with apply).
# ---------------------------------------------------------------------------
reinstall_ok=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes: not invoking apt — would reinstall: $pkgs"
  reinstall_ok=1
else
  # shellcheck disable=SC2086  # $pkgs is a deliberate multi-package arg list
  if "$ONIONARMOR_PM_APT" install -y $pkgs; then
    reinstall_ok=1
    audit_log pm.revert.install "packages=$pkgs"
    info "reinstalled: $pkgs"
  else
    warn "apt-get install returned nonzero reinstalling: $pkgs — keeping removed.list for retry"
    audit_log pm.revert.fail "stage=install packages=$pkgs"
  fi
fi

# ---------------------------------------------------------------------------
# Clear the recorded set on success so a re-run is a clean no-op.
# ---------------------------------------------------------------------------
if [ "$reinstall_ok" -eq 1 ]; then
  if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
    info "removed.list kept (SKIP_RELOAD: no apt run, nothing actually reinstalled): $removed_path"
  else
    rm -f "$removed_path" 2>/dev/null \
      && audit_log pm.revert.clear "removed=$removed_path" \
      || warn "could not remove $removed_path"
  fi
fi

revert_failed=0
[ "$reinstall_ok" -eq 1 ] || revert_failed=1
audit_log pm.revert.done "ok=$([ "$revert_failed" -eq 0 ] && echo 1 || echo 0) packages=$pkgs"

cat <<EOF

[package-minimization] reverted.
  reinstall : $([ "$reinstall_ok" -eq 1 ] && echo "$pkgs" || echo "FAILED — removed.list kept for retry")
  list      : $([ "$reinstall_ok" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ] && echo "cleared ($removed_path)" || echo "kept ($removed_path)")
EOF

[ "$revert_failed" -eq 0 ] || { warn "revert did not reinstall every package — re-run revert"; exit 1; }
