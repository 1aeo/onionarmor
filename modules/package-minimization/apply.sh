#!/usr/bin/env bash
# MODULE: package minimization — remove the build toolchain + debug tooling (gcc/make/cmake, tcpdump/nc, strace/gdb, python3-dev) from a production relay; reversible via reinstall.
#
# apply.sh — remove the target build/debug toolchain from a production relay to
# shrink the attack surface. Records the removed set for revert. Idempotent;
# --dry-run plans only; prompts before removing (destructive-ish). Skipped on
# build-host / ci roles, which legitimately need a toolchain.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pm_parse_flags "$@"

role=$(pm_role)
role_label=${role:-unset}

# ---------------------------------------------------------------------------
# Role gating: build-host / ci legitimately need a toolchain — SKIP cleanly.
# ---------------------------------------------------------------------------
if pm_role_is_skip "$role"; then
  audit_log pm.apply.skip "role=$role_label reason=toolchain-required"
  info "package-minimization: role=$role_label legitimately needs a toolchain — skipping (no packages removed)"
  exit 0
fi

audit_log pm.apply.start "role=$role_label packages=$(printf '%s' "$ONIONARMOR_PM_PACKAGES" | tr -s ' ')"

# ---------------------------------------------------------------------------
# Compute the removable set (installed TARGET packages) + total bytes saved.
# ---------------------------------------------------------------------------
installed=$(pm_installed_targets)

if [ -z "$installed" ]; then
  info "package-minimization: none of the target build/debug packages are installed — nothing to remove (role=$role_label)"
  audit_log pm.apply.done "removed=0 role=$role_label"
  printf '\n[package-minimization] nothing to remove (role=%s).\n' "$role_label"
  exit 0
fi

pkgs=""
total_kib=0
while IFS=' ' read -r pkg sz; do
  [ -n "$pkg" ] || continue
  pkgs="$pkgs $pkg"
  total_kib=$((total_kib + sz))
done <<EOF
$installed
EOF
pkgs=$(printf '%s' "$pkgs" | tr -s ' ' | sed 's/^ *//;s/ *$//')

# ---------------------------------------------------------------------------
# Dry run: print the plan, change nothing.
# ---------------------------------------------------------------------------
if [ "$PM_DRY_RUN" -eq 1 ]; then
  info "dry-run: package-minimization (no host changes, role=$role_label)"
  printf '\nPLAN (apt-get remove)\n'
  printf '  role             -> %s\n' "$role_label"
  while IFS=' ' read -r pkg sz; do
    [ -n "$pkg" ] || continue
    printf '  remove %-20s %s\n' "$pkg" "$(pm_human_kib "$sz")"
  done <<EOF
$installed
EOF
  printf '  ----\n'
  printf '  total reclaimable -> %s\n' "$(pm_human_kib "$total_kib")"
  exit 0
fi

# ---------------------------------------------------------------------------
# Confirm before removing (destructive-ish). --yes / ONIONARMOR_AUTO_CONFIRM=yes
# skip the prompt; a default-no answer aborts cleanly.
# ---------------------------------------------------------------------------
if [ "$PM_ASSUME_YES" -eq 1 ]; then
  export ONIONARMOR_AUTO_CONFIRM=yes
fi
if ! oa_confirm "package-minimization: remove ${pkgs} (reclaim $(pm_human_kib "$total_kib"))?"; then
  audit_log pm.apply.cancel "role=$role_label packages=$pkgs"
  die "package-minimization: cancelled (no packages removed)"
fi

# ---------------------------------------------------------------------------
# Remove via a single apt-get call. Honour ONIONARMOR_SKIP_RELOAD=yes to mean
# "compute/plan only, do not actually invoke apt".
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_PM_STATE_DIR" || die "cannot create state dir $ONIONARMOR_PM_STATE_DIR"
removed_path=$(pm_removed_path)

if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes: not invoking apt — recording the planned removal set only"
else
  # shellcheck disable=SC2086  # $pkgs is a deliberate multi-package arg list
  "$ONIONARMOR_PM_APT" remove -y $pkgs \
    || { audit_log pm.apply.fail "stage=remove packages=$pkgs"; die "apt-get remove failed for: $pkgs"; }
fi
audit_log pm.apply.remove "packages=$pkgs saved_kib=$total_kib skip_reload=${ONIONARMOR_SKIP_RELOAD:-no}"

# ---------------------------------------------------------------------------
# Record the removed set to removed.list (merge with any prior set, deduped).
# ---------------------------------------------------------------------------
merged=$pkgs
if [ -f "$removed_path" ]; then
  merged=$(printf '%s\n%s\n' "$(tr ' ' '\n' < "$removed_path")" "$(printf '%s' "$pkgs" | tr ' ' '\n')" \
           | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ *$//')
fi
tmp="$removed_path.tmp.$$"
if printf '%s\n' "$merged" > "$tmp" 2>/dev/null && mv "$tmp" "$removed_path" 2>/dev/null; then
  audit_log pm.apply.record "path=$removed_path set=$merged"
else
  rm -f "$tmp" 2>/dev/null || true
  warn "could not record removed set to $removed_path — revert will not know to reinstall these"
fi

# ---------------------------------------------------------------------------
# Verify (default on): re-query each removed package is gone. Skipped (with the
# live kernel untouched) under SKIP_RELOAD, where nothing was actually removed.
# ---------------------------------------------------------------------------
verify_failed=0
survivors=""
if [ "$PM_VERIFY" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  for pkg in $pkgs; do
    if pm_pkg_installed "$pkg"; then
      survivors="$survivors $pkg"
      verify_failed=1
    fi
  done
  if [ "$verify_failed" -eq 1 ]; then
    survivors=$(printf '%s' "$survivors" | sed 's/^ *//')
    warn "verify: package(s) still installed after removal: $survivors"
  else
    info "verify: all target packages removed"
  fi
fi

audit_log pm.apply.done "removed=$(printf '%s' "$pkgs" | wc -w | tr -d ' ') saved_kib=$total_kib verify_failed=$verify_failed role=$role_label"

cat <<EOF

[package-minimization] applied.
  role        : $role_label
  removed     : $pkgs
  reclaimed   : $(pm_human_kib "$total_kib")
  removed.list: $removed_path
EOF
printf '\nReinstall on demand:  onionarmor revert --module package-minimization\n'

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported survivors above"; exit 2; }
