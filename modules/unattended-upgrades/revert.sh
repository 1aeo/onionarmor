#!/usr/bin/env bash
# revert.sh — undo the unattended-upgrades posture: disable + mask the service
# and restore the apt.conf.d files to their distro defaults (or remove ours when
# there was no prior file). unattended-upgrades itself is left installed.
#
# WARNING: this turns OFF automatic security updates. Re-apply to restore them.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

uu_parse_flags "$@"

f50=$(uu_50_path)
f20=$(uu_20_path)

warn "revert disables automatic security upgrades — this REMOVES a security control"
audit_log uu.revert.start "f50=$f50 f20=$f20"

# uu_restore_file <path>: restore the backed-up distro default if we have one,
# otherwise remove our managed file. Leaves an unmanaged operator file alone.
uu_restore_file() {
  local path=$1 base backup
  base=$(basename "$path")
  backup=$(uu_backup_path "$base")
  if [ -f "$backup" ]; then
    cp -p "$backup" "$path" \
      || audit_fail_die uu.revert.fail "stage=restore" "failed to restore $path from $backup"
    rm -f "$backup"
    audit_log uu.revert.restore "path=$path from=$backup"
    info "restored distro default: $path"
  elif [ -f "$path" ] && grep -q 'Managed by onionarmor' "$path" 2>/dev/null; then
    rm -f "$path" \
      || audit_fail_die uu.revert.fail "stage=remove" "failed to remove $path"
    audit_log uu.revert.remove "removed=$path"
    info "removed managed config (no prior default to restore): $path"
  elif [ -f "$path" ]; then
    warn "leaving $path as-is (not onionarmor-managed and no backup recorded)"
  else
    info "nothing to restore at $path"
  fi
}

uu_restore_file "$f50"
uu_restore_file "$f20"

# ---------------------------------------------------------------------------
# Disable + mask the service so nothing re-runs it.
# ---------------------------------------------------------------------------
"$ONIONARMOR_UU_SYSTEMCTL" disable --now "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1 \
  || warn "could not disable $ONIONARMOR_UU_SERVICE"
# Masking is what actually guarantees the service can't run again, so a mask
# failure means automatic upgrades may still be active — that's not a clean revert.
mask_ok=0
if "$ONIONARMOR_UU_SYSTEMCTL" mask "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1; then
  mask_ok=1
  info "disabled + masked $ONIONARMOR_UU_SERVICE"
else
  warn "could not mask $ONIONARMOR_UU_SERVICE — automatic upgrades may still run"
fi
audit_log uu.revert.service "masked=$ONIONARMOR_UU_SERVICE mask_ok=$mask_ok"

# Remove the apply-time flags state so the next apply uses defaults.
# Only remove the marker after masking succeeds; keep it on failure for retry.
if [ "$mask_ok" -eq 1 ]; then
  flags_state=$(uu_flags_state_path)
  if [ -f "$flags_state" ]; then
    rm -f "$flags_state" || warn "could not remove $flags_state"
    audit_log uu.revert.flags "removed=$flags_state"
    info "removed apply-time flags state"
  fi
fi

audit_log uu.revert.done "ok=$mask_ok"
cat <<EOF

[unattended-upgrades] reverted.
  50 config : $f50
  20 config : $f20
  service   : $ONIONARMOR_UU_SERVICE ($([ "$mask_ok" -eq 1 ] && echo "disabled + masked" || echo "MASK FAILED — may still run"))

WARNING: automatic security upgrades are now OFF. Re-apply to restore them:
  onionarmor apply --module unattended-upgrades
EOF

[ "$mask_ok" -eq 1 ] || { warn "revert did not fully mask $ONIONARMOR_UU_SERVICE — re-run revert"; exit 1; }
