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

# ---------------------------------------------------------------------------
# Check if this module owned anything — only disable + mask the service when
# there is evidence we applied a posture. Look for apply-flags.state, .orig
# backups, or currently-managed config files as ownership markers.
# ---------------------------------------------------------------------------
flags_state=$(uu_flags_state_path)
b50=$(uu_backup_path "$(basename "$f50")")
b20=$(uu_backup_path "$(basename "$f20")")
had_ownership=0
if [ -f "$flags_state" ]; then
  had_ownership=1
elif [ -f "$b50" ] || [ -f "$b20" ]; then
  had_ownership=1
elif [ -f "$f50" ] && grep -q 'Managed by onionarmor' "$f50" 2>/dev/null; then
  had_ownership=1
elif [ -f "$f20" ] && grep -q 'Managed by onionarmor' "$f20" 2>/dev/null; then
  had_ownership=1
fi

uu_restore_file "$f50"
uu_restore_file "$f20"

# ---------------------------------------------------------------------------
# Disable + mask the service ONLY if we found evidence the module managed it.
# Otherwise, we have no record of having enabled it and must not strip
# automatic security updates that the module never configured.
# ---------------------------------------------------------------------------
mask_ok=0
service_note="left as-is (no evidence onionarmor managed it)"
if [ "$had_ownership" -eq 0 ]; then
  info "no ownership markers found — leaving $ONIONARMOR_UU_SERVICE as-is"
  audit_log uu.revert.service "action=skip reason=no_ownership"
else
  "$ONIONARMOR_UU_SYSTEMCTL" disable --now "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1 \
    || warn "could not disable $ONIONARMOR_UU_SERVICE"
  # Masking is what actually guarantees the service can't run again, so a mask
  # failure means automatic upgrades may still be active — that's not a clean revert.
  if "$ONIONARMOR_UU_SYSTEMCTL" mask "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1; then
    mask_ok=1
    service_note="disabled + masked"
    info "disabled + masked $ONIONARMOR_UU_SERVICE"
  else
    service_note="MASK FAILED — may still run"
    warn "could not mask $ONIONARMOR_UU_SERVICE — automatic upgrades may still run"
  fi
  audit_log uu.revert.service "masked=$ONIONARMOR_UU_SERVICE mask_ok=$mask_ok"

  # Remove the apply-time flags state so the next apply uses defaults.
  # Only remove the marker after masking succeeds; keep it on failure for retry.
  if [ "$mask_ok" -eq 1 ]; then
    if [ -f "$flags_state" ]; then
      rm -f "$flags_state" || warn "could not remove $flags_state"
      audit_log uu.revert.flags "removed=$flags_state"
      info "removed apply-time flags state"
    fi
  fi
fi

audit_log uu.revert.done "ok=$mask_ok had_ownership=$had_ownership"
cat <<EOF

[unattended-upgrades] reverted.
  50 config : $f50
  20 config : $f20
  service   : $ONIONARMOR_UU_SERVICE ($service_note)
EOF

if [ "$had_ownership" -eq 1 ]; then
  cat <<EOF

WARNING: automatic security upgrades are now OFF. Re-apply to restore them:
  onionarmor apply --module unattended-upgrades
EOF
  [ "$mask_ok" -eq 1 ] || { warn "revert did not fully mask $ONIONARMOR_UU_SERVICE — re-run revert"; exit 1; }
else
  info "nothing was reverted (module never applied anything)"
fi
