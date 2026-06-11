#!/usr/bin/env bash
# revert.sh — undo the tor-config-baseline posture: cancel any pending auto-revert
# latch, restore each torrc from its backup, and reload the affected instances.
# Best-effort; summarises what it did. If no backups exist, says so.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

tcb_parse_flags "$@"

audit_log tcb.revert.start "state_dir=$ONIONARMOR_TCB_STATE_DIR"

# ---------------------------------------------------------------------------
# 1. Cancel any pending auto-revert latch (it would otherwise fire mid-revert).
# ---------------------------------------------------------------------------
if oa_latch_is_armed "$TCB_MODULE"; then
  oa_latch_cancel "$TCB_MODULE" || warn "could not cleanly cancel the safety latch"
else
  info "no pending safety latch to cancel"
fi

# ---------------------------------------------------------------------------
# 2. Restore each torrc from its backup + reload that instance.
# ---------------------------------------------------------------------------
backup_dir=$(tcb_backup_dir)
restored=0
missing=0

if [ ! -d "$backup_dir" ]; then
  warn "no backup directory at $backup_dir — nothing to restore (was apply ever run?)"
else
  for bkp in "$backup_dir"/*.torrc; do
    [ -e "$bkp" ] || continue
    inst=$(basename "$bkp" .torrc)
    pathfile="$backup_dir/$inst.path"
    if [ ! -f "$pathfile" ]; then
      warn "tor@$inst: no recorded torrc path ($pathfile) — skipping"
      missing=$((missing + 1))
      continue
    fi
    target=$(cat "$pathfile")
    if [ -z "$target" ]; then
      warn "tor@$inst: empty recorded torrc path — skipping"
      missing=$((missing + 1))
      continue
    fi
    if cp -p "$bkp" "$target"; then
      restored=$((restored + 1))
      audit_log tcb.revert.restore "inst=$inst torrc=$target"
      info "tor@$inst: restored $target from backup"
      if tcb_reload_instance "$inst"; then
        audit_log tcb.revert.reload "inst=$inst ok=1"
        info "tor@$inst: reloaded"
      else
        audit_log tcb.revert.reload "inst=$inst ok=0"
        warn "tor@$inst: reload returned nonzero"
      fi
    else
      warn "tor@$inst: failed to restore $target from $bkp"
      missing=$((missing + 1))
    fi
  done
fi

if [ "$restored" -eq 0 ] && [ "$missing" -eq 0 ]; then
  warn "no per-instance backups found in $backup_dir — nothing to restore"
fi

audit_log tcb.revert.done "restored=$restored missing=$missing"

cat <<EOF

[tor-config-baseline] reverted.
  restored : $restored torrc file(s) from $backup_dir
  skipped  : $missing
  note     : already-loaded tor config stays live until each instance is reloaded
EOF
