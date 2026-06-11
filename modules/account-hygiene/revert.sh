#!/usr/bin/env bash
# revert.sh — undo the account-hygiene posture: cancel any pending safety latch,
# then restore the membership/locks captured at apply time (re-add removed users
# to their groups, unlock accounts this module locked). Best-effort; summarises.
#
# The restore is driven by the snapshot written at apply time. The actual
# re-add/unlock commands are encoded in the staged restore.sh (the same payload
# the latch would have fired), so manual revert and auto-revert do exactly the
# same thing. If no snapshot exists, there is nothing to undo.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ah_parse_flags "$@"

snapshot=$(ah_snapshot_path)
restore="$ONIONARMOR_AH_STATE_DIR/restore.sh"

audit_log ah.revert.start "snapshot=$snapshot"

# ---------------------------------------------------------------------------
# 1. Cancel any pending safety latch so it cannot fire after we have manually
#    restored (or while there is nothing left to restore).
# ---------------------------------------------------------------------------
if oa_latch_is_armed "$AH_MODULE"; then
  oa_latch_cancel "$AH_MODULE" || warn "could not cancel pending safety latch"
else
  info "no pending safety latch to cancel"
fi

# ---------------------------------------------------------------------------
# 2. Restore the snapshot. We re-derive the actions from the snapshot file
#    (rather than blindly exec-ing restore.sh) so revert works even if the
#    staged script was removed, and so each action is individually audited.
# ---------------------------------------------------------------------------
if [ ! -f "$snapshot" ]; then
  warn "no snapshot at $snapshot — account-hygiene was never applied (or state was cleared). Nothing to restore."
  audit_log ah.revert.done "restored=0 reason=no-snapshot"
  cat <<EOF

[account-hygiene] reverted.
  snapshot : none ($snapshot)
  restored : nothing (no prior apply recorded)
EOF
  exit 0
fi

# Parse the snapshot's `key=value` lines (values are space-separated tokens).
snap_cloud_lock=$(sed -n 's/^cloud_lock=//p'   "$snapshot")
snap_cloud_desudo=$(sed -n 's/^cloud_desudo=//p' "$snapshot")
snap_strangers=$(sed -n 's/^strangers=//p'     "$snapshot")

readded=0
unlocked=0

# Re-add cloud defaults removed from sudo.
for u in $snap_cloud_desudo; do
  [ -n "$u" ] || continue
  if "$ONIONARMOR_AH_GPASSWD" -a "$u" sudo >/dev/null 2>&1; then
    audit_log ah.revert.readd "user=$u group=sudo"
    info "re-added to sudo: $u"
    readded=$((readded + 1))
  else
    warn "could not re-add $u to sudo (gpasswd -a)"
  fi
done

# Re-add each stranger to the group it was removed from.
for pair in $snap_strangers; do
  [ -n "$pair" ] || continue
  su=${pair%%:*}; sg=${pair#*:}
  if "$ONIONARMOR_AH_GPASSWD" -a "$su" "$sg" >/dev/null 2>&1; then
    audit_log ah.revert.readd "user=$su group=$sg"
    info "re-added to $sg: $su"
    readded=$((readded + 1))
  else
    warn "could not re-add $su to $sg (gpasswd -a)"
  fi
done

# Unlock accounts this module locked.
for u in $snap_cloud_lock; do
  [ -n "$u" ] || continue
  if "$ONIONARMOR_AH_USERMOD" -U "$u" >/dev/null 2>&1; then
    audit_log ah.revert.unlock "user=$u"
    info "unlocked account: $u"
    unlocked=$((unlocked + 1))
  else
    warn "could not unlock $u (usermod -U)"
  fi
done

# ---------------------------------------------------------------------------
# 3. Clear the snapshot + staged restore script (state is consumed).
# ---------------------------------------------------------------------------
rm -f "$snapshot" "$restore" 2>/dev/null || warn "could not remove state files under $ONIONARMOR_AH_STATE_DIR"

audit_log ah.revert.done "restored=1 readded=$readded unlocked=$unlocked"

cat <<EOF

[account-hygiene] reverted.
  re-added to groups : $readded user(s)
  unlocked accounts  : $unlocked account(s)
  snapshot           : consumed ($snapshot)
EOF
