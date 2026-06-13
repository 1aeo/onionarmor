#!/usr/bin/env bash
# revert.sh — undo account-hygiene: cancel any pending safety latch and run the
# saved restore script (re-add removed sudo memberships, unlock locked accounts).
# Best-effort. Purged (userdel -r) accounts cannot be restored.
#
# WARNING: reverting re-grants sudo to the cloud-init / off-allowlist accounts
# that apply removed. Re-apply to restore the hardened posture.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

acct_parse_flags "$@"

restore=$(acct_restore_path)
latch_state=$(acct_latch_state_path)
snapshot=$(acct_snapshot_path)

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${ACCT_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header account-hygiene revert
  oa_would "cancel any pending safety-latch at-job; remove latch state $latch_state"
  if [ -f "$restore" ]; then
    oa_would "run restore script $restore — re-grant prior sudo membership / unlock removed accounts"
    oa_would "remove module state: $restore, $snapshot"
  else
    oa_would "nothing to undo — no restore script at $restore (apply not run, or already reverted)"
  fi
  exit 0
fi

warn "revert re-grants sudo to the accounts account-hygiene removed it from"
audit_log acct.revert.start "restore=$restore"

# ---------------------------------------------------------------------------
# 1. Cancel a still-pending safety-latch at-job.
# ---------------------------------------------------------------------------
job=$(acct_latch_pending)
if [ -n "$job" ]; then
  if "$ONIONARMOR_ACCT_ATRM" "$job" >/dev/null 2>&1; then
    info "cancelled pending safety-latch at job $job"
    audit_log acct.revert.latch "cancelled=$job"
    rm -f "$latch_state" 2>/dev/null || warn "could not remove $latch_state"
  else
    warn "could not cancel safety-latch at job $job (atrm $job) — keeping state for retry"
  fi
else
  rm -f "$latch_state" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Run the restore script to put prior membership back.
# ---------------------------------------------------------------------------
restore_failed=0
if [ -f "$restore" ]; then
  if sh "$restore"; then
    info "restored prior sudo membership / unlocked accounts"
    audit_log acct.revert.restore "ran=$restore"
    rm -f "$restore" "$snapshot" 2>/dev/null || true
  else
    restore_failed=1
    warn "restore script returned nonzero — keeping $restore for retry"
  fi
else
  info "no restore script found — nothing to undo (apply not run, or already reverted)"
fi

audit_log acct.revert.done "restore_failed=$restore_failed"

cat <<EOF

[account-hygiene] reverted.
  membership : $([ "$restore_failed" -eq 0 ] && echo "restored from snapshot" || echo "restore FAILED — re-run revert")
  latch      : ${job:-none} cancelled

WARNING: removed accounts may again hold sudo. Re-apply to restore the posture:
  onionarmor apply --module account-hygiene
EOF

[ "$restore_failed" -eq 0 ] || { warn "revert did not fully restore membership — re-run revert"; exit 1; }
