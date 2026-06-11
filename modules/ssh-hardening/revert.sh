#!/usr/bin/env bash
# revert.sh — undo the ssh-hardening posture: cancel any pending safety latch,
# restore the prior drop-in (or remove ours), restore any backed-up host keys,
# and reload sshd. Best-effort.
#
# WARNING: reverting re-permits whatever the operator's base sshd_config allowed
# (possibly password / root login). Re-apply to restore the hardened posture.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ssh_parse_flags "$@"

dropin=$(ssh_dropin_path)
bak=$(ssh_backup_path)
latch_state=$(ssh_latch_state_path)

warn "revert relaxes SSH hardening back to the base sshd_config policy"
audit_log ssh.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Cancel a still-pending safety-latch at-job.
# ---------------------------------------------------------------------------
job=$(ssh_latch_pending)
if [ -n "$job" ]; then
  if "$ONIONARMOR_SSH_ATRM" "$job" >/dev/null 2>&1; then
    info "cancelled pending safety-latch at job $job"
    audit_log ssh.revert.latch "cancelled=$job"
    rm -f "$latch_state" 2>/dev/null || warn "could not remove $latch_state"
  else
    warn "could not cancel safety-latch at job $job (atrm $job) — keeping state for retry"
  fi
else
  rm -f "$latch_state" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Restore the prior drop-in (if we backed one up) or remove ours.
# ---------------------------------------------------------------------------
if [ -f "$bak" ]; then
  if cp -p "$bak" "$dropin" && rm -f "$bak"; then
    info "restored prior drop-in from backup"
    audit_log ssh.revert.dropin "restored=$dropin"
  else
    warn "could not restore prior drop-in from $bak"
  fi
elif [ -f "$dropin" ]; then
  rm -f "$dropin" && info "removed hardening drop-in $dropin" \
    || warn "could not remove $dropin"
  audit_log ssh.revert.dropin "removed=$dropin"
fi

# ---------------------------------------------------------------------------
# 3. Restore backed-up host keys (best-effort; the regrown RSA key stays unless
#    a backup of the original exists).
# ---------------------------------------------------------------------------
keybak="$ONIONARMOR_SSH_STATE_DIR/hostkeys.bak"
if [ -d "$keybak" ]; then
  restored=0
  for f in "$keybak"/*; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    if cp -p "$f" "$ONIONARMOR_SSH_HOSTKEY_DIR/$base" 2>/dev/null; then
      restored=$((restored + 1))
    else
      warn "could not restore host key $base"
    fi
  done
  if [ "$restored" -gt 0 ]; then
    info "restored $restored backed-up host-key file(s)"
    audit_log ssh.revert.hostkey "restored=$restored"
    rm -rf "$keybak" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# 4. Reload sshd so the restored config takes effect.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — config restored but sshd not reloaded"
else
  if ssh_config_test >/dev/null 2>&1 && "$ONIONARMOR_SSH_SYSTEMCTL" reload "$ONIONARMOR_SSH_UNIT" >/dev/null 2>&1; then
    info "reloaded $ONIONARMOR_SSH_UNIT"
  else
    reload_failed=1
    warn "could not reload $ONIONARMOR_SSH_UNIT after revert (check sshd -t)"
  fi
fi

audit_log ssh.revert.done "reload_failed=$reload_failed"

cat <<EOF

[ssh-hardening] reverted.
  drop-in : $([ -f "$dropin" ] && echo "restored prior config" || echo "removed")
  latch   : ${job:-none} cancelled

WARNING: SSH hardening is no longer enforced. Re-apply to restore it:
  onionarmor apply --module ssh-hardening
EOF

[ "$reload_failed" -eq 0 ] || { warn "revert completed but sshd reload failed"; exit 1; }
