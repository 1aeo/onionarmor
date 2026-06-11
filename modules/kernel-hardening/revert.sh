#!/usr/bin/env bash
# revert.sh — undo the kernel-hardening posture: back up then remove the managed
# drop-in and reload sysctls so the remaining drop-ins/defaults take over.
#
# NOTE: the kernel keeps already-loaded sysctl values live until something resets
# them, so removing the file does not roll the *running* kernel back to its prior
# values — a reboot does that cleanly. We say so in the summary rather than
# pretend otherwise (these KSPP values are safe to leave live until reboot).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

dropin=$(kh_dropin_path)
backup=$(kh_backup_path)

audit_log kh.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Back up (if present) then remove the managed drop-in.
# ---------------------------------------------------------------------------
had_dropin=0
if [ -f "$dropin" ]; then
  had_dropin=1
  mkdir -p "$ONIONARMOR_KH_STATE_DIR" || die "cannot create $ONIONARMOR_KH_STATE_DIR"
  cp -p "$dropin" "$backup" \
    || audit_fail_die kh.revert.fail "stage=backup" "failed to back up $dropin -> $backup"
  audit_log kh.revert.backup "from=$dropin to=$backup"
  info "backed up drop-in -> $backup"
  rm -f "$dropin" \
    || audit_fail_die kh.revert.fail "stage=remove" "failed to remove $dropin"
  audit_log kh.revert.dropin "removed=$dropin"
  info "removed drop-in: $dropin"
else
  warn "no drop-in at $dropin — nothing to back up or remove"
fi

# ---------------------------------------------------------------------------
# 2. Reload so the kernel re-reads the remaining /etc/sysctl.d drop-ins. Only
#    when we actually removed our drop-in, and not under ONIONARMOR_SKIP_RELOAD.
# ---------------------------------------------------------------------------
if [ "$had_dropin" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1 \
    || warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero during revert"
fi

# ---------------------------------------------------------------------------
# 3. Verify the drop-in is gone.
# ---------------------------------------------------------------------------
if [ -e "$dropin" ]; then
  audit_log kh.revert.fail "stage=verify"
  die "revert ran but $dropin still exists — check permissions"
fi

audit_log kh.revert.done "ok=1 had_dropin=$had_dropin backup=$backup"
if [ "$had_dropin" -eq 1 ]; then
  dropin_line="removed ($dropin)"
  backup_line="$backup"
else
  dropin_line="none present ($dropin)"
  backup_line="(none — nothing to back up)"
fi
cat <<EOF

[kernel-hardening] reverted.
  drop-in : $dropin_line
  backup  : $backup_line
  runtime : already-loaded KSPP values remain live until reboot (safe to leave)
EOF
