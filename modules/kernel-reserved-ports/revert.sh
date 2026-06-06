#!/usr/bin/env bash
# revert.sh — undo the kernel-reserved-ports posture: back up the managed
# drop-in, remove it, clear the runtime reservation, and reload sysctls.
# The kernel keeps a live ip_local_reserved_ports value until something resets
# it, so removing the file is not enough — we also clear the key at runtime.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

krp_parse_flags "$@"

dropin=$(krp_dropin_path)
backup=$(krp_backup_path)

audit_log krp.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Back up the drop-in (if present) before removing it.
# ---------------------------------------------------------------------------
dropin_was_present=0
if [ -f "$dropin" ]; then
  dropin_was_present=1
  mkdir -p "$ONIONARMOR_KRP_STATE_DIR" || die "cannot create $ONIONARMOR_KRP_STATE_DIR"
  cp -p "$dropin" "$backup" \
    || audit_fail_die krp.revert.fail "stage=backup" "failed to back up $dropin -> $backup"
  audit_log krp.revert.backup "from=$dropin to=$backup"
  info "backed up drop-in -> $backup"
  rm -f "$dropin" \
    || audit_fail_die krp.revert.fail "stage=remove" "failed to remove $dropin"
  audit_log krp.revert.dropin "removed=$dropin"
  info "removed drop-in: $dropin"
else
  warn "no drop-in at $dropin — nothing to back up or remove"
fi

# ---------------------------------------------------------------------------
# 2. Clear the runtime reservation (empty = kernel default) and reload.
# $runtime_note records what actually happened so the summary can't claim the
# key was cleared when it wasn't. ONIONARMOR_SKIP_RELOAD leaves the live kernel
# untouched (symmetric with apply, which skips the load under the same knob).
# ---------------------------------------------------------------------------
if [ "$dropin_was_present" -eq 0 ]; then
  runtime_note="left untouched (drop-in was not present)"
  info "drop-in was not present — leaving the runtime reservation untouched"
elif [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  runtime_note="left untouched (ONIONARMOR_SKIP_RELOAD=yes; a reboot clears it)"
  info "ONIONARMOR_SKIP_RELOAD=yes — leaving the runtime reservation untouched"
else
  runtime_note="cleared"
  "$ONIONARMOR_SYSCTL_CMD" -w "$KRP_SYSCTL_KEY=" >/dev/null 2>&1 \
    || { warn "could not clear $KRP_SYSCTL_KEY at runtime via $ONIONARMOR_SYSCTL_CMD -w"; runtime_note="clear FAILED (a reboot clears it)"; }
  "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1 \
    || warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero during revert"
fi

# ---------------------------------------------------------------------------
# 3. Verify the drop-in is gone (and, best-effort, the runtime is clear).
# ---------------------------------------------------------------------------
if [ -e "$dropin" ]; then
  audit_log krp.revert.fail "stage=verify"
  die "revert ran but $dropin still exists — check permissions"
fi
live=$(krp_sysctl_runtime)
if [ -n "$live" ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  warn "revert removed the drop-in but $KRP_SYSCTL_KEY is still '$live' at runtime (a reboot will clear it)"
  runtime_note="still '$live' (a reboot clears it)"
fi

audit_log krp.revert.done "ok=1 backup=$backup runtime=$runtime_note"
cat <<EOF

[kernel-reserved-ports] reverted.
  drop-in : removed ($dropin)
  backup  : $backup
  runtime : $KRP_SYSCTL_KEY — $runtime_note
EOF
