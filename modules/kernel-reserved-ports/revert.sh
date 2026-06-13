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

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${KRP_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header kernel-reserved-ports revert
  if [ -f "$dropin" ]; then
    oa_would "back up drop-in to $backup, then remove $dropin"
  else
    oa_would "no drop-in at $dropin — nothing to back up or remove"
  fi
  # The filter-state file is removed whenever it is present, independent of the
  # drop-in (matches step 1b of the live revert).
  [ -f "$(krp_filters_path)" ] && oa_would "remove filter state $(krp_filters_path)"
  # Runtime is only cleared when our drop-in was present (we must not clobber a
  # value some other tool set) and reload is not skipped.
  if [ -f "$dropin" ]; then
    if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
      oa_would "leave runtime $KRP_SYSCTL_KEY untouched (ONIONARMOR_SKIP_RELOAD=yes; a reboot clears it)"
    else
      oa_would "clear runtime $KRP_SYSCTL_KEY and re-run $ONIONARMOR_SYSCTL_CMD --system"
    fi
  else
    oa_would "leave runtime $KRP_SYSCTL_KEY as-is (no onionarmor drop-in was present)"
  fi
  exit 0
fi

audit_log krp.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Back up the drop-in (if present) before removing it.
# ---------------------------------------------------------------------------
had_dropin=0
if [ -f "$dropin" ]; then
  had_dropin=1
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
# 1b. Remove the persisted apply-filters.conf — only AFTER the drop-in is gone,
# so a failed backup/removal above (which dies) never leaves the filter state
# out of sync with a drop-in that is still present.
# ---------------------------------------------------------------------------
filters_file=$(krp_filters_path)
if [ -f "$filters_file" ]; then
  rm -f "$filters_file" \
    || warn "failed to remove stale filter state $filters_file"
  info "removed filter state: $filters_file"
fi

# ---------------------------------------------------------------------------
# 2. Clear the runtime reservation (empty = kernel default) and reload — but
# ONLY if we actually removed our drop-in. With no drop-in of ours present we
# have no record of having applied anything, so we must not clobber an
# ip_local_reserved_ports value that some other tool/operator may have set.
# $runtime_note records what actually happened so the summary can't claim the
# key was cleared when it wasn't. ONIONARMOR_SKIP_RELOAD leaves the live kernel
# untouched (symmetric with apply, which skips the load under the same knob).
# ---------------------------------------------------------------------------
if [ "$had_dropin" -eq 0 ]; then
  runtime_note="left as-is (no onionarmor drop-in was present)"
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
if [ "$had_dropin" -eq 1 ] && [ -n "$live" ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  warn "revert removed the drop-in but $KRP_SYSCTL_KEY is still '$live' at runtime (a reboot will clear it)"
  runtime_note="still '$live' (a reboot clears it)"
fi

audit_log krp.revert.done "ok=1 had_dropin=$had_dropin backup=$backup runtime=$runtime_note"
if [ "$had_dropin" -eq 1 ]; then
  dropin_line="removed ($dropin)"
  backup_line="$backup"
else
  dropin_line="none present ($dropin)"
  backup_line="(none — nothing to back up)"
fi
cat <<EOF

[kernel-reserved-ports] reverted.
  drop-in : $dropin_line
  backup  : $backup_line
  runtime : $KRP_SYSCTL_KEY — $runtime_note
EOF
