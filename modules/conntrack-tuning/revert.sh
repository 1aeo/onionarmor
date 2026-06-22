#!/usr/bin/env bash
# revert.sh — undo the conntrack-tuning posture: remove the two managed drop-ins
# (restoring prior backups if they exist) and reload sysctls. Best-effort.
#
# Removing the drop-ins stops the tuning from being re-applied on the next boot /
# reload. The live nf_conntrack_max / timeout keep their tuned runtime values
# until something resets them (a reboot returns them to the kernel defaults); we
# do not forcibly shrink the live table, which would be disruptive on a busy host.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ct_parse_flags "$@"

sysctl_dropin=$(ct_sysctl_dropin_path)
modprobe_dropin=$(ct_modprobe_dropin_path)
sysctl_backup=$(ct_sysctl_backup_path)
modprobe_backup=$(ct_modprobe_backup_path)

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${CT_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header conntrack-tuning revert
  for spec in "$sysctl_dropin|$sysctl_backup" "$modprobe_dropin|$modprobe_backup"; do
    dropin=${spec%%|*}; backup=${spec#*|}
    if [ -f "$dropin" ]; then
      if [ -f "$backup" ]; then
        oa_would "restore prior drop-in from backup ($backup -> $dropin)"
      else
        oa_would "remove drop-in $dropin"
      fi
    else
      oa_would "nothing to remove — no drop-in at $dropin"
    fi
  done
  if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
    oa_would "skip reload (ONIONARMOR_SKIP_RELOAD=yes)"
  else
    oa_would "re-run $ONIONARMOR_SYSCTL_CMD --system"
  fi
  exit 0
fi

audit_log ct.revert.start "sysctl_dropin=$sysctl_dropin modprobe_dropin=$modprobe_dropin"

# ---------------------------------------------------------------------------
# 1. For each drop-in: restore the backup if one exists, else remove it.
# Compute had_any up front — ct_revert_one runs in a command-substitution
# subshell, so a had_any set inside it would not survive.
# ---------------------------------------------------------------------------
had_any=0
if [ -f "$sysctl_dropin" ] || [ -f "$modprobe_dropin" ]; then had_any=1; fi
ct_revert_one() {
  # ct_revert_one <dropin> <backup>; echoes a one-word status for the summary.
  local dropin=$1 backup=$2
  if [ ! -f "$dropin" ]; then
    warn "no drop-in at $dropin — nothing to remove"
    printf 'absent'
    return 0
  fi
  if [ -f "$backup" ]; then
    cp -p "$backup" "$dropin" \
      || audit_fail_warn ct.revert.fail "stage=restore" "failed to restore $backup -> $dropin"
    audit_log ct.revert.restore "from=$backup to=$dropin"
    info "restored prior drop-in from backup: $backup"
    printf 'restored'
  else
    rm -f "$dropin" \
      || audit_fail_warn ct.revert.fail "stage=remove" "failed to remove $dropin"
    audit_log ct.revert.dropin "removed=$dropin"
    info "removed drop-in: $dropin"
    printf 'removed'
  fi
}
sysctl_state=$(ct_revert_one "$sysctl_dropin" "$sysctl_backup")
modprobe_state=$(ct_revert_one "$modprobe_dropin" "$modprobe_backup")

# ---------------------------------------------------------------------------
# 2. Reload sysctls so the removed ceiling/timeout stop being re-asserted on the
# next load. Best-effort: a noisy reload must not fail the revert.
# ---------------------------------------------------------------------------
if [ "$had_any" -eq 0 ]; then
  reload_note="skipped (nothing of ours was present)"
elif [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  reload_note="skipped (ONIONARMOR_SKIP_RELOAD=yes)"
  info "ONIONARMOR_SKIP_RELOAD=yes — leaving the live kernel untouched"
elif "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1; then
  reload_note="reloaded via $ONIONARMOR_SYSCTL_CMD --system"
else
  warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero during revert"
  reload_note="reload returned nonzero (best-effort)"
fi

audit_log ct.revert.done "ok=1 sysctl=$sysctl_state modprobe=$modprobe_state"

cat <<EOF

[conntrack-tuning] reverted.
  sysctl drop-in   : $sysctl_state ($sysctl_dropin)
  modprobe drop-in : $modprobe_state ($modprobe_dropin)
  reload           : $reload_note

Note: the live conntrack ceiling/timeout keep their tuned values until a reboot
or an explicit reset; this module does not forcibly shrink the live table. The
modprobe hashsize reverts at the next nf_conntrack (re)load.
EOF
