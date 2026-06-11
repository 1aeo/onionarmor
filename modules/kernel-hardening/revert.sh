#!/usr/bin/env bash
# revert.sh — undo the kernel-hardening posture: remove the managed drop-in
# (restoring a prior backup if one exists) and reload sysctls. Best-effort.
#
# Removing the drop-in stops the keys from being re-applied on the next boot /
# reload. The KSPP keys themselves stay at their hardened runtime values until
# something resets them; this is a pure-uplift module, so that is intentional —
# a reboot returns them to the distro defaults. We do not forcibly un-harden the
# live kernel.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

dropin=$(kh_dropin_path)
backup=$(kh_backup_path)

audit_log kh.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Remove our drop-in; if a backup exists, restore it instead.
# ---------------------------------------------------------------------------
had_dropin=0
restored=0
if [ -f "$dropin" ]; then
  had_dropin=1
  if [ -f "$backup" ]; then
    cp -p "$backup" "$dropin" \
      || audit_fail_warn kh.revert.fail "stage=restore" "failed to restore $backup -> $dropin"
    restored=1
    audit_log kh.revert.restore "from=$backup to=$dropin"
    info "restored prior drop-in from backup: $backup"
  else
    rm -f "$dropin" \
      || audit_fail_warn kh.revert.fail "stage=remove" "failed to remove $dropin"
    audit_log kh.revert.dropin "removed=$dropin"
    info "removed drop-in: $dropin"
  fi
else
  warn "no drop-in at $dropin — nothing to remove"
fi

# ---------------------------------------------------------------------------
# 2. Reload sysctls so the change to /etc/sysctl.d takes effect for the next
# load. ONIONARMOR_SKIP_RELOAD leaves the live kernel untouched (symmetric with
# apply). Best-effort: a noisy reload must not fail the revert.
# ---------------------------------------------------------------------------
if [ "$had_dropin" -eq 0 ]; then
  reload_note="skipped (nothing of ours was present)"
elif [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  reload_note="skipped (ONIONARMOR_SKIP_RELOAD=yes)"
  info "ONIONARMOR_SKIP_RELOAD=yes — leaving the live kernel untouched"
else
  if "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1; then
    reload_note="reloaded via $ONIONARMOR_SYSCTL_CMD --system"
  else
    warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero during revert"
    reload_note="reload returned nonzero (best-effort)"
  fi
fi

audit_log kh.revert.done "ok=1 had_dropin=$had_dropin restored=$restored"

if [ "$had_dropin" -eq 1 ] && [ "$restored" -eq 1 ]; then
  dropin_line="restored from backup ($dropin)"
elif [ "$had_dropin" -eq 1 ]; then
  dropin_line="removed ($dropin)"
else
  dropin_line="none present ($dropin)"
fi

cat <<EOF

[kernel-hardening] reverted.
  drop-in : $dropin_line
  reload  : $reload_note

Note: KSPP keys keep their hardened runtime values until a reboot or an
explicit reset; this module does not forcibly un-harden the live kernel.
EOF
