#!/usr/bin/env bash
# revert.sh — undo the chrony-pinning posture: remove our sources + conf files,
# restore the main chrony.conf if we edited it, unmask + restart
# systemd-timesyncd, and stop chrony. chrony itself is left installed.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

# revert applies no posture flags of its own, but it still runs the shared parser
# so `-h/--help` works and unknown/invalid options are rejected consistently with
# apply/audit. The parsed CHR_* values are intentionally unused here.
chr_parse_flags "$@"

sources=$(chr_sources_path)
conf=$(chr_conf_path)
backup=$(chr_mainconf_backup)
state=$(chr_state_file)

audit_log chr.revert.start "sources=$sources conf=$conf"

# ---------------------------------------------------------------------------
# 1. Remove our managed sources + conf files.
# ---------------------------------------------------------------------------
had_files=0
for f in "$sources" "$conf"; do
  if [ -f "$f" ]; then
    rm -f "$f" || audit_fail_die chr.revert.fail "stage=remove" "failed to remove $f"
    audit_log chr.revert.file "removed=$f"
    info "removed: $f"
    had_files=1
  fi
done

# ---------------------------------------------------------------------------
# 2. Restore the main chrony.conf if apply backed it up (we appended an include
#    block). Restoring the backup drops that block cleanly.
# ---------------------------------------------------------------------------
had_backup=0
if [ -f "$backup" ]; then
  cp -p "$backup" "$ONIONARMOR_CHR_MAIN_CONF" \
    || audit_fail_die chr.revert.fail "stage=mainconf" "failed to restore $ONIONARMOR_CHR_MAIN_CONF from $backup"
  rm -f "$backup"
  audit_log chr.revert.mainconf "restored=$ONIONARMOR_CHR_MAIN_CONF from=$backup"
  info "restored $ONIONARMOR_CHR_MAIN_CONF from backup"
  had_backup=1
fi

# ---------------------------------------------------------------------------
# 3. Unmask + restart systemd-timesyncd so the host keeps disciplining time.
#    Only if we actually managed these services (i.e. had module-owned files
#    OR a state file indicating apply ran).
# ---------------------------------------------------------------------------
had_state=0
[ -f "$state" ] && had_state=1

if [ "$had_files" -eq 1 ] || [ "$had_backup" -eq 1 ] || [ "$had_state" -eq 1 ]; then
  # Bring systemd-timesyncd back up FIRST and confirm it actually started; only
  # then is it safe to hand the clock off chrony. Keep the state file (for a
  # retry) if no replacement disciplinarian came up.
  "$ONIONARMOR_CHR_SYSTEMCTL" unmask "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
  "$ONIONARMOR_CHR_SYSTEMCTL" enable --now "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 \
    || "$ONIONARMOR_CHR_SYSTEMCTL" start "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
  timesyncd_state=$("$ONIONARMOR_CHR_SYSTEMCTL" is-active "$ONIONARMOR_CHR_TIMESYNCD" 2>/dev/null || true)
  if [ "$timesyncd_state" != "active" ]; then
    audit_fail_die chr.revert.fail "stage=timesyncd" \
      "$ONIONARMOR_CHR_TIMESYNCD is '$timesyncd_state' (expected active); leaving $ONIONARMOR_CHR_SERVICE running and keeping state for retry"
  fi
  audit_log chr.revert.timesyncd "unmasked=$ONIONARMOR_CHR_TIMESYNCD"
  info "unmasked + started $ONIONARMOR_CHR_TIMESYNCD"

  # ---------------------------------------------------------------------------
  # 4. Stop chrony (leave it installed), then confirm it is actually inactive
  #    before auditing success and removing state. A failed stop must NOT delete
  #    the managed files' state marker, or the next revert would skip service
  #    reconciliation and strand both chrony and timesyncd.
  # ---------------------------------------------------------------------------
  "$ONIONARMOR_CHR_SYSTEMCTL" stop "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 \
    || warn "could not stop $ONIONARMOR_CHR_SERVICE (already stopped?)"
  "$ONIONARMOR_CHR_SYSTEMCTL" disable "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 || true
  chrony_state=$("$ONIONARMOR_CHR_SYSTEMCTL" is-active "$ONIONARMOR_CHR_SERVICE" 2>/dev/null || true)
  if [ "$chrony_state" = "active" ]; then
    # Roll back timesyncd to avoid dual-daemon state; re-mask + stop it.
    "$ONIONARMOR_CHR_SYSTEMCTL" stop "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
    "$ONIONARMOR_CHR_SYSTEMCTL" mask "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
    audit_fail_die chr.revert.fail "stage=chrony" \
      "$ONIONARMOR_CHR_SERVICE still active after stop; keeping state for retry"
  fi
  audit_log chr.revert.chrony "stopped=$ONIONARMOR_CHR_SERVICE"

  # Remove state file only after the service handoff is confirmed complete.
  rm -f "$state" || true
else
  info "no module-owned files or state found; skipping service changes"
fi

audit_log chr.revert.done "ok=1"
if [ "$had_files" -eq 1 ] || [ "$had_backup" -eq 1 ] || [ "$had_state" -eq 1 ]; then
  cat <<EOF

[chrony-pinning] reverted.
  sources file : removed ($sources)
  conf file    : removed ($conf)
  timesyncd    : unmasked + started ($ONIONARMOR_CHR_TIMESYNCD)
  chrony       : stopped + disabled (left installed)

NOTE: time is now disciplined by $ONIONARMOR_CHR_TIMESYNCD again.
EOF
else
  cat <<EOF

[chrony-pinning] revert: no module-owned files or state found.
  Nothing to revert; services left untouched.
EOF
fi
