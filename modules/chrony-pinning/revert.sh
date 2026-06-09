#!/usr/bin/env bash
# revert.sh — undo the chrony-pinning posture: remove our sources + conf files,
# restore the main chrony.conf if we edited it, unmask + restart
# systemd-timesyncd, and stop chrony. chrony itself is left installed.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

chr_parse_flags "$@"

sources=$(chr_sources_path)
conf=$(chr_conf_path)
backup=$(chr_mainconf_backup)

audit_log chr.revert.start "sources=$sources conf=$conf"

# ---------------------------------------------------------------------------
# 1. Remove our managed sources + conf files.
# ---------------------------------------------------------------------------
for f in "$sources" "$conf"; do
  if [ -f "$f" ]; then
    rm -f "$f" || audit_fail_die chr.revert.fail "stage=remove" "failed to remove $f"
    audit_log chr.revert.file "removed=$f"
    info "removed: $f"
  fi
done

# ---------------------------------------------------------------------------
# 2. Restore the main chrony.conf if apply backed it up (we appended an include
#    block). Restoring the backup drops that block cleanly.
# ---------------------------------------------------------------------------
if [ -f "$backup" ]; then
  cp -p "$backup" "$ONIONARMOR_CHR_MAIN_CONF" \
    || audit_fail_die chr.revert.fail "stage=mainconf" "failed to restore $ONIONARMOR_CHR_MAIN_CONF from $backup"
  rm -f "$backup"
  audit_log chr.revert.mainconf "restored=$ONIONARMOR_CHR_MAIN_CONF from=$backup"
  info "restored $ONIONARMOR_CHR_MAIN_CONF from backup"
fi

# ---------------------------------------------------------------------------
# 3. Unmask + restart systemd-timesyncd so the host keeps disciplining time.
# ---------------------------------------------------------------------------
"$ONIONARMOR_CHR_SYSTEMCTL" unmask "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
"$ONIONARMOR_CHR_SYSTEMCTL" enable --now "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 \
  || "$ONIONARMOR_CHR_SYSTEMCTL" start "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
audit_log chr.revert.timesyncd "unmasked=$ONIONARMOR_CHR_TIMESYNCD"
info "unmasked + started $ONIONARMOR_CHR_TIMESYNCD"

# ---------------------------------------------------------------------------
# 4. Stop chrony (leave it installed). Reload first so it drops our sources if
#    it is still running, then stop the service.
# ---------------------------------------------------------------------------
"$ONIONARMOR_CHR_SYSTEMCTL" stop "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 \
  || warn "could not stop $ONIONARMOR_CHR_SERVICE (already stopped?)"
"$ONIONARMOR_CHR_SYSTEMCTL" disable "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 || true
audit_log chr.revert.chrony "stopped=$ONIONARMOR_CHR_SERVICE"

audit_log chr.revert.done "ok=1"
cat <<EOF

[chrony-pinning] reverted.
  sources file : removed ($sources)
  conf file    : removed ($conf)
  timesyncd    : unmasked + started ($ONIONARMOR_CHR_TIMESYNCD)
  chrony       : stopped + disabled (left installed)

NOTE: time is now disciplined by $ONIONARMOR_CHR_TIMESYNCD again.
EOF
