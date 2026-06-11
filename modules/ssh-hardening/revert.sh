#!/usr/bin/env bash
# revert.sh — undo the ssh-hardening posture: cancel any pending auto-revert
# latch, back up then remove the managed drop-in, validate with `sshd -t` and
# reload sshd so the distro defaults take over. Best-effort; summarises.
#
# HONEST CAVEAT: removing the drop-in returns sshd to its distro defaults; it
# does NOT restore the DSA/ECDSA host keys this module deleted (those are gone for
# good — clients that pinned them must re-trust the host). The summary says so.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sshd_parse_flags "$@"

dropin=$(sshd_dropin_path)
backup=$(sshd_backup_path)

audit_log sshd.revert.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Cancel a still-pending auto-revert latch so it can't fire after we revert.
# ---------------------------------------------------------------------------
if oa_latch_cancel "$SSHD_LATCH_MODULE"; then
  audit_log sshd.revert.latch "cancelled=1"
else
  info "no pending safety latch to cancel"
fi

# ---------------------------------------------------------------------------
# 2. Back up (if present) then remove the managed drop-in.
# ---------------------------------------------------------------------------
had_dropin=0
if [ -f "$dropin" ]; then
  had_dropin=1
  mkdir -p "$ONIONARMOR_SSHD_STATE_DIR" || die "cannot create $ONIONARMOR_SSHD_STATE_DIR"
  cp -p "$dropin" "$backup" \
    || audit_fail_die sshd.revert.fail "stage=backup" "failed to back up $dropin -> $backup"
  audit_log sshd.revert.backup "from=$dropin to=$backup"
  info "backed up drop-in -> $backup"
  rm -f "$dropin" \
    || audit_fail_die sshd.revert.fail "stage=remove" "failed to remove $dropin"
  audit_log sshd.revert.dropin "removed=$dropin"
  info "removed drop-in: $dropin"
else
  warn "no drop-in at $dropin — nothing to back up or remove"
fi

# ---------------------------------------------------------------------------
# 3. Validate + reload sshd so the remaining config (distro defaults) takes over.
#    Best-effort: never reload a config that fails `sshd -t`.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "$had_dropin" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  if ! "$ONIONARMOR_SSHD_SSHD_CMD" -t >/dev/null 2>&1; then
    warn "'$ONIONARMOR_SSHD_SSHD_CMD -t' failed AFTER removing our drop-in — NOT reloading (some other sshd config is broken)"
    reload_failed=1
  elif "$ONIONARMOR_SSHD_SYSTEMCTL" reload "$ONIONARMOR_SSHD_UNIT" >/dev/null 2>&1; then
    info "reloaded sshd ($ONIONARMOR_SSHD_SYSTEMCTL reload $ONIONARMOR_SSHD_UNIT)"
  else
    warn "$ONIONARMOR_SSHD_SYSTEMCTL reload $ONIONARMOR_SSHD_UNIT returned nonzero during revert"
    reload_failed=1
  fi
fi

# ---------------------------------------------------------------------------
# 4. Verify the drop-in is gone.
# ---------------------------------------------------------------------------
if [ -e "$dropin" ]; then
  audit_log sshd.revert.fail "stage=verify"
  die "revert ran but $dropin still exists — check permissions"
fi

audit_log sshd.revert.done "ok=1 had_dropin=$had_dropin reload_failed=$reload_failed"
if [ "$had_dropin" -eq 1 ]; then
  dropin_line="removed ($dropin)"
  backup_line="$backup"
else
  dropin_line="none present ($dropin)"
  backup_line="(none — nothing to back up)"
fi
cat <<EOF

[ssh-hardening] reverted.
  drop-in : $dropin_line
  backup  : $backup_line
  sshd    : back to distro defaults (the managed hardening drop-in is gone)

NOTE: this does NOT restore the DSA/ECDSA host keys removed at apply time, nor a
replaced RSA host key — those are not recoverable from a drop-in revert. Clients
that pinned the old host keys must re-trust this host.
EOF

[ "$reload_failed" -eq 0 ] || { warn "revert removed the drop-in but the sshd reload reported problems above"; exit 1; }
