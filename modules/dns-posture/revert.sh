#!/usr/bin/env bash
# revert.sh — undo the dns-posture: restore resolv.conf from backup, remove
# our unbound snippet, unmask + restart systemd-resolved. unbound is left
# installed. Verifies name resolution works before exiting.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

dns_parse_flags "$@"

snippet=$(dns_snippet_path)
backup=$(dns_resolv_backup)

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${DNS_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header dns-posture revert
  oa_would "clear the immutable bit on $DNS_RESOLV_CONF"
  if [ -e "$backup" ]; then
    oa_would "restore $DNS_RESOLV_CONF from backup $backup"
  else
    oa_would "leave $DNS_RESOLV_CONF as-is (no backup present)"
  fi
  [ -f "$snippet" ] && oa_would "remove unbound snippet $snippet and reload unbound"
  oa_would "unmask + restart systemd-resolved (unbound left installed)"
  exit 0
fi

audit_log dns.revert.start "resolv=$DNS_RESOLV_CONF snippet=$snippet"

# ---------------------------------------------------------------------------
# 1. Clear immutability so resolv.conf can be restored.
# ---------------------------------------------------------------------------
"$ONIONARMOR_DNS_CHATTR" -i "$DNS_RESOLV_CONF" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 2. Restore resolv.conf from the backup taken at apply time.
# ---------------------------------------------------------------------------
if [ -e "$backup" ]; then
  [ -L "$DNS_RESOLV_CONF" ] && rm -f "$DNS_RESOLV_CONF"
  cp "$backup" "$DNS_RESOLV_CONF" \
    || audit_fail_die dns.revert.fail "stage=resolv" "failed to restore $DNS_RESOLV_CONF from $backup"
  audit_log dns.revert.resolv "restored=$DNS_RESOLV_CONF from=$backup"
  info "restored resolv.conf from $backup"
else
  warn "no resolv.conf backup at $backup — leaving $DNS_RESOLV_CONF as-is"
fi

# ---------------------------------------------------------------------------
# 3. Remove our unbound snippet (leave unbound itself installed).
# ---------------------------------------------------------------------------
if [ -f "$snippet" ]; then
  rm -f "$snippet"
  audit_log dns.revert.snippet "removed=$snippet"
  info "removed unbound snippet: $snippet"
  # Reload unbound so the forwarders go away; best-effort.
  "$ONIONARMOR_DNS_SYSTEMCTL" reload unbound >/dev/null 2>&1 \
    || "$ONIONARMOR_DNS_SYSTEMCTL" restart unbound >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 4. Unmask + restart systemd-resolved.
# ---------------------------------------------------------------------------
"$ONIONARMOR_DNS_SYSTEMCTL" unmask systemd-resolved >/dev/null 2>&1 || true
"$ONIONARMOR_DNS_SYSTEMCTL" enable --now systemd-resolved >/dev/null 2>&1 \
  || "$ONIONARMOR_DNS_SYSTEMCTL" start systemd-resolved >/dev/null 2>&1 || true
audit_log dns.revert.resolved "unmasked=systemd-resolved"
info "unmasked + started systemd-resolved"

# ---------------------------------------------------------------------------
# 5. Verify name resolution still works before declaring success.
# ---------------------------------------------------------------------------
if "$ONIONARMOR_DNS_GETENT" hosts cloudflare.com >/dev/null 2>&1; then
  info "verify: getent hosts cloudflare.com ok"
else
  audit_log dns.revert.fail "stage=verify"
  die "revert completed but name resolution failed (getent hosts cloudflare.com) — check systemd-resolved / resolv.conf manually"
fi

audit_log dns.revert.done "ok=1"
cat <<EOF

[dns-posture] reverted.
  resolv.conf     : restored from $backup
  unbound snippet : removed ($snippet) — unbound left installed
  systemd-resolved: unmasked + started
EOF
