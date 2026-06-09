#!/usr/bin/env bash
# revert.sh — undo the firewall-default-deny posture: ufw disable + reset,
# cancel any pending safety latch, remove our manifest/state. ufw is left
# installed.
#
# WARNING: this re-exposes every closed port to kernel-RST emission — port scans
# will again produce onionleak flows and the inbound attack surface returns.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

fw_parse_flags "$@"

manifest_path=$(fw_manifest_path)
latch_state=$(fw_latch_state_path)

warn "revert DISABLES the firewall — closed ports will again emit kernel RSTs (attack surface returns)"
audit_log fw.revert.start "manifest=$manifest_path"

if ! command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1; then
  warn "ufw not found — nothing to disable; cleaning up onionarmor state only"
fi

# ---------------------------------------------------------------------------
# 1. Cancel a still-pending safety-latch at-job (so it doesn't fire later).
# ---------------------------------------------------------------------------
job=$(fw_latch_pending)
if [ -n "$job" ]; then
  "$ONIONARMOR_FW_ATRM" "$job" >/dev/null 2>&1 \
    && info "cancelled pending safety-latch at job $job" \
    || warn "could not cancel safety-latch at job $job (atrm $job)"
  audit_log fw.revert.latch "cancelled=$job"
fi
rm -f "$latch_state" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Disable + reset ufw (drops our rules and the default-deny policy).
# ---------------------------------------------------------------------------
if command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1; then
  "$ONIONARMOR_FW_UFW" disable >/dev/null 2>&1 \
    || warn "ufw disable returned nonzero"
  "$ONIONARMOR_FW_UFW" --force reset >/dev/null 2>&1 \
    || "$ONIONARMOR_FW_UFW" reset >/dev/null 2>&1 \
    || warn "ufw reset returned nonzero"
  audit_log fw.revert.ufw "disabled+reset"
  info "ufw disabled + reset"
fi

# ---------------------------------------------------------------------------
# 3. Remove our managed manifest.
# ---------------------------------------------------------------------------
if [ -f "$manifest_path" ]; then
  rm -f "$manifest_path" || warn "could not remove $manifest_path"
  audit_log fw.revert.manifest "removed=$manifest_path"
  info "removed rule manifest: $manifest_path"
fi

audit_log fw.revert.done "ok=1"
cat <<EOF

[firewall-default-deny] reverted.
  ufw      : disabled + reset (left installed)
  latch    : ${job:-none} cancelled
  manifest : removed ($manifest_path)

WARNING: inbound is no longer default-deny. Re-apply to restore the posture:
  onionarmor apply --module firewall-default-deny
EOF
