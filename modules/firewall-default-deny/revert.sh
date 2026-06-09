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
  if "$ONIONARMOR_FW_ATRM" "$job" >/dev/null 2>&1; then
    info "cancelled pending safety-latch at job $job"
    audit_log fw.revert.latch "cancelled=$job"
    rm -f "$latch_state" 2>/dev/null || warn "could not remove $latch_state"
  else
    warn "could not cancel safety-latch at job $job (atrm $job) — keeping state file for retry"
  fi
else
  rm -f "$latch_state" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Disable + reset ufw (drops our rules and the default-deny policy).
# ---------------------------------------------------------------------------
disable_ok=0
reset_ok=0
if command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1; then
  if "$ONIONARMOR_FW_UFW" disable >/dev/null 2>&1; then
    disable_ok=1
  else
    warn "ufw disable returned nonzero"
  fi
  if "$ONIONARMOR_FW_UFW" --force reset >/dev/null 2>&1 || "$ONIONARMOR_FW_UFW" reset >/dev/null 2>&1; then
    reset_ok=1
  else
    warn "ufw reset returned nonzero"
  fi
  if [ "$disable_ok" -eq 1 ] && [ "$reset_ok" -eq 1 ]; then
    audit_log fw.revert.ufw "disabled+reset"
    info "ufw disabled + reset"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Remove auxiliary state (manifest, IPv6 choice) only if reset succeeded.
# ---------------------------------------------------------------------------
ipv6_choice_path=$(fw_ipv6_choice_path)
extra_allow_path=$(fw_extra_allow_path)
if [ "$reset_ok" -eq 1 ]; then
  if [ -f "$manifest_path" ]; then
    rm -f "$manifest_path" || warn "could not remove $manifest_path"
    audit_log fw.revert.manifest "removed=$manifest_path"
    info "removed rule manifest: $manifest_path"
  fi
  rm -f "$ipv6_choice_path" 2>/dev/null || true
  rm -f "$extra_allow_path" 2>/dev/null || true
else
  if [ -f "$manifest_path" ]; then
    warn "keeping manifest $manifest_path (ufw reset failed — retry revert)"
  fi
fi

# If ufw is present but disable or reset actually failed, the posture was NOT
# fully torn down — report failure (nonzero) so callers/automation don't assume
# a clean revert. A host without ufw installed has nothing to disable (ok).
revert_failed=0
if command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1 \
   && { [ "$disable_ok" -ne 1 ] || [ "$reset_ok" -ne 1 ]; }; then
  revert_failed=1
fi
audit_log fw.revert.done "ok=$([ "$revert_failed" -eq 0 ] && echo 1 || echo 0)"
cat <<EOF

[firewall-default-deny] reverted.
  ufw      : $([ "$revert_failed" -eq 0 ] && echo "disabled + reset (left installed)" || echo "disable/reset FAILED — posture may still be partially active")
  latch    : ${job:-none} cancelled
EOF
if [ "$reset_ok" -eq 1 ]; then
  printf '  manifest : removed (%s)\n' "$manifest_path"
else
  printf '  manifest : kept for retry (%s)\n' "$manifest_path"
fi
cat <<EOF

WARNING: inbound is no longer default-deny. Re-apply to restore the posture:
  onionarmor apply --module firewall-default-deny
EOF

[ "$revert_failed" -eq 0 ] || { warn "revert did not fully tear down ufw — re-run revert"; exit 1; }
