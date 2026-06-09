#!/usr/bin/env bash
# revert.sh — remove every onionarmor systemd-hardening drop-in, daemon-reload,
# and restart the affected units so they run unsandboxed again. Discovers the
# drop-ins by scanning the drop-in root, so it cleans up units that are no longer
# autodetected (e.g. a tor instance that was since disabled).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sh_parse_flags "$@"

audit_log sh.revert.start "root=$ONIONARMOR_SH_DROPIN_ROOT"

# Discover our managed drop-ins under the drop-in root.
units=()
for d in "$ONIONARMOR_SH_DROPIN_ROOT"/*.d; do
  [ -d "$d" ] || continue
  path="$d/$ONIONARMOR_SH_DROPIN_NAME"
  sh_is_managed_dropin "$path" || continue
  base=$(basename "$d")
  units+=("${base%.d}")
done

if [ "${#units[@]}" -eq 0 ]; then
  audit_log sh.revert.done "removed=none"
  info "no onionarmor hardening drop-ins found under $ONIONARMOR_SH_DROPIN_ROOT — nothing to revert"
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Remove each managed drop-in (and the now-empty .d dir).
# ---------------------------------------------------------------------------
for u in "${units[@]}"; do
  path=$(sh_dropin_path "$u")
  dir=$(sh_dropin_dir "$u")
  rm -f "$path" \
    || audit_fail_die sh.revert.fail "stage=remove unit=$u" "failed to remove $path"
  rmdir "$dir" 2>/dev/null || true
  audit_log sh.revert.dropin "removed=$path unit=$u"
  info "removed drop-in: $path"
done

# ---------------------------------------------------------------------------
# 2. daemon-reload, then restart the affected units so the sandbox is dropped.
#    Best-effort restart: a unit that won't come back is surfaced, not fatal —
#    the operator may have stopped it deliberately.
# ---------------------------------------------------------------------------
# The drop-ins are already off disk; if daemon-reload fails here, systemd still
# has the hardened unit cached and a restart would re-apply the very sandbox we
# just removed. Fail fast rather than silently leave units hardened (CR revert.sh:52).
"$ONIONARMOR_SH_SYSTEMCTL" daemon-reload >/dev/null 2>&1 \
  || audit_fail_die sh.revert.fail "stage=daemon-reload" "systemctl daemon-reload failed — units may still be hardened; re-run revert"

# The next apply must not assume these units are still activated.
rm -f "$(sh_activated_state)" 2>/dev/null || true

down=()
for u in "${units[@]}"; do
  if "$ONIONARMOR_SH_SYSTEMCTL" restart "$u" >/dev/null 2>&1 && sh_wait_active "$u"; then
    info "restarted (unsandboxed): $u"
    audit_log sh.revert.restart "unit=$u ok=1"
  else
    warn "restart of $u did not report active — check 'systemctl status $u'"
    audit_log sh.revert.restart "unit=$u ok=0"
    down+=("$u")
  fi
done

audit_log sh.revert.done "removed=${units[*]} down=${down[*]:-none}"
cat <<EOF

[systemd-hardening] reverted.
  drop-ins removed : ${units[*]}
EOF
[ "${#down[@]}" -eq 0 ] || printf '  did NOT confirm active : %s\n' "${down[*]}"
