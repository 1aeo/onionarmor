#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the firewall-default-deny posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

fw_parse_flags "$@"

_fw_worst=0
fw_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_FW_GREEN; [ "$_fw_worst" -lt 0 ] && _fw_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_FW_YEL; [ "$_fw_worst" -lt 1 ] && _fw_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_FW_RED; _fw_worst=2 ;;
  esac
  printf '%s%s%s %-30s %s\n' "$col" "$mark" "$OA_FW_OFF" "$label" "$detail"
}

info "firewall-default-deny audit"
printf '\n'

# Front-end must exist to audit anything meaningful.
if ! command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1; then
  fw_check red "ufw present" "ufw not installed (apt install ufw)"
  printf '\n'
  warn "audit: one or more RED checks — posture is broken"
  exit 1
fi

verbose=$("$ONIONARMOR_FW_UFW" status verbose 2>/dev/null || true)

# --- 1. ufw active --------------------------------------------------------
if printf '%s\n' "$verbose" | head -1 | grep -qi 'Status: active'; then
  fw_check green "ufw active" "Status: active"
else
  fw_check red "ufw active" "ufw is inactive (default-deny NOT in force)"
fi

# --- 2. default policies (deny incoming / allow outgoing) -----------------
defline=$(printf '%s\n' "$verbose" | grep -i '^Default:' || true)
if printf '%s' "$defline" | grep -qi 'deny (incoming)'; then
  if printf '%s' "$defline" | grep -qi 'allow (outgoing)'; then
    fw_check green "default policy" "deny incoming / allow outgoing"
  else
    fw_check yellow "default policy" "deny incoming, but outgoing not 'allow' ($defline)"
  fi
else
  fw_check red "default policy" "incoming is not default-deny (${defline:-no Default line})"
fi

# --- 3. IPv6 enabled ------------------------------------------------------
# Read the persisted IPv6 choice from apply if available
ipv6_choice=$(fw_read_ipv6_choice)
if [ -n "$ipv6_choice" ]; then
  # Use the persisted choice from apply, unless overridden by --no-ipv6 flag
  if [ "$FW_IPV6" -eq 1 ] && [ "$ipv6_choice" = "0" ]; then
    # Apply was v4-only, audit didn't override → use apply's choice
    FW_IPV6=0
  fi
fi

if fw_ipv6_enabled; then
  fw_check green "IPv6 enabled" "IPV6=yes in $(basename "$ONIONARMOR_FW_UFW_DEFAULTS")"
elif [ "$FW_IPV6" -eq 0 ]; then
  fw_check yellow "IPv6 enabled" "--no-ipv6: v4 only (operator choice)"
else
  fw_check red "IPv6 enabled" "IPV6 not 'yes' — v6 inbound is unfiltered"
fi

# --- 4. rule count --------------------------------------------------------
nrules=$("$ONIONARMOR_FW_UFW" status numbered 2>/dev/null | grep -cE '^\[[[:space:]]*[0-9]+\]' || true)
fw_check green "rule count" "$nrules allow rule(s) active"

# --- 5. listener <-> allow drift ------------------------------------------
# Merge persisted --allow flags from apply with any CLI flags for audit
persisted_allow=$(fw_read_extra_allow)
if [ -n "$persisted_allow" ]; then
  FW_EXTRA_ALLOW="$FW_EXTRA_ALLOW $persisted_allow"
fi
fw_build_manifest      # FW_RULES + FW_UNKNOWN for the CURRENT host
listeners=$(fw_listeners | awk '{print $2}' | sort -u | paste -sd, - 2>/dev/null \
            || fw_listeners | awk '{print $2}' | sort -u | tr '\n' ',')
fw_check green "listeners (non-loopback)" "${listeners:-none}"

if [ -n "$FW_UNKNOWN" ]; then
  fw_check yellow "unallowed listeners" "DENIED (no allow rule): $FW_UNKNOWN — --allow to expose"
else
  fw_check green "unallowed listeners" "every non-loopback listener is covered by a rule"
fi

# Manifest drift: does the stored manifest still match what the host needs?
manifest_path=$(fw_manifest_path)
rendered=$(fw_render_manifest)
if [ ! -f "$manifest_path" ]; then
  fw_check yellow "manifest in sync" "no manifest yet at $manifest_path (apply not run?)"
elif [ "$(cat "$manifest_path")" = "$rendered" ]; then
  # Manifest exists and matches, but if UFW is inactive, this is a posture regression
  if printf '%s\n' "$verbose" | head -1 | grep -qi 'Status: active'; then
    fw_check green "manifest in sync" "stored rule set matches current host"
  else
    fw_check red "manifest in sync" "manifest exists but UFW is inactive — posture regression"
  fi
else
  fw_check yellow "manifest in sync" "host listeners changed since apply — re-apply to reconcile"
fi

# --- 6. safety-latch status -----------------------------------------------
job=$(fw_latch_pending)
if [ -n "$job" ]; then
  fw_check yellow "safety latch" "at job $job still PENDING — cancel with: atrm $job"
else
  fw_check green "safety latch" "no pending auto-disable job"
fi

printf '\n'
case "$_fw_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — posture is broken"; exit 1 ;;
esac
