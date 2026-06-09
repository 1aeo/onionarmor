#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the bgp-hardening posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) bgpd listener is bound to a specific IP, not 0.0.0.0 / [::]  (REQUIRED),
#   (b) IF the optional tcp/179 firewall is configured, it is sound (optional),
#   (c) IF optional RPKI is configured, the validator is up + FRR queries it,
#   (d) FRR is a current release (CVE awareness — advisory only).
# Only (a) and a broken opted-in (b)/(c) are red. The single-homed stub-AS
# default posture (listener bind only) is all-green.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

bgp_parse_flags "$@"

info "bgp-hardening audit"
printf '\n'

# --- (a) listener bind ----------------------------------------------------
bind=$(bgp_listener_bind)
if [ -z "$bind" ]; then
  oa_status_check yellow "listener bind" "no tcp/179 listener found (is bgpd running?)"
elif bgp_bind_is_wildcard "$bind"; then
  oa_status_check red "listener bind" "bgpd bound to $bind (wildcard) — set -l <peer-facing-ip> via apply"
else
  oa_status_check green "listener bind" "bgpd bound to $bind (specific)"
fi

# --- (b) firewall restricts tcp/179 (OPTIONAL defense-in-depth) ----------
# The :179 firewall is opt-in (--enable-firewall), so its absence is fine —
# never red. When it IS in place, validate it.
# Use the persisted peer list from apply (if available) to check against the
# actual deployed config, not just auto-detected peers (handles --peer-ip overrides).
firewall_peers_file=$(bgp_firewall_peers_path)
fw_owned=0
if [ -e "$firewall_peers_file" ] && [ -s "$firewall_peers_file" ]; then
  fw_owned=1
  peers=$(cat "$firewall_peers_file" 2>/dev/null || true)
else
  peers=$(bgp_resolve_peers)
fi
cur=$(bgp_nft_current)
if [ -z "$cur" ] && [ "$fw_owned" -eq 1 ]; then
  # We previously applied the firewall (ownership marker present) but the managed
  # table is gone — that's drift, not "not configured". Red.
  oa_status_check red "firewall tcp/179" "applied via --enable-firewall but the managed nft table inet $BGP_NFT_TABLE is gone — re-apply or revert"
elif [ -z "$cur" ]; then
  oa_status_check green "firewall tcp/179" "not configured (optional defense-in-depth; --enable-firewall to add)"
elif ! printf '%s\n' "$cur" | grep -qE 'tcp dport 179 drop'; then
  oa_status_check red "firewall tcp/179" "managed table present but missing the default tcp/179 drop"
elif [ -z "$peers" ]; then
  oa_status_check yellow "firewall tcp/179" "drop in place, but no peers detected — may block all BGP"
else
  missing=""
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    # Escape dots for regex and match with non-IP-character boundaries to avoid
    # substring false positives (e.g. 10.0.0.1 inside 10.0.0.10).
    escaped=$(printf '%s' "$p" | sed 's/\./\\./g')
    printf '%s\n' "$cur" | grep -qE "(^|[^0-9.])$escaped([^0-9.]|$)" || missing="$missing $p"
  done <<EOF
$peers
EOF
  if [ -n "$missing" ]; then
    oa_status_check yellow "firewall tcp/179" "drop in place, but known peer(s) not in accept set:$missing"
  else
    oa_status_check green "firewall tcp/179" "tcp/179 restricted to known peer(s); default drop present"
  fi
fi

# --- (c) RPKI validation (OPTIONAL — minimal value for a stub AS) ---------
# RPKI is opt-in (--enable-rpki). For a single-homed stub AS that doesn't forward
# traffic, inbound RPKI changes no forwarding decision (every route resolves to
# the one peer), so its absence is GREEN, never yellow. When it IS configured,
# validate that the validator is actually up and FRR is querying it.
marker=$(bgp_rpki_marker_path)
rpki_running=0
bgp_service_active routinator && rpki_running=1
frr_rpki=$("$ONIONARMOR_BGP_VTYSH" -c "show rpki cache" 2>/dev/null || true)
if [ ! -e "$marker" ]; then
  oa_status_check green "RPKI validation" "not configured (optional; minimal value for a single-homed stub AS — see README)"
elif [ "$rpki_running" -ne 1 ]; then
  oa_status_check red "RPKI validation" "FRR configured for RPKI but routinator is not active"
elif printf '%s\n' "$frr_rpki" | grep -qF "$BGP_RPKI_CACHE_HOST"; then
  # Match the configured cache host specifically — not a bare "rpki" substring,
  # which could appear in unrelated/error output and false-pass.
  oa_status_check green "RPKI validation" "routinator active; FRR querying cache $BGP_RPKI_CACHE_HOST:$BGP_RPKI_CACHE_PORT"
else
  oa_status_check yellow "RPKI validation" "routinator active but FRR shows no rpki cache (reload FRR?)"
fi

# --- (d) FRR version (CVE awareness — advisory) --------------------------
ver=$(bgp_frr_version)
case "$(bgp_version_concern "$ver")" in
  ok)      oa_status_check green  "FRR version" "FRRouting $ver (>= fleet minimum $BGP_FRR_MIN_VERSION)" ;;
  flagged) oa_status_check yellow "FRR version" "FRRouting $ver is on the fleet advisory list — review CVEs / plan an upgrade" ;;
  old)     oa_status_check yellow "FRR version" "FRRouting $ver is below the fleet minimum $BGP_FRR_MIN_VERSION — plan an upgrade" ;;
  *)       oa_status_check yellow "FRR version" "could not determine the FRR version (vtysh unavailable?)" ;;
esac

oa_status_summary "one or more RED checks — BGP hardening posture is incomplete"
