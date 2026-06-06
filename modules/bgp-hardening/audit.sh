#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the bgp-hardening posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) bgpd listener is bound to a specific IP, not 0.0.0.0 / [::],
#   (b) the firewall restricts tcp/179 to the known peer IP(s),
#   (c) the RPKI validator is running locally and FRR is configured to query it,
#   (d) FRR is a current release (CVE awareness — advisory only).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

bgp_parse_flags "$@"

_bgp_worst=0
bgp_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_BGP_GREEN; [ "$_bgp_worst" -lt 0 ] && _bgp_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_BGP_YEL; [ "$_bgp_worst" -lt 1 ] && _bgp_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_BGP_RED; _bgp_worst=2 ;;
  esac
  printf '%s%s%s %-26s %s\n' "$col" "$mark" "$OA_BGP_OFF" "$label" "$detail"
}

info "bgp-hardening audit"
printf '\n'

# --- (a) listener bind ----------------------------------------------------
bind=$(bgp_listener_bind)
if [ -z "$bind" ]; then
  bgp_check yellow "listener bind" "no tcp/179 listener found (is bgpd running?)"
elif bgp_bind_is_wildcard "$bind"; then
  bgp_check red "listener bind" "bgpd bound to $bind (wildcard) — set -l <peer-facing-ip> via apply"
else
  bgp_check green "listener bind" "bgpd bound to $bind (specific)"
fi

# --- (b) firewall restricts tcp/179 --------------------------------------
peers=$(bgp_resolve_peers)
if [ "$BGP_FIREWALL" = "nftables" ]; then
  cur=$(bgp_nft_current)
  if [ -z "$cur" ]; then
    bgp_check red "firewall tcp/179" "no managed nft table inet $BGP_NFT_TABLE — run apply"
  elif ! printf '%s\n' "$cur" | grep -qE 'tcp dport 179 drop'; then
    bgp_check red "firewall tcp/179" "managed table present but missing the default tcp/179 drop"
  else
    # Every known peer must appear in the accept set; otherwise it's drift.
    # If no peers are detected, that's a configuration problem.
    if [ -z "$peers" ]; then
      bgp_check yellow "firewall tcp/179" "drop in place, but no peers detected — may block all BGP"
    else
      missing=""
      while IFS= read -r p; do
        [ -n "$p" ] || continue
        printf '%s\n' "$cur" | grep -qF "$p" || missing="$missing $p"
      done <<EOF
$peers
EOF
      if [ -n "$missing" ]; then
        bgp_check yellow "firewall tcp/179" "drop in place, but known peer(s) not in accept set:$missing"
      else
        bgp_check green "firewall tcp/179" "tcp/179 restricted to known peer(s); default drop present"
      fi
    fi
  fi
else
  if "$ONIONARMOR_BGP_UFW" status 2>/dev/null | grep -qE '179'; then
    bgp_check green "firewall tcp/179" "ufw has tcp/179 rules"
  else
    bgp_check red "firewall tcp/179" "ufw has no tcp/179 rule — run apply"
  fi
fi

# --- (c) RPKI validator running + FRR querying it ------------------------
marker=$(bgp_rpki_marker_path)
rpki_running=0
bgp_service_active routinator && rpki_running=1
frr_rpki=$("$ONIONARMOR_BGP_VTYSH" -c "show rpki cache" 2>/dev/null || true)
if [ ! -e "$marker" ]; then
  bgp_check yellow "RPKI validation" "not configured by this module (run apply, or --no-enable-rpki)"
elif [ "$rpki_running" -ne 1 ]; then
  bgp_check red "RPKI validation" "FRR configured for RPKI but routinator is not active"
elif printf '%s\n' "$frr_rpki" | grep -qE "$BGP_RPKI_CACHE_HOST|rpki"; then
  bgp_check green "RPKI validation" "routinator active; FRR querying cache $BGP_RPKI_CACHE_HOST:$BGP_RPKI_CACHE_PORT"
else
  bgp_check yellow "RPKI validation" "routinator active but FRR shows no rpki cache (reload FRR?)"
fi

# --- (d) FRR version (CVE awareness — advisory) --------------------------
ver=$(bgp_frr_version)
case "$(bgp_version_concern "$ver")" in
  ok)      bgp_check green  "FRR version" "FRRouting $ver (>= fleet minimum $BGP_FRR_MIN_VERSION)" ;;
  flagged) bgp_check yellow "FRR version" "FRRouting $ver is on the fleet advisory list — review CVEs / plan an upgrade" ;;
  old)     bgp_check yellow "FRR version" "FRRouting $ver is below the fleet minimum $BGP_FRR_MIN_VERSION — plan an upgrade" ;;
  *)       bgp_check yellow "FRR version" "could not determine the FRR version (vtysh unavailable?)" ;;
esac

printf '\n'
case "$_bgp_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — BGP hardening posture is incomplete"; exit 1 ;;
esac
