#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the dns-posture. Read-only; never
# changes host state. Exits non-zero if ANY check is red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

dns_parse_flags "$@"

# Worst severity seen so far: 0 green, 1 yellow, 2 red.
_dns_worst=0

# dns_check <severity> <label> <detail>
#   severity: green|yellow|red
dns_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_DNS_GREEN; [ "$_dns_worst" -lt 0 ] && _dns_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_DNS_YEL; [ "$_dns_worst" -lt 1 ] && _dns_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_DNS_RED; _dns_worst=2 ;;
  esac
  printf '%s%s%s %-26s %s\n' "$col" "$mark" "$OA_DNS_OFF" "$label" "$detail"
}

info "dns-posture audit"
printf '\n'

# --- 1. unbound active ----------------------------------------------------
state=$("$ONIONARMOR_DNS_SYSTEMCTL" is-active unbound 2>/dev/null || true)
if [ "$state" = "active" ]; then
  dns_check green "unbound active" "systemctl is-active unbound = active"
else
  dns_check red "unbound active" "unbound is '$state' (expected active)"
fi

# --- 2. single trust anchor ----------------------------------------------
anchors=$(dns_count_anchor_lines)
case "$anchors" in
  1) dns_check green  "single trust anchor" "exactly 1 auto-trust-anchor-file" ;;
  0) dns_check yellow "single trust anchor" "no auto-trust-anchor-file (DNSSEC anchor absent)" ;;
  *) dns_check red    "single trust anchor" "$anchors auto-trust-anchor-file lines — DUPLICATE anchor (crashes unbound)" ;;
esac

# --- 3. resolv.conf is a real file pointing at the listener ---------------
stub=$(dns_stub_addrs | head -1)
if [ -L "$DNS_RESOLV_CONF" ]; then
  dns_check red "resolv.conf pinned" "$DNS_RESOLV_CONF is a symlink (expected a real file)"
elif [ ! -f "$DNS_RESOLV_CONF" ]; then
  dns_check red "resolv.conf pinned" "$DNS_RESOLV_CONF missing"
elif grep -qE "^[[:space:]]*nameserver[[:space:]]+$(printf '%s' "$stub" | sed 's/[.[\*^$/]/\\&/g')([[:space:]]|$)" "$DNS_RESOLV_CONF"; then
  dns_check green "resolv.conf pinned" "real file, nameserver $stub"
else
  dns_check red "resolv.conf pinned" "real file but no 'nameserver $stub' line"
fi

# --- 4. systemd-resolved masked ------------------------------------------
en=$("$ONIONARMOR_DNS_SYSTEMCTL" is-enabled systemd-resolved 2>/dev/null || true)
act=$("$ONIONARMOR_DNS_SYSTEMCTL" is-active systemd-resolved 2>/dev/null || true)
if [ "$DNS_MASK_RESOLVED" -eq 0 ]; then
  # apply was (or can be) run with --no-mask-resolved: masking is opt-out here,
  # so a running systemd-resolved is the operator's choice, not a red failure.
  # Pass the same --no-mask-resolved flag to audit to get this relaxed check.
  if [ "$en" = "masked" ]; then
    dns_check green  "systemd-resolved masked" "is-enabled = masked"
  else
    dns_check yellow "systemd-resolved masked" "--no-mask-resolved: left as-is (is-enabled=$en, is-active=$act)"
  fi
elif [ "$en" = "masked" ]; then
  dns_check green "systemd-resolved masked" "is-enabled = masked"
elif [ "$act" = "active" ]; then
  dns_check red "systemd-resolved masked" "still active (is-enabled=$en)"
else
  dns_check yellow "systemd-resolved masked" "not masked but inactive (is-enabled=$en)"
fi

# --- 5. forwarders are DoT/:853 only -------------------------------------
fwd=$("$ONIONARMOR_DNS_UNBOUND_CONTROL" list_forwards 2>/dev/null || true)
case "$(dns_forwards_classify "$fwd")" in
  only-dot) dns_check green  "forwarders DoT-only" "all forward-addr are @853" ;;
  has-do53) dns_check red    "forwarders DoT-only" "a plaintext :53 forwarder is present" ;;
  none)     dns_check yellow "forwarders DoT-only" "no forwarders reported (unbound-control reachable?)" ;;
esac

# --- 6. DNSSEC ad flag returns -------------------------------------------
if [ "$DNS_DNSSEC" -eq 1 ]; then
  dig_out=$("$ONIONARMOR_DNS_DIG" "@$stub" -p "$DNS_LISTEN_PORT" +dnssec cloudflare.com A 2>/dev/null || true)
  if printf '%s\n' "$dig_out" | grep -qE 'flags:[^;]* ad'; then
    dns_check green "DNSSEC ad flag" "validating answer carries the ad flag"
  else
    dns_check red "DNSSEC ad flag" "no ad flag in dig answer (validation not happening)"
  fi
else
  dns_check yellow "DNSSEC ad flag" "DNSSEC disabled (--no-dnssec); not checked"
fi

printf '\n'
case "$_dns_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — posture is broken"; exit 1 ;;
esac
