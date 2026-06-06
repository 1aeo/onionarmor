#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the kernel-reserved-ports posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) the managed drop-in is present,
#   (b) the live sysctl value matches the drop-in,
#   (c) (with --auto) every tor loopback port is covered by the reservation.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

krp_parse_flags "$@"

# Worst severity seen so far: 0 green, 1 yellow, 2 red.
_krp_worst=0

# krp_check <severity> <label> <detail>
krp_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_KRP_GREEN; [ "$_krp_worst" -lt 0 ] && _krp_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_KRP_YEL; [ "$_krp_worst" -lt 1 ] && _krp_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_KRP_RED; _krp_worst=2 ;;
  esac
  printf '%s%s%s %-26s %s\n' "$col" "$mark" "$OA_KRP_OFF" "$label" "$detail"
}

info "kernel-reserved-ports audit"
printf '\n'

dropin=$(krp_dropin_path)
dropin_val=$(krp_dropin_value)

# --- (a) drop-in present --------------------------------------------------
if [ ! -f "$dropin" ]; then
  krp_check red "drop-in present" "$dropin missing — run: onionarmor apply --module kernel-reserved-ports --auto"
elif [ -z "$dropin_val" ]; then
  krp_check red "drop-in present" "$dropin exists but declares no $KRP_SYSCTL_KEY"
else
  krp_check green "drop-in present" "$dropin -> $dropin_val"
fi

# --- (b) runtime sysctl matches drop-in -----------------------------------
live=$(krp_sysctl_runtime)
if [ -z "$dropin_val" ]; then
  krp_check yellow "runtime matches drop-in" "no drop-in value to compare (live=${live:-<empty>})"
elif [ "$(krp_canon "$live")" = "$(krp_canon "$dropin_val")" ]; then
  krp_check green "runtime matches drop-in" "$KRP_SYSCTL_KEY = ${live:-<empty>}"
else
  krp_check red "runtime matches drop-in" "live '$live' != drop-in '$dropin_val' (run: $ONIONARMOR_SYSCTL_CMD --system)"
fi

# --- (c) every tor loopback port is covered (only with --auto) ------------
if [ "$KRP_AUTO" -eq 1 ]; then
  if [ -z "$dropin_val" ]; then
    krp_check yellow "tor ports covered" "no drop-in value to compare against detected tor ports"
  else
    # Compare the CURRENT auto-detected tor ports against what the drop-in
    # actually reserves — surfacing drift (e.g. new instances added since apply).
    uncovered=$(krp_detect_ports | sort -n -u | krp_uncovered_ports "$dropin_val")
    detected=$(krp_detect_ports | sort -n -u | wc -l | tr -d ' ')
    if [ "$detected" -eq 0 ]; then
      krp_check yellow "tor ports covered" "no loopback tor ports detected in torrc (nothing to cover)"
    elif [ -z "$uncovered" ]; then
      krp_check green "tor ports covered" "all $detected detected loopback tor port(s) inside the reservation"
    else
      gap=$(printf '%s\n' "$uncovered" | krp_compact_ports "$KRP_CLUSTER_GAP" | krp_pairs_to_csv)
      nun=$(printf '%s\n' "$uncovered" | grep -c .)
      krp_check red "tor ports covered" "drift: $nun tor port(s) NOT reserved ($gap) — reservation is '$dropin_val'"
    fi
  fi
else
  krp_check yellow "tor ports covered" "pass --auto to cross-check torrc ports against the reservation"
fi

printf '\n'
case "$_krp_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — reservation posture is broken or drifted"; exit 1 ;;
esac
