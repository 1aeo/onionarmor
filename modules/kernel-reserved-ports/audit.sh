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

# With --auto, load the apply-time filter parameters (if any) so the coverage
# check uses the same port-detection scope that apply used. This prevents false
# drift reports when apply was run with e.g. --listen-ip or --min-port.
krp_load_apply_filters

info "kernel-reserved-ports audit"
printf '\n'

dropin=$(krp_dropin_path)
dropin_val=$(krp_dropin_value)

# --- (a) drop-in present --------------------------------------------------
if [ ! -f "$dropin" ]; then
  oa_status_check red "drop-in present" "$dropin missing — run: onionarmor apply --module kernel-reserved-ports --auto"
elif [ -z "$dropin_val" ]; then
  oa_status_check red "drop-in present" "$dropin exists but declares no $KRP_SYSCTL_KEY"
else
  oa_status_check green "drop-in present" "$dropin -> $dropin_val"
fi

# --- (b) runtime sysctl matches drop-in -----------------------------------
live=$(krp_sysctl_runtime)
if [ -z "$dropin_val" ]; then
  oa_status_check yellow "runtime matches drop-in" "no drop-in value to compare (live=${live:-<empty>})"
elif [ "$(krp_canon "$live")" = "$(krp_canon "$dropin_val")" ]; then
  oa_status_check green "runtime matches drop-in" "$KRP_SYSCTL_KEY = ${live:-<empty>}"
else
  oa_status_check red "runtime matches drop-in" "live '$live' != drop-in '$dropin_val' (run: $ONIONARMOR_SYSCTL_CMD --system)"
fi

# --- (c) every tor loopback port is covered (only with --auto) ------------
if [ "$KRP_AUTO" -eq 1 ] && [ -z "$dropin_val" ]; then
  # With no reservation in place there is nothing to drift FROM — the missing
  # drop-in is already RED in check (a). Calling every tor port "uncovered
  # drift" here would be a misleading second red for one root cause.
  oa_status_check yellow "tor ports covered" "no reservation in place yet (see the drop-in check above)"
elif [ "$KRP_AUTO" -eq 1 ]; then
  # Compare the CURRENT auto-detected tor ports against what the drop-in
  # actually reserves — surfacing drift (e.g. new instances added since apply).
  # Detect once; an empty list means there is nothing to cover.
  detected_ports=$(krp_detect_ports | sort -n -u)
  if [ -z "$detected_ports" ]; then
    oa_status_check yellow "tor ports covered" "no loopback tor ports detected in torrc (nothing to cover)"
  else
    detected=$(printf '%s\n' "$detected_ports" | grep -c .)
    uncovered=$(printf '%s\n' "$detected_ports" | krp_uncovered_ports "$dropin_val")
    if [ -z "$uncovered" ]; then
      oa_status_check green "tor ports covered" "all $detected detected loopback tor port(s) inside the reservation"
    else
      gap=$(printf '%s\n' "$uncovered" | krp_compact_ports "$KRP_CLUSTER_GAP" | krp_pairs_to_csv)
      n_uncovered=$(printf '%s\n' "$uncovered" | grep -c .)
      oa_status_check red "tor ports covered" "drift: $n_uncovered tor port(s) NOT reserved ($gap) — reservation is '$dropin_val'"
    fi
  fi
else
  oa_status_check yellow "tor ports covered" "pass --auto to cross-check torrc ports against the reservation"
fi

oa_status_summary "one or more RED checks — reservation posture is broken or drifted"
