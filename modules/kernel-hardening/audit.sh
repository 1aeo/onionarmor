#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the kernel-hardening posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# If the managed drop-in is absent -> one yellow "not applied" check. Otherwise
# one check per KSPP key comparing the live sysctl value to the target:
#   green  — live matches target
#   red    — live drifts from target
#   yellow — key unreadable/missing on this kernel (module/arch-dependent)

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

info "kernel-hardening audit"
printf '\n'

dropin=$(kh_dropin_path)

if [ ! -f "$dropin" ]; then
  oa_status_check yellow "drop-in present" "$dropin missing — not applied (run: onionarmor apply --module kernel-hardening)"
  oa_status_summary "one or more kernel hardening sysctls drift from the KSPP target"
fi

oa_status_check green "drop-in present" "$dropin"

while read -r key want; do
  live=$(kh_sysctl_runtime "$key")
  if [ -z "$live" ]; then
    oa_status_check yellow "$key" "unreadable on this kernel (want $want)"
  elif [ "$(kh_normalise "$live")" = "$(kh_normalise "$want")" ]; then
    oa_status_check green "$key" "= $live"
  else
    oa_status_check red "$key" "live '$live' != target '$want'"
  fi
done < <(kh_each_key)

oa_status_summary "one or more kernel hardening sysctls drift from the KSPP target"
