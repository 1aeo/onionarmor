#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the kernel-hardening posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) the managed drop-in is present and matches the rendered posture,
#   (b) every managed KSPP key's live sysctl value matches the target.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

info "kernel-hardening audit"
printf '\n'

dropin=$(kh_dropin_path)
rendered=$(kh_render_dropin)

# --- (a) drop-in present + matches the rendered posture -------------------
if [ ! -f "$dropin" ]; then
  oa_status_check red "drop-in present" "$dropin missing — run: onionarmor apply --module kernel-hardening"
elif [ "$(cat "$dropin")" = "$rendered" ]; then
  oa_status_check green "drop-in present" "$dropin (matches KSPP posture)"
else
  oa_status_check red "drop-in present" "$dropin DRIFTED from posture — re-apply"
fi

# --- (b) every managed key's live value matches the target ----------------
while read -r key val; do
  [ -n "$key" ] || continue
  live=$(kh_sysctl_runtime "$key")
  if [ -z "$live" ]; then
    oa_status_check yellow "$key" "not readable on this kernel (expected $val)"
  elif [ "$(kh_norm "$live")" = "$(kh_norm "$val")" ]; then
    oa_status_check green "$key" "= $live"
  else
    oa_status_check red "$key" "live '$live' != target '$val' (run: $ONIONARMOR_SYSCTL_CMD --system)"
  fi
done <<EOF
$KH_TARGETS
EOF

oa_status_summary "one or more RED checks — kernel-hardening posture is broken or drifted"
