#!/usr/bin/env bash
# diff.sh — read-only preview of the kernel-reserved-ports posture.
#
# Compares the live net.ipv4.ip_local_reserved_ports value to the reservation
# this module would write for the given flags (--auto detection and/or explicit
# --reserved-range), and reports whether `apply` would change it. PURE READ:
# never writes the drop-in, never runs `sysctl -w` or `sysctl --system`.
# Exits 0 regardless of drift.
#
# The would-be value is a single (possibly long) comma-joined range string, so
# this prints a labelled block rather than the fixed-width sysctl table the
# kernel-hardening diff uses.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

krp_parse_flags "$@"
krp_load_apply_filters

want=$(krp_compute_ranges)
live=$(krp_sysctl_runtime)

info "kernel-reserved-ports diff (read-only preview; no host changes)"
printf '\n'
printf '%-10s %s\n' "KEY" "$KRP_SYSCTL_KEY"
printf '%-10s %s\n' "CURRENT" "${live:-<empty>}"

if [ -z "$want" ]; then
  printf '%-10s %s\n' "WOULD-BE" "<none computed>"
  printf '%-10s %s\n' "DELTA" "no ranges to reserve (pass --auto or --reserved-range)"
  printf '\nPreview only — nothing was written.\n'
  exit 0
fi

printf '%-10s %s\n' "WOULD-BE" "$want"
if [ "$(krp_canon "$live")" = "$(krp_canon "$want")" ]; then
  printf '%-10s %s\n' "DELTA" "(no change)"
else
  printf '%-10s %s\n' "DELTA" "→ reserve"
fi

printf '\nPreview only — nothing was written.\n'
printf 'Apply with: onionarmor apply --module kernel-reserved-ports %s\n' \
  "$([ "$KRP_AUTO" -eq 1 ] && printf -- '--auto' || printf -- '--reserved-range %s' "$KRP_RANGES")"
