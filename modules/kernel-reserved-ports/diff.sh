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
# NB: deliberately NOT loading persisted apply-filters here. `diff` must preview
# what `apply` would write for THESE flags — apply itself computes from the CLI
# flags (defaults if unset) and does not read apply-filters.conf — so loading
# stale filters would make the preview diverge from the apply it previews.

want=$(krp_compute_ranges)
live=$(krp_sysctl_runtime)

info "kernel-reserved-ports diff (read-only preview; no host changes)"
printf '\n'
printf '%-10s %s\n' "KEY" "$KRP_SYSCTL_KEY"
printf '%-10s %s\n' "CURRENT" "${live:-<empty>}"

if [ -z "$want" ]; then
  printf '%-10s %s\n' "WOULD-BE" "<none computed>"
  if [ "$KRP_AUTO" -eq 1 ]; then
    # --auto was asked for but detection found nothing — call that out so an
    # empty reservation isn't silently mistaken for "no flags given".
    printf '%-10s %s\n' "DELTA" "--auto detected no loopback tor ports to reserve"
  else
    printf '%-10s %s\n' "DELTA" "no ranges to reserve (pass --auto or --reserved-range)"
  fi
  printf '\nPreview only — nothing was written.\n'
  exit 0
fi

printf '%-10s %s\n' "WOULD-BE" "$want"
if [ "$(krp_canon "$live")" = "$(krp_canon "$want")" ]; then
  printf '%-10s %s\n' "DELTA" "(no change)"
else
  printf '%-10s %s\n' "DELTA" "→ reserve"
fi

# Echo back the flags that produced this preview so the hint matches the run.
apply_flags=""
[ "$KRP_AUTO" -eq 1 ] && apply_flags="--auto"
[ -n "$KRP_RANGES" ] && apply_flags="${apply_flags:+$apply_flags }--reserved-range $KRP_RANGES"
printf '\nPreview only — nothing was written.\n'
printf 'Apply with: onionarmor apply --module kernel-reserved-ports %s\n' "$apply_flags"
