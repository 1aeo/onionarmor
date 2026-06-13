#!/usr/bin/env bash
# diff.sh — read-only preview of the kernel-hardening posture.
#
# For every KSPP sysctl this module would write, show the live runtime value,
# the would-be (target) value, and whether `apply` would change it. PURE READ:
# never writes the drop-in, never runs `sysctl -w` or `sysctl --system`. Exits 0
# regardless of how many keys would change (a drifted host is not an error here).
#
#   KEY                                   CURRENT    WOULD-BE   DELTA
#   ------------------------------------- ---------- ---------- ------
#   kernel.kptr_restrict                  2          2          (no change)
#   kernel.kexec_load_disabled            0          1          → harden

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

info "kernel-hardening diff (read-only preview; no host changes)"
printf '\n'
# shellcheck disable=SC2059  # format is a centralised constant, not user input
printf "$_OA_FMT_SYSCTL_ROW" "KEY" "CURRENT" "WOULD-BE" "DELTA"
# shellcheck disable=SC2059
printf "$_OA_FMT_SYSCTL_ROW" "$_OA_DASH_SYSCTL_ROW" "$_OA_DASH_SYSCTL_COL" "$_OA_DASH_SYSCTL_COL" "------"

changes=0 total=0
while read -r key want; do
  total=$((total + 1))
  live=$(kh_sysctl_runtime "$key")
  if [ -z "$live" ]; then
    # Key unreadable on this kernel (module/arch-dependent). Not counted as a
    # change we can promise to make; flag it so the operator can verify.
    # shellcheck disable=SC2059
    printf "$_OA_FMT_SYSCTL_ROW" "$key" "<unreadable>" "$want" "? unreadable"
  elif [ "$(kh_normalise "$live")" = "$(kh_normalise "$want")" ]; then
    # shellcheck disable=SC2059
    printf "$_OA_FMT_SYSCTL_ROW" "$key" "$live" "$want" "(no change)"
  else
    changes=$((changes + 1))
    # shellcheck disable=SC2059
    printf "$_OA_FMT_SYSCTL_ROW" "$key" "$live" "$want" "→ harden"
  fi
done < <(kh_each_key)

printf '\n%d/%d KSPP keys would change. Preview only — nothing was written.\n' "$changes" "$total"
printf 'Apply with: onionarmor apply --module kernel-hardening\n'
