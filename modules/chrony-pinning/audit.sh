#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the chrony-pinning posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

chr_parse_flags "$@"
chr_read_state  # override defaults with persisted state from apply

_chr_worst=0
chr_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_CHR_GREEN; [ "$_chr_worst" -lt 0 ] && _chr_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_CHR_YEL; [ "$_chr_worst" -lt 1 ] && _chr_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_CHR_RED; _chr_worst=2 ;;
  esac
  printf '%s%s%s %-28s %s\n' "$col" "$mark" "$OA_CHR_OFF" "$label" "$detail"
}

info "chrony-pinning audit"
printf '\n'

sources=$(chr_sources_path)

# --- 1. chrony active -----------------------------------------------------
state=$("$ONIONARMOR_CHR_SYSTEMCTL" is-active "$ONIONARMOR_CHR_SERVICE" 2>/dev/null || true)
if [ "$state" = "active" ]; then
  chr_check green "chrony active" "systemctl is-active $ONIONARMOR_CHR_SERVICE = active"
else
  chr_check red "chrony active" "$ONIONARMOR_CHR_SERVICE is '$state' (expected active)"
fi

# --- 2. managed sources file present + matches the posture ----------------
if [ ! -f "$sources" ]; then
  chr_check red "sources pinned" "missing: $sources"
elif ! grep -q 'Managed by onionarmor (module: chrony-pinning)' "$sources" 2>/dev/null; then
  chr_check red "sources pinned" "present but not onionarmor-managed: $sources"
elif [ "$(cat "$sources")" = "$(chr_render_sources)" ]; then
  chr_check green "sources pinned" "managed, matches posture"
else
  chr_check yellow "sources pinned" "managed but differs from current posture (custom sources?)"
fi

# --- 3. systemd-timesyncd masked (only chrony should discipline the clock) --
en=$("$ONIONARMOR_CHR_SYSTEMCTL" is-enabled "$ONIONARMOR_CHR_TIMESYNCD" 2>/dev/null || true)
if [ "$CHR_MASK_TIMESYNCD" -eq 0 ]; then
  chr_check yellow "timesyncd masked" "--no-mask-timesyncd: not enforced (is-enabled=$en)"
elif [ "$en" = "masked" ]; then
  chr_check green "timesyncd masked" "is-enabled = masked"
else
  chr_check red "timesyncd masked" "$ONIONARMOR_CHR_TIMESYNCD is '$en' (competing time daemon)"
fi

# --- 4. >=2 reachable stratum-1 sources -----------------------------------
srcs=$("$ONIONARMOR_CHR_CHRONYC" -n sources 2>/dev/null || true)
n=$(chr_count_reachable_stratum1 "$srcs")
if [ "$n" -ge 2 ]; then
  chr_check green "stratum-1 reachable" "$n reachable stratum-1 sources"
elif [ "$n" -eq 1 ]; then
  chr_check yellow "stratum-1 reachable" "only 1 reachable stratum-1 (no source diversity)"
else
  chr_check red "stratum-1 reachable" "0 reachable stratum-1 sources (chronyc -n sources)"
fi

# --- 5. system offset within threshold ------------------------------------
trk=$("$ONIONARMOR_CHR_CHRONYC" tracking 2>/dev/null || true)
off=$(chr_offset_seconds "$trk")
if [ -z "$off" ]; then
  chr_check yellow "offset within ${CHR_OFFSET_MS}ms" "could not read offset from chronyc tracking"
else
  # Compare |offset_seconds| * 1000 <= threshold_ms using awk (float math). Take
  # the magnitude here too so a negative offset can never slip under the
  # threshold even if an upstream parser ever stops stripping the sign.
  within=$(awk -v o="$off" -v t="$CHR_OFFSET_MS" 'BEGIN { a = (o < 0 ? -o : o); print (a*1000 <= t) ? 1 : 0 }')
  off_ms=$(awk -v o="$off" 'BEGIN { a = (o < 0 ? -o : o); printf "%.3f", a*1000 }')
  if [ "$within" = "1" ]; then
    chr_check green "offset within ${CHR_OFFSET_MS}ms" "last |offset| ${off_ms}ms"
  else
    chr_check red "offset within ${CHR_OFFSET_MS}ms" "last |offset| ${off_ms}ms exceeds ${CHR_OFFSET_MS}ms"
  fi
fi

printf '\n'
case "$_chr_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — posture is broken"; exit 1 ;;
esac
