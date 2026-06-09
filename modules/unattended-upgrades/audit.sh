#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the unattended-upgrades posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

uu_parse_flags "$@"

# Worst severity seen so far: 0 green, 1 yellow, 2 red.
_uu_worst=0

# uu_check <severity> <label> <detail>
uu_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_UU_GREEN; [ "$_uu_worst" -lt 0 ] && _uu_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_UU_YEL; [ "$_uu_worst" -lt 1 ] && _uu_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_UU_RED; _uu_worst=2 ;;
  esac
  printf '%s%s%s %-26s %s\n' "$col" "$mark" "$OA_UU_OFF" "$label" "$detail"
}

info "unattended-upgrades audit"
printf '\n'

f50=$(uu_50_path)
f20=$(uu_20_path)

# --- 1. service enabled + active -----------------------------------------
en=$("$ONIONARMOR_UU_SYSTEMCTL" is-enabled "$ONIONARMOR_UU_SERVICE" 2>/dev/null || true)
act=$("$ONIONARMOR_UU_SYSTEMCTL" is-active "$ONIONARMOR_UU_SERVICE" 2>/dev/null || true)
# The unit is oneshot-ish: "active" is normal, but so is being enabled and
# briefly inactive between runs. Enabled is the load-bearing check.
if [ "$en" = "enabled" ] && { [ "$act" = "active" ] || [ "$act" = "inactive" ]; }; then
  uu_check green "service enabled" "is-enabled=$en, is-active=$act"
elif [ "$en" = "masked" ]; then
  uu_check red "service enabled" "$ONIONARMOR_UU_SERVICE is masked (upgrades disabled)"
elif [ "$en" = "enabled" ]; then
  uu_check yellow "service enabled" "is-enabled=$en, is-active=$act"
else
  uu_check red "service enabled" "is-enabled=$en (expected enabled)"
fi

# --- 2. managed config files present + match the posture ------------------
uu_audit_conf() {
  # uu_audit_conf <label> <path> <rendered>
  local label=$1 path=$2 rendered=$3 sum
  sum=$(uu_checksum "$path")
  if [ ! -f "$path" ]; then
    uu_check red "$label" "missing: $path"
  elif [ "$(cat "$path")" = "$rendered" ]; then
    uu_check green "$label" "present, matches posture (sha256:$sum)"
  elif grep -q 'Managed by onionarmor' "$path" 2>/dev/null; then
    uu_check red "$label" "onionarmor-managed but DRIFTED from posture (sha256:$sum) — re-apply"
  else
    uu_check red "$label" "present but not onionarmor-managed (sha256:$sum)"
  fi
}
uu_audit_conf "50 config present" "$f50" "$(uu_render_50)"
uu_audit_conf "20 config present" "$f20" "$(uu_render_20)"

# --- 3. last unattended-upgrade run --------------------------------------
last=$(uu_last_run)
if [ -n "$last" ]; then
  uu_check green "last run" "$last (from $(basename "$ONIONARMOR_UU_LOG"))"
elif [ -f "$ONIONARMOR_UU_LOG" ]; then
  uu_check yellow "last run" "log present but no timestamped run yet: $ONIONARMOR_UU_LOG"
else
  uu_check yellow "last run" "no log yet at $ONIONARMOR_UU_LOG (service may not have run)"
fi

# --- 4. apt holds (advisory — held packages are skipped by upgrades) ------
holds=$(uu_holds)
if [ -z "$holds" ]; then
  uu_check green "apt holds" "none — nothing pinned out of upgrades"
else
  uu_check yellow "apt holds" "held (skipped by unattended-upgrade): $(printf '%s' "$holds" | tr '\n' ' ')"
fi

printf '\n'
case "$_uu_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — posture is broken"; exit 1 ;;
esac
