#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the systemd-hardening posture. For each
# present unit: drop-in present + checksum, and the hardening directives that
# are actually EFFECTIVE per `systemctl show`. Read-only; non-zero if any red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sh_parse_flags "$@"

_sh_worst=0
sh_check() {
  local sev=$1 label=$2 detail=$3 mark col
  case "$sev" in
    green)  mark="[ ok ]"; col=$OA_SH_GREEN; [ "$_sh_worst" -lt 0 ] && _sh_worst=0 ;;
    yellow) mark="[warn]"; col=$OA_SH_YEL; [ "$_sh_worst" -lt 1 ] && _sh_worst=1 ;;
    red)    mark="[FAIL]"; col=$OA_SH_RED; _sh_worst=2 ;;
  esac
  printf '%s%s%s %-34s %s\n' "$col" "$mark" "$OA_SH_OFF" "$label" "$detail"
}

# sh_show_prop <unit> <prop>: effective value via systemctl show --value.
sh_show_prop() {
  "$ONIONARMOR_SH_SYSTEMCTL" show "$1" --property="$2" --value 2>/dev/null || true
}

# The directives audit confirms are EFFECTIVE (a representative subset of the
# full drop-in) plus their expected value.
OA_SH_AUDIT_PROPS="NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes"

info "systemd-hardening audit"
printf '\n'

UNITS=()
while IFS= read -r _u; do [ -n "$_u" ] && UNITS+=("$_u"); done < <(sh_detect_units)
if [ "${#UNITS[@]}" -eq 0 ]; then
  sh_check yellow "managed units" "none present (tor@*/onionwarden/onionleak-*) — nothing to audit"
  printf '\n'
  info "audit: green/yellow — no managed units on this host"
  exit 0
fi

for u in "${UNITS[@]}"; do
  printf '%s:\n' "$u"
  path=$(sh_dropin_path "$u")

  # --- drop-in present + managed + matches the rendered posture ---
  rendered=$(sh_render_dropin "$u")
  sum=$(sh_checksum "$path")
  if [ ! -f "$path" ]; then
    sh_check red "  drop-in present" "missing: $path"
  elif ! sh_is_managed_dropin "$path"; then
    sh_check red "  drop-in present" "present but not onionarmor-managed (sha256:$sum)"
  elif [ "$(cat "$path")" = "$rendered" ]; then
    sh_check green "  drop-in present" "managed, matches posture (sha256:$sum)"
  else
    sh_check red "  drop-in present" "managed but DRIFTED from posture (sha256:$sum) — re-apply"
  fi

  # --- effective hardening directives (systemctl show) ---
  while IFS='=' read -r prop want; do
    [ -n "$prop" ] || continue
    got=$(sh_show_prop "$u" "$prop")
    if [ "$got" = "$want" ]; then
      sh_check green "  $prop" "effective=$got"
    else
      sh_check red "  $prop" "effective='$got' (expected '$want')"
    fi
  done <<EOF
$OA_SH_AUDIT_PROPS
EOF

  # --- CapabilityBoundingSet (report effective; empty = all dropped) ---
  caps=$(sh_show_prop "$u" CapabilityBoundingSet)
  want_caps=$(sh_caps_for_unit "$u")
  if [ -z "$want_caps" ]; then
    sh_check green "  CapabilityBoundingSet" "effective='${caps:-<all dropped>}' (policy: drop all)"
  else
    sh_check green "  CapabilityBoundingSet" "effective='$caps' (policy: $want_caps)"
  fi
done

printf '\n'
case "$_sh_worst" in
  0) info "audit: all green"; exit 0 ;;
  1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
  2) warn "audit: one or more RED checks — posture is broken"; exit 1 ;;
esac
