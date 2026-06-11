#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the mac-profile-install posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# green  = the LSM is enforcing and (AppArmor) the tor profile is in enforce mode.
# yellow = installed but complain/permissive, or the tor profile is absent.
# red    = no MAC LSM is active at all.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

lsm=$(mac_detect_lsm)

info "mac-profile-install audit (LSM: $lsm)"
printf '\n'

if [ "$lsm" = "apparmor" ]; then
  # --- 1. AppArmor installed/active ---------------------------------------
  if ! mac_aa_installed; then
    oa_status_check red "AppArmor installed" "aa-status not found — no mandatory access control"
  elif mac_aa_active; then
    oa_status_check green "AppArmor active" "aa-status reports AppArmor enabled"
  else
    oa_status_check red "AppArmor active" "AppArmor is installed but not active"
  fi

  # --- 2. kernel cmdline tokens -------------------------------------------
  if mac_grub_has_tokens; then
    oa_status_check green "kernel cmdline" "$ONIONARMOR_MAC_GRUB_TOKENS present in $(basename "$ONIONARMOR_GRUB_FILE")"
  else
    oa_status_check yellow "kernel cmdline" "missing $ONIONARMOR_MAC_GRUB_TOKENS — apply, then reboot"
  fi

  # --- 3. tor profile loaded + enforced -----------------------------------
  if ! mac_aa_tor_profile_exists; then
    oa_status_check yellow "tor profile" "no tor profile installed at $(mac_tor_profile_path)"
  else
    tor_mode=$(mac_aa_tor_mode)
    case "$tor_mode" in
      enforce)  oa_status_check green  "tor profile" "loaded and in enforce mode" ;;
      complain) oa_status_check yellow "tor profile" "loaded but in complain mode — apply to enforce" ;;
      *)        oa_status_check yellow "tor profile" "profile on disk but not loaded — apply to enforce" ;;
    esac
  fi

else
  # --- 1. SELinux installed/present ---------------------------------------
  if ! mac_se_installed; then
    oa_status_check red "SELinux installed" "sestatus not found — no mandatory access control"
  else
    cur=$(mac_se_current_mode)
    case "$cur" in
      enforcing)  oa_status_check green  "SELinux mode" "current mode: enforcing" ;;
      permissive) oa_status_check yellow "SELinux mode" "current mode: permissive — apply to enforce" ;;
      disabled)   oa_status_check red    "SELinux mode" "current mode: disabled — no mandatory access control" ;;
      "")         oa_status_check red    "SELinux mode" "sestatus did not report a current mode" ;;
      *)          oa_status_check yellow "SELinux mode" "current mode: $cur" ;;
    esac
  fi

  # --- 2. config requests enforcing ---------------------------------------
  cfg=$(mac_se_config_mode)
  case "$cfg" in
    enforcing)  oa_status_check green  "config enforcing" "SELINUX=enforcing in $(basename "$ONIONARMOR_MAC_SELINUX_CONFIG")" ;;
    permissive) oa_status_check yellow "config enforcing" "SELINUX=permissive — apply to set enforcing" ;;
    disabled)   oa_status_check red    "config enforcing" "SELINUX=disabled — apply to enable" ;;
    "")         oa_status_check yellow "config enforcing" "no SELINUX= line in $(basename "$ONIONARMOR_MAC_SELINUX_CONFIG")" ;;
    *)          oa_status_check yellow "config enforcing" "SELINUX=$cfg" ;;
  esac
fi

oa_status_summary "no mandatory access control LSM is enforcing"
