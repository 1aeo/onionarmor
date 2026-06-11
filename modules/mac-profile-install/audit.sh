#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the mac-profile-install posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# Reports the active LSM, its enforce state, and the tor profile status:
#   AppArmor: tor profile loaded+enforcing -> green; present-but-complain ->
#             yellow; absent / aa-status unavailable -> red.
#   SELinux:  running mode enforcing -> green; permissive -> yellow; disabled /
#             config not enforcing -> red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

info "mac-profile-install audit (distro family: $MAC_DISTRO)"
printf '\n'

if [ "$MAC_DISTRO" = "debian" ]; then
  # --- active LSM ---------------------------------------------------------
  oa_status_check green "active LSM" "AppArmor (Debian/Ubuntu family)"

  # --- tor profile state --------------------------------------------------
  case "$(mac_apparmor_tor_state)" in
    enforce)
      oa_status_check green "tor profile" "loaded + enforcing ($ONIONARMOR_MAC_APPARMOR_PROFILE)"
      ;;
    complain)
      oa_status_check yellow "tor profile" "loaded but in COMPLAIN mode (not enforced) — run apply to enforce"
      ;;
    absent)
      oa_status_check red "tor profile" "no tor profile loaded — run: onionarmor apply --module mac-profile-install"
      ;;
    *)
      oa_status_check red "tor profile" "aa-status unavailable ($ONIONARMOR_MAC_AA_STATUS) — is AppArmor installed?"
      ;;
  esac
else
  # --- active LSM + running enforce state ---------------------------------
  case "$(mac_selinux_runtime_mode)" in
    enforcing)
      oa_status_check green "active LSM" "SELinux running in ENFORCING mode"
      ;;
    permissive)
      oa_status_check yellow "active LSM" "SELinux running in PERMISSIVE mode (logs, does not block) — run apply"
      ;;
    disabled)
      oa_status_check red "active LSM" "SELinux is DISABLED — run: onionarmor apply --module mac-profile-install"
      ;;
    *)
      oa_status_check red "active LSM" "sestatus unavailable ($ONIONARMOR_MAC_SESTATUS) — is SELinux installed?"
      ;;
  esac

  # --- persisted config mode (survives reboot) ----------------------------
  case "$(mac_selinux_config_mode)" in
    enforcing)
      oa_status_check green "config persistence" "SELINUX=enforcing in $ONIONARMOR_MAC_SELINUX_CONFIG (survives reboot)"
      ;;
    permissive)
      oa_status_check yellow "config persistence" "SELINUX=permissive in $ONIONARMOR_MAC_SELINUX_CONFIG — reboot would relax"
      ;;
    *)
      oa_status_check red "config persistence" "SELINUX not set to enforcing in $ONIONARMOR_MAC_SELINUX_CONFIG"
      ;;
  esac
fi

oa_status_summary "MAC layer is not enforcing for tor — run: onionarmor apply --module mac-profile-install"
