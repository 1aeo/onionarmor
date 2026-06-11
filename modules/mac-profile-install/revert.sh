#!/usr/bin/env bash
# revert.sh — relax the MAC enforcement conservatively. This module deliberately
# does NOT uninstall the LSM: ripping AppArmor/SELinux off a host wholesale is
# far more destructive than the posture it backs out, and other profiles may
# depend on it. Instead it relaxes *tor's* enforcement:
#   AppArmor: aa-complain the tor profile (loaded, but logs instead of blocks).
#   SELinux:  SELINUX=permissive in the config + setenforce 0 (running).
# Packages are left installed (noted honestly in the summary). Best-effort.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

audit_log mac.revert.start "distro=$MAC_DISTRO"

if [ "$MAC_DISTRO" = "debian" ]; then
  # -------------------------------------------------------------------------
  # AppArmor: set the tor profile to complain mode (relaxes, does not remove).
  # -------------------------------------------------------------------------
  if mac_apparmor_profile_present; then
    if "$ONIONARMOR_MAC_AA_COMPLAIN" "$ONIONARMOR_MAC_APPARMOR_PROFILE" >/dev/null 2>&1; then
      audit_log mac.revert.complain "profile=$ONIONARMOR_MAC_APPARMOR_PROFILE mode=complain"
      info "set AppArmor tor profile to complain mode: $ONIONARMOR_MAC_APPARMOR_PROFILE"
      profile_line="complain ($ONIONARMOR_MAC_APPARMOR_PROFILE)"
    else
      warn "aa-complain failed for $ONIONARMOR_MAC_APPARMOR_PROFILE — profile left as-is"
      audit_log mac.revert.fail "stage=aa-complain"
      profile_line="UNCHANGED (aa-complain failed)"
    fi
  else
    warn "no tor AppArmor profile at $ONIONARMOR_MAC_APPARMOR_PROFILE — nothing to relax"
    profile_line="absent ($ONIONARMOR_MAC_APPARMOR_PROFILE)"
  fi

  audit_log mac.revert.done "distro=debian"
  cat <<EOF

[mac-profile-install] reverted (relaxed, not removed).
  layer       : AppArmor — packages LEFT INSTALLED (removing the LSM is too destructive)
  tor profile : $profile_line
  note        : revert relaxes enforcement; it does not uninstall AppArmor.

Re-enforce: onionarmor apply --module mac-profile-install
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# SELinux: set permissive in the config (survives reboot) + setenforce 0 (live).
# ---------------------------------------------------------------------------
if [ -f "$ONIONARMOR_MAC_SELINUX_CONFIG" ]; then
  if [ "$(mac_selinux_config_mode)" = "permissive" ]; then
    info "SELINUX=permissive already set in $ONIONARMOR_MAC_SELINUX_CONFIG"
  else
    mac_selinux_write_mode permissive
    audit_log mac.revert.config "wrote=$ONIONARMOR_MAC_SELINUX_CONFIG SELINUX=permissive"
    info "set SELINUX=permissive in $ONIONARMOR_MAC_SELINUX_CONFIG"
  fi
  config_line="permissive ($ONIONARMOR_MAC_SELINUX_CONFIG)"
else
  warn "SELinux config not found: $ONIONARMOR_MAC_SELINUX_CONFIG — nothing to relax in config"
  config_line="absent ($ONIONARMOR_MAC_SELINUX_CONFIG)"
fi

if "$ONIONARMOR_MAC_SETENFORCE" 0 >/dev/null 2>&1; then
  audit_log mac.revert.enforce "setenforce=0"
  info "set running SELinux mode to permissive (setenforce 0)"
  running_line="permissive"
else
  warn "setenforce 0 failed — running mode unchanged (config now permissive)"
  running_line="unchanged"
fi

audit_log mac.revert.done "distro=rhel"
cat <<EOF

[mac-profile-install] reverted (relaxed, not removed).
  layer  : SELinux — packages LEFT INSTALLED (removing the LSM is too destructive)
  running: $running_line
  config : $config_line
  note   : revert relaxes enforcement to permissive; it does not disable/uninstall SELinux.

Re-enforce: onionarmor apply --module mac-profile-install
EOF
