#!/usr/bin/env bash
# MODULE: mac-profile-install — install + enforce a MAC layer for tor (AppArmor on Debian/Ubuntu, SELinux on RHEL). Low risk; recommended-off.
#
# apply.sh — detect the distro family and install + enforce the matching
# Mandatory Access Control layer for tor. Idempotent; supports --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

# ---------------------------------------------------------------------------
# Dry run: print the plan (detected distro, packages, profile/enforce actions),
# change nothing.
# ---------------------------------------------------------------------------
if [ "$MAC_DRY_RUN" -eq 1 ]; then
  info "dry-run: mac-profile-install (no host changes)"
  if [ "$MAC_DISTRO" = "debian" ]; then
    cat <<EOF

PLAN
  distro family     -> debian (AppArmor)
  install command   -> $ONIONARMOR_MAC_APT install -y apparmor apparmor-profiles apparmor-utils
  tor profile       -> $ONIONARMOR_MAC_APPARMOR_PROFILE ($(mac_apparmor_profile_present && echo present || echo absent))
  enforce command   -> $ONIONARMOR_MAC_AA_ENFORCE $ONIONARMOR_MAC_APPARMOR_PROFILE $(mac_apparmor_profile_present || echo '(skipped — profile absent)')
EOF
  else
    cat <<EOF

PLAN
  distro family     -> rhel (SELinux)
  install command   -> $ONIONARMOR_MAC_DNF install -y policycoreutils selinux-policy-targeted
  config            -> $ONIONARMOR_MAC_SELINUX_CONFIG (set SELINUX=enforcing; currently '$(mac_selinux_config_mode)')
  enforce command   -> $ONIONARMOR_MAC_SETENFORCE 1 (running mode currently '$(mac_selinux_runtime_mode)')
EOF
  fi
  exit 0
fi

audit_log mac.apply.start "distro=$MAC_DISTRO"

if [ "$MAC_DISTRO" = "debian" ]; then
  # -------------------------------------------------------------------------
  # Debian/Ubuntu -> AppArmor.
  # -------------------------------------------------------------------------
  # 1. Idempotency: if the tor profile is already loaded + enforcing, stop.
  if [ "$(mac_apparmor_tor_state)" = "enforce" ]; then
    info "AppArmor tor profile already enforcing — already applied"
    audit_log mac.apply.done "distro=debian changed=0 state=enforce"
    cat <<EOF

[mac-profile-install] already applied.
  layer       : AppArmor
  tor profile : enforcing ($ONIONARMOR_MAC_APPARMOR_PROFILE)

Check status any time:  onionarmor audit  --module mac-profile-install
EOF
    exit 0
  fi

  # 2. Install the AppArmor packages + tooling.
  info "installing AppArmor packages via $ONIONARMOR_MAC_APT"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_MAC_APT" install -y \
    apparmor apparmor-profiles apparmor-utils \
    || audit_fail_die mac.apply.fail "stage=apt-install" "apt-get install of apparmor packages failed"
  audit_log mac.apply.install "distro=debian pkgs=apparmor,apparmor-profiles,apparmor-utils"

  # 3. Enforce the tor profile if one is present. Absence is honest, not fatal:
  #    the packages are installed and a later profile drop-in can be enforced.
  if mac_apparmor_profile_present; then
    "$ONIONARMOR_MAC_AA_ENFORCE" "$ONIONARMOR_MAC_APPARMOR_PROFILE" \
      || audit_fail_die mac.apply.fail "stage=aa-enforce" "aa-enforce $ONIONARMOR_MAC_APPARMOR_PROFILE failed"
    audit_log mac.apply.enforce "profile=$ONIONARMOR_MAC_APPARMOR_PROFILE mode=enforce"
    info "enforcing AppArmor tor profile: $ONIONARMOR_MAC_APPARMOR_PROFILE"
    profile_line="enforcing ($ONIONARMOR_MAC_APPARMOR_PROFILE)"
  else
    warn "no tor AppArmor profile at $ONIONARMOR_MAC_APPARMOR_PROFILE — packages installed, nothing to enforce yet"
    profile_line="absent ($ONIONARMOR_MAC_APPARMOR_PROFILE) — packages installed"
  fi

  audit_log mac.apply.done "distro=debian changed=1"
  cat <<EOF

[mac-profile-install] applied.
  layer       : AppArmor
  packages    : apparmor apparmor-profiles apparmor-utils
  tor profile : $profile_line

Check status any time:  onionarmor audit  --module mac-profile-install
Undo the posture:       onionarmor revert --module mac-profile-install
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# RHEL family -> SELinux.
# ---------------------------------------------------------------------------
# 1. Idempotency: if SELinux is already enforcing (running + persisted), stop.
if [ "$(mac_selinux_runtime_mode)" = "enforcing" ] \
   && [ "$(mac_selinux_config_mode)" = "enforcing" ]; then
  info "SELinux already enforcing (running + config) — already applied"
  audit_log mac.apply.done "distro=rhel changed=0 state=enforcing"
  cat <<EOF

[mac-profile-install] already applied.
  layer  : SELinux
  running: enforcing
  config : enforcing ($ONIONARMOR_MAC_SELINUX_CONFIG)

Check status any time:  onionarmor audit  --module mac-profile-install
EOF
  exit 0
fi

# 2. Install the SELinux policy + tooling.
info "installing SELinux packages via $ONIONARMOR_MAC_DNF"
"$ONIONARMOR_MAC_DNF" install -y policycoreutils selinux-policy-targeted \
  || audit_fail_die mac.apply.fail "stage=dnf-install" "dnf install of selinux packages failed"
audit_log mac.apply.install "distro=rhel pkgs=policycoreutils,selinux-policy-targeted"

# 3. Persist SELINUX=enforcing in the config (survives reboot) ...
if [ "$(mac_selinux_config_mode)" = "enforcing" ]; then
  info "SELINUX=enforcing already set in $ONIONARMOR_MAC_SELINUX_CONFIG"
else
  mac_selinux_write_mode enforcing
  audit_log mac.apply.config "wrote=$ONIONARMOR_MAC_SELINUX_CONFIG SELINUX=enforcing"
  info "set SELINUX=enforcing in $ONIONARMOR_MAC_SELINUX_CONFIG"
fi

# 4. ... and flip the running system now (no reboot needed). A box booted with
#    SELinux fully disabled cannot setenforce live — surface that honestly.
if "$ONIONARMOR_MAC_SETENFORCE" 1 >/dev/null 2>&1; then
  audit_log mac.apply.enforce "setenforce=1"
  info "set running SELinux mode to enforcing (setenforce 1)"
  running_line="enforcing"
else
  warn "setenforce 1 failed — SELinux may be disabled until reboot (config now enforcing)"
  running_line="unchanged (config enforcing; reboot to activate)"
fi

audit_log mac.apply.done "distro=rhel changed=1"
cat <<EOF

[mac-profile-install] applied.
  layer  : SELinux
  packages: policycoreutils selinux-policy-targeted
  running: $running_line
  config : enforcing ($ONIONARMOR_MAC_SELINUX_CONFIG)

Check status any time:  onionarmor audit  --module mac-profile-install
Undo the posture:       onionarmor revert --module mac-profile-install
EOF
