#!/usr/bin/env bash
# revert.sh — relax the mac-profile-install posture. Best-effort.
#
# This module's failure mode is "permissive, not broken": revert does NOT
# uninstall the LSM. It only steps the host DOWN from enforcement —
#   AppArmor: aa-disable the tor profile (AppArmor itself stays enabled).
#   SELinux:  set SELINUX=permissive in the config (SELinux stays installed).
# If apply modified the grub cmdline, the grub backup is restored (this too
# needs a reboot to take effect). The host keeps running throughout.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

lsm=$(mac_detect_lsm)
state_path=$(mac_state_path)
grub_backup=$(mac_grub_backup_path)
tor_profile=$(mac_tor_profile_path)

# Did apply record a grub modification? (only meaningful on AppArmor)
grub_modified=0
if [ -f "$state_path" ]; then
  if grep -q '^grub_modified=1' "$state_path" 2>/dev/null; then grub_modified=1; fi
fi

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${MAC_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header mac-profile-install revert
  if [ "$lsm" = "apparmor" ]; then
    if mac_aa_tor_profile_exists; then
      if mac_skip_reload; then
        oa_would "(SKIP_RELOAD) plan only: aa-disable the tor profile $tor_profile — not invoked"
      else
        oa_would "aa-disable the tor profile $tor_profile (AppArmor itself left enabled)"
      fi
    else
      oa_would "no tor profile at $tor_profile — nothing to relax"
    fi
    if [ "$grub_modified" -eq 1 ] && [ -f "$grub_backup" ]; then
      oa_would "restore grub cmdline in $ONIONARMOR_GRUB_FILE from $grub_backup (reboot required)"
    fi
  else
    if grep -qE '^[[:space:]]*SELINUX=' "$ONIONARMOR_MAC_SELINUX_CONFIG" 2>/dev/null; then
      oa_would "set SELINUX=permissive in $ONIONARMOR_MAC_SELINUX_CONFIG (SELinux left installed)"
    else
      oa_would "no SELINUX= line in $ONIONARMOR_MAC_SELINUX_CONFIG — nothing to relax"
    fi
  fi
  [ -f "$state_path" ] && oa_would "clear apply state $state_path"
  exit 0
fi

info "revert relaxes mandatory access control to PERMISSIVE — the LSM stays installed (failure mode: permissive, not broken)"
audit_log mac.revert.start "lsm=$lsm grub_modified=$grub_modified"

reboot_required=0

if [ "$lsm" = "apparmor" ]; then
  # --- 1. Put the tor profile into complain/disabled; leave AppArmor on. ---
  if mac_aa_tor_profile_exists; then
    if mac_skip_reload; then
      info "SKIP_RELOAD: would aa-disable $tor_profile (plan only)"
    elif command -v "$ONIONARMOR_MAC_AA_DISABLE" >/dev/null 2>&1; then
      if "$ONIONARMOR_MAC_AA_DISABLE" "$tor_profile" >/dev/null 2>&1; then
        audit_log mac.revert.profile "disabled=$tor_profile"
        info "tor profile disabled (AppArmor itself left enabled): $tor_profile"
      else
        warn "aa-disable $tor_profile returned nonzero — tor profile may still be enforcing"
      fi
    else
      warn "aa-disable not found — cannot relax the tor profile"
    fi
  else
    info "no tor profile present — nothing to relax"
  fi

  # --- 2. Restore the grub backup if apply modified the cmdline. -----------
  if [ "$grub_modified" -eq 1 ] && [ -f "$grub_backup" ]; then
    if [ -w "$ONIONARMOR_GRUB_FILE" ] || [ ! -e "$ONIONARMOR_GRUB_FILE" ]; then
      if cp "$grub_backup" "$ONIONARMOR_GRUB_FILE" 2>/dev/null; then
        audit_log mac.revert.grub "restored=$ONIONARMOR_GRUB_FILE from=$grub_backup"
        info "restored grub cmdline from backup: $grub_backup (reboot to take effect)"
        reboot_required=1
      else
        warn "could not restore grub from $grub_backup"
      fi
    else
      warn "grub file not writable ($ONIONARMOR_GRUB_FILE) — cannot restore backup"
    fi
  fi

else
  # --- SELinux: set SELINUX=permissive; leave SELinux installed. -----------
  if [ -r "$ONIONARMOR_MAC_SELINUX_CONFIG" ] && [ -w "$ONIONARMOR_MAC_SELINUX_CONFIG" ]; then
    tmp="$ONIONARMOR_MAC_SELINUX_CONFIG.onionarmor.$$"
    if grep -qE '^[[:space:]]*SELINUX=' "$ONIONARMOR_MAC_SELINUX_CONFIG"; then
      if awk '/^[[:space:]]*SELINUX=/ { print "SELINUX=permissive"; next } { print }' \
           "$ONIONARMOR_MAC_SELINUX_CONFIG" > "$tmp" 2>/dev/null \
         && mv "$tmp" "$ONIONARMOR_MAC_SELINUX_CONFIG" 2>/dev/null; then
        audit_log mac.revert.selinux "set=SELINUX=permissive file=$ONIONARMOR_MAC_SELINUX_CONFIG"
        info "set SELINUX=permissive in $ONIONARMOR_MAC_SELINUX_CONFIG (SELinux left installed)"
      else
        rm -f "$tmp" 2>/dev/null || true
        warn "could not set SELINUX=permissive in $ONIONARMOR_MAC_SELINUX_CONFIG"
      fi
    else
      warn "no SELINUX= line in $ONIONARMOR_MAC_SELINUX_CONFIG — nothing to relax"
    fi
  else
    warn "selinux config not writable ($ONIONARMOR_MAC_SELINUX_CONFIG) — cannot set permissive"
  fi
fi

# --- Clear apply state. -----------------------------------------------------
if [ -f "$state_path" ]; then
  rm -f "$state_path" 2>/dev/null || warn "could not remove $state_path"
fi
rm -f "$grub_backup" "$grub_backup.selinux" 2>/dev/null || true

audit_log mac.revert.done "lsm=$lsm reboot_required=$reboot_required"

cat <<EOF

[mac-profile-install] reverted (relaxed to permissive).
  LSM       : $lsm (left INSTALLED — only enforcement relaxed)
  posture   : $([ "$lsm" = "apparmor" ] && echo "tor profile disabled" || echo "SELINUX=permissive")
EOF

if [ "$reboot_required" -eq 1 ]; then
  cat >&2 <<EOF

============================================================
REBOOT REQUIRED
============================================================
The grub kernel cmdline was restored from backup in $ONIONARMOR_GRUB_FILE.
It takes effect on next reboot. onionarmor does NOT reboot automatically.
============================================================
EOF
fi

cat <<EOF

The host is PERMISSIVE, not broken. Re-apply to restore enforcement:
  onionarmor apply --module mac-profile-install
EOF
