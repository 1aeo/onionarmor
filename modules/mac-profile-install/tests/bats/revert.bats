#!/usr/bin/env bats
# mac-profile-install revert.sh — relax to permissive; the LSM stays installed.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert (Debian): disables the tor profile, leaves AppArmor installed" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  [ "$(cat "$AA_PROFILE_STATE")" = "enforce" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # tor profile flipped to disabled by the aa-disable stub.
  [ "$(cat "$AA_PROFILE_STATE")" = "disabled" ]
  # AppArmor itself remains "installed" — aa-status is still available + reports.
  run "$ONIONARMOR_MAC_AA_STATUS"
  [ "$status" -eq 0 ]
  [[ "$output" == *"apparmor module is loaded"* ]]
}

@test "revert (Debian): restores the grub backup" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  grep -q 'apparmor=1' "$ONIONARMOR_GRUB_FILE"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # grub cmdline restored to the pre-apply value (no AppArmor tokens).
  ! grep -q 'apparmor=1' "$ONIONARMOR_GRUB_FILE"
  grep -q 'quiet splash' "$ONIONARMOR_GRUB_FILE"
  [[ "$output" == *"REBOOT REQUIRED"* ]]
}

@test "revert (Debian): emphasises permissive-not-broken and clears state" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  [ -f "$ONIONARMOR_MAC_STATE_DIR/applied.state" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"permissive, not broken"* ]]
  [[ "$output" == *"left INSTALLED"* ]]
  [ ! -e "$ONIONARMOR_MAC_STATE_DIR/applied.state" ]
}

@test "revert (RHEL): sets SELINUX=permissive, leaves SELinux installed" {
  set_rhel
  seed_selinux_mode permissive
  bash "$APPLY" >/dev/null
  grep -q '^SELINUX=enforcing' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q '^SELINUX=permissive' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  ! grep -q '^SELINUX=enforcing' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  # sestatus is still available => SELinux left installed.
  run "$ONIONARMOR_MAC_SESTATUS"
  [ "$status" -eq 0 ]
}

@test "revert: ONIONARMOR_SKIP_RELOAD does not invoke aa-disable" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  [ "$(cat "$AA_PROFILE_STATE")" = "enforce" ]
  ONIONARMOR_SKIP_RELOAD=yes run bash "$REVERT"
  [ "$status" -eq 0 ]
  # aa-disable never ran, so the profile state is unchanged.
  [ "$(cat "$AA_PROFILE_STATE")" = "enforce" ]
}

@test "revert (Debian): writes audit-log entries" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'mac.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.revert.profile' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # mac-profile-install needs a distro context before any action resolves the
  # LSM; establish the Debian/AppArmor sandbox + an applied posture first.
  set_debian
  seed_tor_profile complain
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
