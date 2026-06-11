#!/usr/bin/env bats
# mac-profile-install apply.sh — distro detection, AppArmor enforce + grub
# cmdline, idempotency, dry-run, the SELinux branch, and audit-log entries.

load test_helper

grub_cmdline() {
  sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT=//p' "$ONIONARMOR_GRUB_FILE"
}

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: unknown distro fails clearly" {
  printf 'ID=plan9\n' > "$ONIONARMOR_MAC_OS_RELEASE"
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot determine distro family"* ]]
}

@test "apply (Debian): enforces the tor profile and sets the grub cmdline" {
  set_debian
  seed_tor_profile complain
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  # tor profile flipped to enforce by the aa-enforce stub.
  [ "$(cat "$AA_PROFILE_STATE")" = "enforce" ]
  # grub cmdline now carries both AppArmor tokens.
  [[ "$(grub_cmdline)" == *"apparmor=1"* ]]
  [[ "$(grub_cmdline)" == *"security=apparmor"* ]]
  # original tokens preserved.
  [[ "$(grub_cmdline)" == *"quiet splash"* ]]
  [[ "$output" == *"REBOOT REQUIRED"* ]]
  [[ "$output" == *"applied."* ]]
}

@test "apply (Debian): backs up the grub file before editing" {
  set_debian
  seed_tor_profile complain
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  backup="$ONIONARMOR_MAC_STATE_DIR/grub.backup"
  [ -f "$backup" ]
  [[ "$(cat "$backup")" == *"quiet splash"* ]]
  ! [[ "$(cat "$backup")" == *"apparmor=1"* ]]
}

@test "apply (Debian): idempotent — second run makes no grub change" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  first="$(grub_cmdline)"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ "$(grub_cmdline)" = "$first" ]
  [[ "$output" == *"already has"* ]]
  # No duplicate tokens.
  [ "$(grub_cmdline | grep -o 'apparmor=1' | wc -l | tr -d ' ')" = "1" ]
}

@test "apply (Debian): no tor profile is informational, not a failure" {
  set_debian
  seed_tor_profile absent
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no tor AppArmor profile installed"* ]]
}

@test "apply --dry-run (Debian): changes nothing" {
  set_debian
  seed_tor_profile complain
  before="$(cat "$ONIONARMOR_GRUB_FILE")"
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: mac-profile-install"* ]]
  [ "$(cat "$ONIONARMOR_GRUB_FILE")" = "$before" ]
  # tor profile NOT flipped to enforce.
  [ "$(cat "$AA_PROFILE_STATE")" = "complain" ]
  [ ! -e "$ONIONARMOR_MAC_STATE_DIR/applied.state" ]
}

@test "apply (RHEL): sets SELINUX=enforcing in the config" {
  set_rhel
  seed_selinux_mode permissive
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q '^SELINUX=enforcing' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  ! grep -q '^SELINUX=permissive' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  [[ "$output" == *"REBOOT REQUIRED"* ]]
}

@test "apply (RHEL): idempotent — second run leaves enforcing set" {
  set_rhel
  seed_selinux_mode permissive
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already set to enforcing"* ]]
  [ "$(grep -c '^SELINUX=' "$ONIONARMOR_MAC_SELINUX_CONFIG")" = "1" ]
}

@test "apply: ONIONARMOR_SKIP_RELOAD does not invoke aa-enforce/apt" {
  set_debian
  seed_tor_profile complain
  ONIONARMOR_SKIP_RELOAD=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  # tor profile left in complain (aa-enforce never ran).
  [ "$(cat "$AA_PROFILE_STATE")" = "complain" ]
}

@test "apply (Debian): writes audit-log entries" {
  set_debian
  seed_tor_profile complain
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'mac.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.enforce' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.grub' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
