#!/usr/bin/env bats
# mac-profile-install audit.sh — green/yellow/red checks + exit codes for both
# the AppArmor and SELinux branches.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit (Debian): RED + exit 1 when AppArmor is not installed" {
  set_debian
  # Point aa-status at a nonexistent command so it is "not installed".
  ONIONARMOR_MAC_AA_STATUS="$SB/stubs/nope-aa-status" run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"no mandatory access control"* ]]
}

@test "audit (Debian): green after a Debian enforce + grub apply" {
  set_debian
  seed_tor_profile complain
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"enforce mode"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit (Debian): yellow when the tor profile is absent" {
  set_debian
  seed_tor_profile absent
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"* ]]
  [[ "$output" == *"no tor profile installed"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit (Debian): yellow when the tor profile is in complain mode" {
  set_debian
  seed_tor_profile complain
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"complain mode"* ]]
  [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit (RHEL): green when SELinux is enforcing" {
  set_rhel
  seed_selinux_mode enforcing
  printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' > "$ONIONARMOR_MAC_SELINUX_CONFIG"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"enforcing"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit (RHEL): RED + exit 1 when SELinux is disabled (no LSM active)" {
  set_rhel
  seed_selinux_mode disabled
  printf 'SELINUX=disabled\n' > "$ONIONARMOR_MAC_SELINUX_CONFIG"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"no mandatory access control LSM is enforcing"* ]]
}

@test "audit (RHEL): yellow when SELinux is permissive" {
  set_rhel
  seed_selinux_mode permissive
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"permissive"* ]]
  [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}
