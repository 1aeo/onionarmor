#!/usr/bin/env bats
# mac-profile-install audit.sh — red when not enforcing, green when enforcing,
# yellow on AppArmor complain / SELinux permissive. Read-only.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit (debian): RED when no tor profile is loaded" {
  seed_os_release_debian
  set_aa_tor_state absent
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"tor profile"* ]]
  [[ "$output" == *"no tor profile loaded"* ]]
}

@test "audit (debian): GREEN when tor profile loaded + enforcing" {
  seed_os_release_debian
  set_aa_tor_state enforce
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"loaded + enforcing"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit (debian): YELLOW when tor profile is in complain mode" {
  seed_os_release_debian
  set_aa_tor_state complain
  run bash "$AUDIT"
  [ "$status" -eq 0 ]   # yellow is non-failing
  [[ "$output" == *"COMPLAIN mode"* ]]
}

@test "audit (rhel): GREEN when running + config enforcing" {
  seed_os_release_rhel
  seed_selinux_config enforcing
  set_se_runmode enforcing
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ENFORCING mode"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit (rhel): RED when SELinux is disabled" {
  seed_os_release_rhel
  seed_selinux_config disabled
  set_se_runmode disabled
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"DISABLED"* ]]
}

@test "audit (rhel): YELLOW when running permissive" {
  seed_os_release_rhel
  seed_selinux_config enforcing
  set_se_runmode permissive
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"PERMISSIVE mode"* ]]
}
