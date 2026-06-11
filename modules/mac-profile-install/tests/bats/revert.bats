#!/usr/bin/env bats
# mac-profile-install revert.sh — relax (not remove) enforcement; round-trip
# apply -> audit -> revert -> audit.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert (debian): sets the tor profile to complain mode" {
  seed_os_release_debian
  seed_apparmor_profile
  set_aa_tor_state enforce
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q "aa-complain .*usr.bin.tor" "$ACTION_LOG"
  [ "$(cat "$AA_TOR_STATE")" = "complain" ]
  [[ "$output" == *"LEFT INSTALLED"* ]]
}

@test "revert (debian): no tor profile present — warns, exits clean" {
  seed_os_release_debian
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to relax"* ]]
}

@test "revert (rhel): rewrites config to permissive + setenforce 0" {
  seed_os_release_rhel
  seed_selinux_config enforcing
  set_se_runmode enforcing
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(config_selinux_mode)" = "permissive" ]
  grep -q 'setenforce 0' "$ACTION_LOG"
  [ "$(cat "$SE_RUNMODE")" = "permissive" ]
  [[ "$output" == *"LEFT INSTALLED"* ]]
}

@test "round-trip (debian): apply -> audit green -> revert -> audit yellow" {
  seed_os_release_debian
  seed_apparmor_profile
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]   # complain mode -> yellow, non-failing
  [[ "$output" == *"COMPLAIN mode"* ]]
}

@test "round-trip (rhel): apply -> audit green -> revert -> audit yellow (relaxed)" {
  seed_os_release_rhel
  seed_selinux_config permissive
  set_se_runmode permissive
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  [[ "$output" == *"ENFORCING mode"* ]]
  bash "$REVERT" >/dev/null
  # revert relaxes to permissive: SELinux still loaded but no longer blocking ->
  # yellow (warnings), not a hard red. Audit reflects the relaxed posture.
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  [[ "$output" == *"PERMISSIVE mode"* ]]
}

@test "revert: writes audit-log entries (rhel)" {
  seed_os_release_rhel
  seed_selinux_config enforcing
  set_se_runmode enforcing
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'mac.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.revert.config' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
