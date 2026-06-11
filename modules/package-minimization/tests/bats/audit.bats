#!/usr/bin/env bats
# package-minimization audit.sh — read-only advisory checks: yellow when target
# packages are present, all-green when absent, build-host/ci reported as retained.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: yellow advisory when target packages are present" {
  set_role relay-guard
  seed_pkg gcc 5000
  seed_pkg gdb 8000
  run bash "$AUDIT"
  [ "$status" -eq 0 ]   # advisory yellows only — never red
  [[ "$output" == *"[warn]"* ]]
  [[ "$output" == *"removable: gcc"* ]]
  [[ "$output" == *"removable: gdb"* ]]
  [[ "$output" == *"reclaimable"* ]]
  [[ "$output" == *"green/yellow"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: all-green when no target packages are installed" {
  set_role relay-mid
  # Fake DB empty.
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"absent"* ]]
  [[ "$output" == *"no target build/debug packages installed"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: role=ci reported as toolchain retained (green)" {
  set_role ci
  seed_pkg gcc 5000   # present, but retained by design on a ci host
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"toolchain retained"* ]]
  [[ "$output" == *"ci"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: role=build-host reported as toolchain retained (green)" {
  set_role build-host
  seed_pkg gcc 5000
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"toolchain retained"* ]]
  [[ "$output" == *"build-host"* ]]
}

@test "audit: reports the detected role on a relay" {
  set_role relay-exit
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"role=relay-exit"* ]]
}

@test "audit: never mutates host state (fake DB unchanged)" {
  set_role relay-guard
  seed_pkg gcc 5000
  before=$(cat "$PM_DB")
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [ "$(cat "$PM_DB")" = "$before" ]
  [ ! -s "$PM_APT_LOG" ]
}
