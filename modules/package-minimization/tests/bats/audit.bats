#!/usr/bin/env bats
# package-minimization audit.sh — green/yellow/red status, build-host skip.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: GREEN when no removable packages are installed" {
  install_pkg vim 3000   # not in the removable set
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"none installed"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit: RED when a critical debug tool (gcc) is present" {
  install_pkg gcc 5000
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"gcc"* ]]
  [[ "$output" == *"INSTALLED"* ]]
}

@test "audit: RED for any of gcc/gdb/tcpdump/strace present" {
  install_pkg strace 800
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"strace"* ]]
}

@test "audit: YELLOW (not red) when only non-critical removables are present" {
  install_pkg make 1500
  install_pkg cmake 9000
  run bash "$AUDIT"
  [ "$status" -eq 0 ]          # yellow-only exits 0
  [[ "$output" == *"make"* ]]
  [[ "$output" == *"removable build/debug tool"* ]]
  [[ "$output" != *"all green"* ]]
}

@test "audit: reports the reclaimable size when packages are present" {
  install_pkg make 2048
  run bash "$AUDIT"
  [[ "$output" == *"reclaimable"* ]]
}

@test "audit: build-host role -> YELLOW 'skipped', never red" {
  set_role build-host
  install_pkg gcc 5000    # would be RED on any other role
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"build-host"* ]]
  [[ "$output" == *"skipped"* ]]
}
