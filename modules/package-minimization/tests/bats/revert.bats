#!/usr/bin/env bats
# package-minimization revert.sh — prints the reinstall command from recorded
# state, honest "not auto-reversible" messaging, round-trip, audit-log lines.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: no removal on record — clean exit, explains nothing to reinstall" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"No removal on record"* ]]
}

@test "revert: prints the exact apt-get install command from recorded state" {
  install_pkg gcc 5000
  install_pkg gdb 2000
  bash "$APPLY" --confirm >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"install"* ]]
  [[ "$output" == *"gcc"* ]]
  [[ "$output" == *"gdb"* ]]
  [[ "$output" == *"not"*"reversible"* || "$output" == *"NOT auto-reversible"* ]]
}

@test "revert: is read-only — does not itself reinstall (no apt install logged)" {
  install_pkg gcc 5000
  bash "$APPLY" --confirm >/dev/null
  : > "$STUB_APT_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -s "$STUB_APT_LOG" ]
}

@test "round-trip: apply --confirm -> audit green -> revert prints reinstall" {
  install_pkg gcc 5000
  run bash "$AUDIT"; [ "$status" -eq 1 ]      # RED before
  bash "$APPLY" --confirm >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]      # GREEN after purge
  [[ "$output" == *"all green"* ]]
  run bash "$REVERT"; [ "$status" -eq 0 ]
  [[ "$output" == *"gcc"* ]]
}

@test "revert: writes audit-log entries" {
  install_pkg gcc 5000
  bash "$APPLY" --confirm >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'pkg.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pkg.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
