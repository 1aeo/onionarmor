#!/usr/bin/env bats
# kernel-hardening revert.sh — drop-in removal, backup, round-trip with audit.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes the drop-in and backs it up" {
  bash "$APPLY" >/dev/null
  [ -f "$DROPIN" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  [ -f "$ONIONARMOR_KH_STATE_DIR/backup.conf" ]
  [[ "$output" == *"reverted."* ]]
}

@test "revert: no drop-in present — warns, exits clean" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to back up"* ]]
}

@test "round-trip: apply -> audit green -> revert -> audit red" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]
  [[ "$output" == *"missing"* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'kh.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'kh.revert.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'kh.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
