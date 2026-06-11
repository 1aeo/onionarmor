#!/usr/bin/env bats
# account-hygiene revert.sh — restore membership/locks, cancel latch, round-trip.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: no snapshot present — warns, exits clean" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Nothing to restore"* ]]
}

@test "revert: restores group membership and unlocks accounts" {
  add_account ubuntu 1001
  add_account stranger 1002
  set_group_members sudo "ubuntu,operator,stranger"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  # Post-apply: ubuntu locked + out of sudo, stranger out of sudo.
  is_locked ubuntu
  [[ "$(group_members sudo)" != *"ubuntu"* ]]
  [[ "$(group_members sudo)" != *"stranger"* ]]

  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # Restored: ubuntu re-added + unlocked, stranger re-added.
  [[ "$(group_members sudo)" == *"ubuntu"* ]]
  [[ "$(group_members sudo)" == *"stranger"* ]]
  ! is_locked ubuntu
  [[ "$output" == *"reverted."* ]]
}

@test "revert: cancels a pending safety latch" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  [ "$(at_queue_count)" -eq 1 ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(at_queue_count)" -eq 0 ]
  [ ! -f "$ONIONARMOR_LATCH_STATE_DIR/account-hygiene/jobid" ]
}

@test "round-trip: apply -> audit -> revert -> audit" {
  add_account ubuntu 1001
  add_account stranger 1002
  set_group_members sudo "ubuntu,operator,stranger"
  write_allowlist operator

  bash "$APPLY" --confirm >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  # After apply (+ latch cancelled): clean -> audit green.
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]

  bash "$REVERT" >/dev/null
  # After revert: ubuntu unlocked + back in sudo, stranger back -> audit red again.
  run bash "$AUDIT"; [ "$status" -eq 1 ]
  [[ "$output" == *"ubuntu"* ]]
}

@test "revert: writes audit-log entries" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'ah.revert.start'  "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.revert.unlock' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.revert.done'   "$ONIONARMOR_AUDIT_LOG"
}
