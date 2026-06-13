#!/usr/bin/env bats
# account-hygiene revert.sh — cancel the latch and run the restore script to put
# prior sudo membership back. Best-effort + idempotent.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: restores sudo and unlocks the cloud-init user" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  bash "$APPLY" >/dev/null
  ! group_members sudo | grep -q ubuntu
  is_locked ubuntu
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  group_members sudo | grep -q ubuntu
  ! is_locked ubuntu
}

@test "revert: cancels the pending safety latch" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  bash "$APPLY" >/dev/null
  [ -s "$ATQ_FILE" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -s "$ATQ_FILE" ]
}

@test "revert: is a clean no-op when nothing was applied" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"reverted"* ]]
}

@test "revert: writes audit-log entries" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'acct.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'acct.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Establish an applied posture so a real revert would have work to do.
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
