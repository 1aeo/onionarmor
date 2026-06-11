#!/usr/bin/env bats
# account-hygiene apply.sh — cloud-init cleanup, allowlist enforcement, the
# sudo safety latch, confirmation gating, purge, dry-run, idempotency.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: de-sudoes and locks a leftover cloud-init user" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  ! group_members sudo | grep -q ubuntu
  is_locked ubuntu
  [ -f "$ONIONARMOR_ACCT_STATE_DIR/latch-restore.sh" ]
}

@test "apply: schedules the 5-minute sudo safety latch" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"SUDO SAFETY LATCH ACTIVE"* ]]
  [ -s "$ATQ_FILE" ]
  [ -f "$ONIONARMOR_ACCT_STATE_DIR/safety-latch.job" ]
}

@test "apply: --no-safety-latch schedules no auto-restore" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY" --no-safety-latch
  [ "$status" -eq 0 ]
  [[ "$output" == *"no auto-restore scheduled"* ]]
  [ ! -s "$ATQ_FILE" ]
}

@test "apply: enforces the sudo allowlist (removes off-allowlist users)" {
  seed_user eve 1002
  add_to_group eve sudo
  set_allowlist operator
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  ! group_members sudo | grep -q eve
  group_members sudo | grep -q operator
}

@test "apply: a missing allowlist skips allowlist enforcement" {
  seed_user eve 1002
  add_to_group eve sudo
  # No allowlist file -> eve is NOT removed (no cloud-init, no allowlist).
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  group_members sudo | grep -q eve
  [[ "$output" == *"already clean"* ]]
}

@test "apply: --dry-run changes nothing" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: account-hygiene"* ]]
  group_members sudo | grep -q ubuntu
  [ ! -s "$ATQ_FILE" ]
}

@test "apply: confirmation 'no' aborts without changes" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  ONIONARMOR_AUTO_CONFIRM=no run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cancelled"* ]]
  group_members sudo | grep -q ubuntu
}

@test "apply: idempotent — second run reports already clean" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already clean"* ]]
}

@test "apply: --purge userdels the cloud-init account" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY" --purge
  [ "$status" -eq 0 ]
  ! grep -q '^ubuntu:' "$ACCT_PASSWD_FILE"
}

@test "apply: a shared UID-0 account is reported but never auto-deleted" {
  add_uid0 backdoor
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"UID-0"* ]]
  grep -q '^backdoor:' "$ACCT_PASSWD_FILE"
}

@test "apply: writes audit-log entries" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'acct.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'acct.apply.desudo' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'acct.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
