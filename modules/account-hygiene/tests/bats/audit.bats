#!/usr/bin/env bats
# account-hygiene audit.sh — read-only green/yellow/red status + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: a clean baseline has no reds and exits 0" {
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"root is the only UID-0 account"* ]]
}

@test "audit: a leftover cloud-init sudo user is yellow" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"cloud-init sudo users"* ]]
  [[ "$output" == *"ubuntu"* ]]
}

@test "audit: a shared UID-0 account is red and exits non-zero" {
  add_uid0 backdoor
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"shared UID-0"* ]]
}

@test "audit: a blanket NOPASSWD: ALL sudoers file is red" {
  add_nopasswd_all 90-admins
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"NOPASSWD"* ]]
}

@test "audit: off-allowlist sudo users are yellow" {
  seed_user eve 1002
  add_to_group eve sudo
  set_allowlist operator
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"off-allowlist sudo"* ]]
  [[ "$output" == *"eve"* ]]
}

@test "audit: green after apply cleans the cloud-init user" {
  seed_user ubuntu 1001
  add_to_group ubuntu sudo
  bash "$APPLY" >/dev/null
  job=$(cat "$ONIONARMOR_ACCT_STATE_DIR/safety-latch.job"); "$STUB/atrm" "$job"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no cloud-init account holds sudo"* ]]
}
