#!/usr/bin/env bats
# account-hygiene audit.sh — green/yellow/red status, read-only.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: GREEN on a clean baseline (no cloud defaults, empty priv groups)" {
  write_allowlist operator
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
}

@test "audit: RED when a present cloud default is unlocked / in sudo" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"cloud default: ubuntu"* ]]
  [[ "$output" == *"in_sudo=yes"* ]]
}

@test "audit: RED on a priv-group stranger not in the allowlist" {
  add_account stranger 1002
  set_group_members sudo "operator,stranger"
  write_allowlist operator
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"stranger"* ]]
  [[ "$output" == *"not in"* ]]
}

@test "audit: YELLOW (not red) when the allowlist file is missing" {
  add_account stranger 1002
  set_group_members sudo "operator,stranger"
  # No allowlist file.
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"allowlist"* ]]
  [[ "$output" == *"missing"* ]]
}

@test "audit: RED on a non-root UID-0 account" {
  add_account backdoor 0
  write_allowlist operator
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"UID 0"* ]]
  [[ "$output" == *"backdoor"* ]]
}

@test "audit: RED on a blanket NOPASSWD:ALL sudoers.d file" {
  write_allowlist operator
  write_nopasswd_sudoers 90-devs
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"NOPASSWD:ALL"* ]]
}

@test "audit: YELLOW when a safety latch is pending" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  run bash "$AUDIT"
  # cloud default now locked+desudoed so the only non-green is the pending latch.
  [ "$status" -eq 0 ]
  [[ "$output" == *"safety latch"* ]]
  [[ "$output" == *"pending"* ]]
}

@test "audit: GREEN after apply once the latch is cancelled" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
}
