#!/usr/bin/env bats
# account-hygiene apply.sh — plan/dry-run, confirm gating, latch, mutations.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: prints the plan and changes nothing" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator,stranger"
  add_account stranger 1002
  write_allowlist operator
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: account-hygiene"* ]]
  [[ "$output" == *"lock"*"ubuntu"* ]]
  [[ "$output" == *"remove from sudo"*"stranger"* ]]
  # Nothing mutated: ubuntu still unlocked + still in sudo.
  ! is_locked ubuntu
  [[ "$(group_members sudo)" == *"stranger"* ]]
  # No latch scheduled on a dry run.
  [ "$(at_queue_count)" -eq 0 ]
}

@test "apply: bare apply (no --dry-run, no --confirm) refuses to mutate" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  ONIONARMOR_AUTO_CONFIRM=no run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to mutate without --confirm"* ]]
  ! is_locked ubuntu
}

@test "apply: missing allowlist dies without mutating" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  # No allowlist file written.
  run bash "$APPLY" --confirm
  [ "$status" -ne 0 ]
  [[ "$output" == *"allowlist"* ]]
  [[ "$output" == *"not found"* ]]
  ! is_locked ubuntu
  [[ "$(group_members sudo)" == *"ubuntu"* ]]
  [ "$(at_queue_count)" -eq 0 ]
}

@test "apply: a stranger in sudo is removed while an allowlisted user stays" {
  add_account stranger 1002
  set_group_members sudo "operator,stranger"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$(group_members sudo)" != *"stranger"* ]]
  [[ "$(group_members sudo)" == *"operator"* ]]
}

@test "apply: strangers in wheel and admin are removed too" {
  add_account w1 1003
  add_account a1 1004
  set_group_members wheel "w1,operator"
  set_group_members admin "a1"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$(group_members wheel)" != *"w1"* ]]
  [[ "$(group_members admin)" != *"a1"* ]]
}

@test "apply: a present cloud-init default is locked + removed from sudo" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  is_locked ubuntu
  [[ "$(group_members sudo)" != *"ubuntu"* ]]
  [[ "$(group_members sudo)" == *"operator"* ]]
}

@test "apply: only present cloud defaults are acted on" {
  # 'debian' absent, 'pi' present.
  add_account pi 1005
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  is_locked pi
  ! is_locked debian
}

@test "apply: a non-root UID-0 account makes apply warn loudly (no auto-fix)" {
  add_account backdoor 0
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$output" == *"non-root UID-0 account"* ]]
  [[ "$output" == *"backdoor"* ]]
  # Not auto-fixed: still present.
  grep -q '^backdoor:' "$AH_PASSWD_DB"
}

@test "apply: a blanket NOPASSWD:ALL sudoers.d file makes apply warn (no edit)" {
  write_allowlist operator
  write_nopasswd_sudoers 90-devs
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$output" == *"NOPASSWD: ALL"* ]]
  # File untouched.
  grep -q 'NOPASSWD: ALL' "$ONIONARMOR_AH_SUDOERS_D/90-devs"
}

@test "apply: arms the safety latch and prints the cancel command" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [ "$(at_queue_count)" -eq 1 ]
  # restore.sh staged + jobid persisted under the latch state dir.
  [ -f "$ONIONARMOR_LATCH_STATE_DIR/account-hygiene/restore.sh" ]
  [ -f "$ONIONARMOR_LATCH_STATE_DIR/account-hygiene/jobid" ]
  [[ "$output" == *"SAFETY LATCH ACTIVE"* ]]
  [[ "$output" == *"atrm"* ]]
  [[ "$output" == *"--cancel-safety-latch"* ]]
}

@test "apply: the staged restore script re-adds removed users and unlocks locked" {
  add_account ubuntu 1001
  add_account stranger 1002
  set_group_members sudo "ubuntu,operator,stranger"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  rs="$ONIONARMOR_LATCH_STATE_DIR/account-hygiene/restore.sh"
  grep -q -- '-a ubuntu sudo'   "$rs"
  grep -q -- '-a stranger sudo' "$rs"
  grep -q -- '-U ubuntu'        "$rs"
}

@test "apply --no-safety-latch: mutates without scheduling a latch" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  run bash "$APPLY" --confirm --no-safety-latch
  [ "$status" -eq 0 ]
  is_locked ubuntu
  [ "$(at_queue_count)" -eq 0 ]
  [[ "$output" == *"no auto-restore scheduled"* ]]
}

@test "apply: latch arm failure (atd down) aborts BEFORE any mutation" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  AH_AT_RC=1 run bash "$APPLY" --confirm
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not arm the safety latch"* ]]
  # No mutation happened: ubuntu still unlocked + still in sudo.
  ! is_locked ubuntu
  [[ "$(group_members sudo)" == *"ubuntu"* ]]
}

@test "apply --cancel-safety-latch: cancels a pending latch and exits" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  bash "$APPLY" --confirm >/dev/null
  [ "$(at_queue_count)" -eq 1 ]
  run bash "$APPLY" --cancel-safety-latch
  [ "$status" -eq 0 ]
  [ "$(at_queue_count)" -eq 0 ]
  [ ! -f "$ONIONARMOR_LATCH_STATE_DIR/account-hygiene/jobid" ]
}

@test "apply: --confirm via interactive yes also works" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  ONIONARMOR_AUTO_CONFIRM=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  is_locked ubuntu
}

@test "apply: writes audit-log entries" {
  add_account ubuntu 1001
  set_group_members sudo "ubuntu,operator"
  write_allowlist operator
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  grep -q 'ah.apply.start'    "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.apply.snapshot' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.apply.lock'     "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.apply.desudo'   "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ah.apply.done'     "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: unknown option is rejected" {
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "apply: --latch-minutes requires a value" {
  run bash "$APPLY" --latch-minutes
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires a value"* ]]
}
