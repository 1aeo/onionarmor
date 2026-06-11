#!/usr/bin/env bats
# kernel-hardening revert.sh — drop-in removal, backup restore, idempotence,
# and audit logging.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes the drop-in after an apply" {
  bash "$APPLY" >/dev/null
  [ -f "$DROPIN" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  [[ "$output" == *"reverted."* ]]
}

@test "revert: audit after revert reflects removal (yellow not-applied)" {
  bash "$APPLY" >/dev/null
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"not applied"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "revert: restores a prior backup when one exists" {
  # First apply over a stale hand-written drop-in -> apply creates backup.conf.
  mkdir -p "$ONIONARMOR_SYSCTL_DIR"
  printf '# prior hand-written drop-in\nkernel.dmesg_restrict = 0\n' > "$DROPIN"
  bash "$APPLY" >/dev/null
  [ -f "$ONIONARMOR_KH_STATE_DIR/backup.conf" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # Revert restored the prior content rather than just deleting the file.
  [ -f "$DROPIN" ]
  grep -q 'prior hand-written drop-in' "$DROPIN"
  [[ "$output" == *"restored from backup"* ]]
}

@test "revert: best-effort no-op when nothing was applied" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remove"* ]]
  [ ! -e "$DROPIN" ]
}

@test "revert: idempotent — second revert is still a clean no-op" {
  bash "$APPLY" >/dev/null
  bash "$REVERT" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remove"* ]]
}

@test "revert: ONIONARMOR_SKIP_RELOAD leaves the live kernel untouched" {
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSCTL_LOG"
  ONIONARMOR_SKIP_RELOAD=yes run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
  [[ "$output" == *"ONIONARMOR_SKIP_RELOAD"* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'kh.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'kh.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
