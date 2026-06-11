#!/usr/bin/env bats
# ssh-hardening audit.sh — read-only green/yellow/red status + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: not-applied is yellow and exits 0" {
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"not applied yet"* ]]
}

@test "audit: a clean apply is all green and exits 0" {
  seed_login operator
  bash "$APPLY" >/dev/null
  # Cancel the pending latch so the latch check is green, not yellow.
  job=$(cat "$ONIONARMOR_SSH_STATE_DIR/safety-latch.job")
  "$STUB/atrm" "$job"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"PermitRootLogin"* ]]
  [[ "$output" == *"sshd -t"* ]]
  [[ "$output" == *"audit: all green"* ]]
}

@test "audit: a drifted directive is red and exits non-zero" {
  seed_login operator
  bash "$APPLY" >/dev/null
  # Weaken the posture out from under us.
  sed -i.orig 's/^PermitRootLogin no$/PermitRootLogin yes/' "$DROPIN"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"drifted"* ]]
}

@test "audit: a pending safety latch is reported yellow" {
  seed_login operator
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"safety latch"* ]]
  [[ "$output" == *"PENDING"* ]]
}
