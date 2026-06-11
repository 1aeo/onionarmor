#!/usr/bin/env bats
# ssh-hardening revert.sh — removes the drop-in, cancels a pending latch,
# validates + reloads sshd. Plus the apply->audit->revert->audit round trip.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes the drop-in and reloads sshd" {
  bash "$APPLY" --no-safety-latch >/dev/null
  [ -f "$DROPIN" ]
  : > "$SYSTEMCTL_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  grep -q "reload ssh" "$SYSTEMCTL_LOG"
  [[ "$output" == *"reverted."* ]]
}

@test "revert: cancels a pending safety latch" {
  bash "$APPLY" >/dev/null
  [ -s "$AT_QUEUE" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -f "$LATCH_DIR/jobid" ]
  [ ! -s "$AT_QUEUE" ]
}

@test "revert: no drop-in present is a no-op (warns, still succeeds)" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to back up"* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" --no-safety-latch >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'sshd.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sshd.revert.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sshd.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "round trip: apply -> audit green -> revert -> audit red" {
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=4096 bash "$APPLY" --no-safety-latch >/dev/null
  SSHD_RSA_BITS=4096 run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]

  run bash "$REVERT"
  [ "$status" -eq 0 ]

  run bash "$AUDIT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing"* ]]
}
