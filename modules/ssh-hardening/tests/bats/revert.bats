#!/usr/bin/env bats
# ssh-hardening revert.sh — remove the drop-in, cancel the latch, restore host
# keys, reload sshd. Best-effort + idempotent.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes the drop-in and cancels the pending latch" {
  seed_login operator
  bash "$APPLY" >/dev/null
  [ -f "$DROPIN" ]
  [ -s "$ATQ_FILE" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  [ ! -s "$ATQ_FILE" ]
  [[ "$output" == *"reverted"* ]]
}

@test "revert: restores backed-up weak host keys" {
  seed_login operator
  seed_weak_hostkeys
  bash "$APPLY" >/dev/null
  [ ! -e "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_dsa_key" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -e "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_dsa_key" ]
}

@test "revert: reloads sshd after restoring config" {
  seed_login operator
  bash "$APPLY" >/dev/null
  : > "$SYSTEMCTL_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q "reload ssh" "$SYSTEMCTL_LOG"
}

@test "revert: is a clean no-op when nothing was applied" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"reverted"* ]]
}

@test "revert: writes audit-log entries" {
  seed_login operator
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'ssh.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ssh.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
