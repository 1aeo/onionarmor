#!/usr/bin/env bats
# tor-config-baseline revert.sh — restore torrc from backup, cancel latch, round-trip.

load test_helper

seed_relay() {
  seed_instance relay1 <<'EOF'
Nickname placeholderrelay
ContactInfo operator <noreply@example.invalid>
ORPort 9001
ControlPort 9051
EOF
}

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: restores the torrc from backup" {
  seed_relay
  original=$(cat "$(torrc_path relay1)")
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  # torrc has changed
  [ "$(cat "$(torrc_path relay1)")" != "$original" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$(torrc_path relay1)")" = "$original" ]
  [[ "$output" == *"reverted."* ]]
}

@test "revert: cancels a pending safety latch" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  [ -n "$(latch_jobid)" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -z "$(latch_jobid)" ]
}

@test "revert: reloads the restored instance" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  : > "$SYSTEMCTL_LOG"   # clear apply's reload so we observe revert's
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  reloaded relay1
}

@test "revert: no backups present -> says so, exits clean" {
  seed_relay
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to restore"* ]]
}

@test "round-trip: apply -> audit green -> revert -> audit red" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]
  [[ "$output" == *"OfflineMasterKey"* ]]
}

@test "revert: writes audit-log entries" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'tcb.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.revert.restore' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
