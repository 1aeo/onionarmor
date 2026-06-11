#!/usr/bin/env bats
# tor-config-baseline revert.sh — apply then revert restores the original torrc
# byte-for-byte, logs the reload, clears state, and is idempotent.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: apply then revert restores the original torrc byte-for-byte" {
  seed_instance relay1 "ORPort 9001" "ContactInfo operator@example.com" "Nickname examplerelay"
  orig=$(cat "$(torrc_path relay1)")
  bash "$APPLY" >/dev/null
  # Sanity: the block went in.
  grep -q 'onionarmor tor-config-baseline' "$(torrc_path relay1)"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$(torrc_path relay1)")" = "$orig" ]
  ! grep -q 'onionarmor tor-config-baseline' "$(torrc_path relay1)"
}

@test "revert: reload tor@<name> logged for the reverted instance" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSTEMCTL_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'reload tor@relay1' "$STUB_SYSTEMCTL_LOG"
}

@test "revert: clears module state on success" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  [ -f "$ONIONARMOR_TCB_STATE_DIR/relay1.torrc.bak" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -d "$ONIONARMOR_TCB_STATE_DIR" ]
}

@test "revert: idempotent — second revert is a clean no-op" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  bash "$REVERT" >/dev/null
  saved=$(cat "$(torrc_path relay1)")
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$(torrc_path relay1)")" = "$saved" ]
}

@test "revert: strips the managed block when no backup is present" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  # Remove the backup so revert must fall back to block-stripping.
  rm -rf "$ONIONARMOR_TCB_STATE_DIR"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  ! grep -q 'onionarmor tor-config-baseline' "$(torrc_path relay1)"
  grep -q 'ORPort 9001' "$(torrc_path relay1)"
}

@test "revert: ONIONARMOR_SKIP_RELOAD=yes skips the reload" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSTEMCTL_LOG"
  ONIONARMOR_SKIP_RELOAD=yes run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -s "$STUB_SYSTEMCTL_LOG" ]
}

@test "revert: writes audit-log entries" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'tcb.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
