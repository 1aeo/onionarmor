#!/usr/bin/env bats
# firewall-default-deny revert.sh — disable + reset, cancel latch, clean state.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: disables + resets ufw and removes the manifest" {
  add_listener 0.0.0.0 443
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$UFW_STATE/active")" = "inactive" ]
  [ ! -s "$UFW_STATE/rules" ]
  [ ! -e "$ONIONARMOR_FW_STATE_DIR/rules.manifest" ]
  [[ "$output" == *"reverted."* ]]
  [[ "$output" == *"WARNING"* ]]
}

@test "revert: cancels a pending safety-latch at job" {
  bash "$APPLY" >/dev/null
  job="$(cat "$AT_QUEUE")"
  [ -n "$job" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # job removed from the at queue
  ! grep -qx "$job" "$AT_QUEUE"
  [ ! -e "$ONIONARMOR_FW_STATE_DIR/safety-latch.job" ]
  [[ "$output" == *"cancelled pending safety-latch"* ]]
}

@test "revert: tolerates a host that was never applied" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"reverted."* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'fw.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'fw.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "roundtrip: apply -> audit(ok) -> revert -> audit(red: ufw inactive)" {
  add_listener 0.0.0.0 443
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]   # ufw now inactive -> red
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Establish an applied posture so a real revert would have work to do.
  bash "$APPLY" >/dev/null 2>&1 || true
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
