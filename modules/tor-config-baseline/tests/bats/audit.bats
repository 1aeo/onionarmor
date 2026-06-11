#!/usr/bin/env bats
# tor-config-baseline audit.sh — RED before apply, GREEN after, latch caution.

load test_helper

seed_relay() {
  seed_instance relay1 <<'EOF'
Nickname placeholderrelay
ContactInfo operator <noreply@example.invalid>
ORPort 9001
ControlPort 9051
EOF
}

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: RED before apply (missing enforced settings)" {
  seed_relay
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"OfflineMasterKey"* ]]
  [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: an unauthenticated ControlPort is flagged RED" {
  seed_relay
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"ControlPort-auth"* ]]
}

@test "audit: GREEN after apply (no latch pending)" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  # cancel the latch so audit is fully green, not yellow.
  bash "$APPLY" --cancel-safety-latch >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
}

@test "audit: a pending latch is a YELLOW caution (still exit 0)" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"safety-latch"* ]]
  [[ "$output" == *"[warn]"* ]]
}

@test "audit: preserved operator lines reported present" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  run bash "$AUDIT"
  [[ "$output" == *"ContactInfo"* ]]
  [[ "$output" == *"preserved"* ]]
}

@test "audit: no torrc anywhere -> RED, exit 1" {
  rm -rf "$ONIONARMOR_TCB_INSTANCES_DIR"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no torrc"* ]]
}

@test "audit: read-only — does not change the torrc" {
  seed_relay
  before=$(cat "$(torrc_path relay1)")
  run bash "$AUDIT"
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
}
