#!/usr/bin/env bats
# kernel-hardening audit.sh — red before apply, green after, drift detection.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: RED when the drop-in is missing" {
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"missing"* ]]
}

@test "audit: GREEN after apply (drop-in present + live values match)" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"matches KSPP posture"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit: RED when a live value drifts from target" {
  bash "$APPLY" >/dev/null
  # Operator (or a competing tool) flips a key back at runtime.
  "$ONIONARMOR_SYSCTL_CMD" -w kernel.kptr_restrict=0 >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"kernel.kptr_restrict"* ]]
  [[ "$output" == *"!= target"* ]]
}

@test "audit: RED when the drop-in drifted from the rendered posture" {
  bash "$APPLY" >/dev/null
  printf '# tampered\n' >> "$DROPIN"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"DRIFTED"* ]]
}
