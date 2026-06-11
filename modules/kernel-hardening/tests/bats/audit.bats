#!/usr/bin/env bats
# kernel-hardening audit.sh — yellow "not applied", all-green after apply,
# red drift, and exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: yellow 'not applied' + exit 0 when no drop-in is present" {
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"not applied"* ]]
  [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: red/drift before apply once a drop-in exists but keys are unloaded" {
  # Write the managed drop-in WITHOUT loading it (skip the reload). The stub
  # returns the pre-hardening default (0) for unloaded keys -> drift.
  ONIONARMOR_SKIP_RELOAD=yes bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"drift from the KSPP target"* ]]
}

@test "audit: all green after a clean apply" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"kernel.dmesg_restrict"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: exits nonzero when a single key drifts" {
  bash "$APPLY" >/dev/null
  # Knock one key out of the hardened value.
  "$ONIONARMOR_SYSCTL_CMD" -w kernel.kptr_restrict=0
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"kernel.kptr_restrict"* ]]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"target '2'"* ]]
}
