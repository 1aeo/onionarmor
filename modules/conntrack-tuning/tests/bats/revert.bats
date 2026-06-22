#!/usr/bin/env bats
# conntrack-tuning revert.sh — dry-run is inert, both drop-ins are removed,
# a prior backup is restored when present, and a clean host is a no-op.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: --dry-run previews removal and changes nothing" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: conntrack-tuning revert"* ]]
  [[ "$output" == *"would:"* ]]
  [ -f "$SYSCTL_DROPIN" ]
  [ -f "$MODPROBE_DROPIN" ]
}

@test "revert: removes both managed drop-ins" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -f "$SYSCTL_DROPIN" ]
  [ ! -f "$MODPROBE_DROPIN" ]
  [[ "$output" == *"reverted"* ]]
}

@test "revert: restores a prior drop-in from backup when one exists" {
  # Seed a pre-existing sysctl drop-in, then apply (which backs it up), then
  # revert (which should restore the original, not delete it).
  printf 'net.netfilter.nf_conntrack_max = 999\n' > "$SYSCTL_DROPIN"
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -f "$SYSCTL_DROPIN" ]
  grep -q "999" "$SYSCTL_DROPIN"
  [[ "$output" == *"restored"* ]]
}

@test "revert: no drop-ins present is a clean no-op" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing"* || "$output" == *"absent"* ]]
}
