#!/usr/bin/env bats
# conntrack-tuning apply.sh — dry-run is inert, both drop-ins are written with
# the expected content, apply is idempotent, verification passes, a non-numeric
# target override dies cleanly, and drop-ins are still persisted when unloaded.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: --dry-run writes nothing and previews both drop-ins" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: conntrack-tuning"* ]]
  [[ "$output" == *"net.netfilter.nf_conntrack_max = 2097152"* ]]
  [[ "$output" == *"options nf_conntrack hashsize=524288"* ]]
  [ ! -f "$SYSCTL_DROPIN" ]
  [ ! -f "$MODPROBE_DROPIN" ]
}

@test "apply: writes both drop-ins with the expected lines" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$SYSCTL_DROPIN" ]
  [ -f "$MODPROBE_DROPIN" ]
  grep -q "^net.netfilter.nf_conntrack_max = 2097152$" "$SYSCTL_DROPIN"
  grep -q "^net.netfilter.nf_conntrack_tcp_timeout_established = 86400$" "$SYSCTL_DROPIN"
  grep -q "^options nf_conntrack hashsize=524288$" "$MODPROBE_DROPIN"
}

@test "apply: loads the sysctl ceiling/timeout and verifies them live" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ "$("$ONIONARMOR_SYSCTL_CMD" -n net.netfilter.nf_conntrack_max)" = "2097152" ]
  [ "$("$ONIONARMOR_SYSCTL_CMD" -n net.netfilter.nf_conntrack_tcp_timeout_established)" = "86400" ]
  [[ "$output" == *"verify: net.netfilter.nf_conntrack_max = 2097152"* ]]
}

@test "apply: is idempotent (second run reports already current)" {
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
}

@test "apply: a non-numeric target override dies cleanly (no garbage drop-in)" {
  ONIONARMOR_CT_MIN_MAX="lots" run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be a non-negative integer"* ]]
  [ ! -f "$SYSCTL_DROPIN" ]
}

@test "apply: re-apply preserves the original pre-onionarmor backup (not clobbered)" {
  # An operator drop-in exists first; apply backs it up, then a SECOND apply must
  # not overwrite that one-time backup with our own managed content. Revert then
  # restores the ORIGINAL, not the tuned values.
  printf 'net.netfilter.nf_conntrack_max = 111\n' > "$SYSCTL_DROPIN"
  bash "$APPLY" >/dev/null
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -f "$SYSCTL_DROPIN" ]
  grep -q "111" "$SYSCTL_DROPIN"
  ! grep -q "2097152" "$SYSCTL_DROPIN"
  [[ "$output" == *"restored"* ]]
}

@test "apply: persists drop-ins pre-emptively even when nf_conntrack is unloaded" {
  ct_set_unloaded
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$SYSCTL_DROPIN" ]
  [ -f "$MODPROBE_DROPIN" ]
  [[ "$output" == *"not loaded"* ]]
}
