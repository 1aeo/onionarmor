#!/usr/bin/env bats
# conntrack-tuning audit.sh — graceful n/a when unloaded, all-green when tuned,
# red on an undersized ceiling or missing persistence, yellow on a near-full
# table, and yellow "unscoreable" (not a crash, not a hard fail) on a bad
# numeric override.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: n/a + exit 0 when nf_conntrack is not loaded (tailscale inactive)" {
  ct_set_unloaded
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"n/a"* ]]
  [[ "$output" == *"not loaded"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: all green after a clean apply (loaded, both files, values OK)" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nf_conntrack_max"* ]]
  [[ "$output" == *"sysctl drop-in"* ]]
  [[ "$output" == *"modprobe hashsize"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: red with a named finding when nf_conntrack_max is the kernel default" {
  bash "$APPLY" >/dev/null
  # Knock the live ceiling back to the kernel default (the bug condition).
  "$ONIONARMOR_SYSCTL_CMD" -w net.netfilter.nf_conntrack_max=262144
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"nf_conntrack_max"* ]]
  [[ "$output" == *"262144"* ]]
}

@test "audit: red when the persistence files are missing (values OK live)" {
  # Good live values but no drop-ins written -> nothing survives a reboot.
  "$ONIONARMOR_SYSCTL_CMD" -w net.netfilter.nf_conntrack_max=2097152
  "$ONIONARMOR_SYSCTL_CMD" -w net.netfilter.nf_conntrack_tcp_timeout_established=86400
  [ ! -f "$SYSCTL_DROPIN" ]
  [ ! -f "$MODPROBE_DROPIN" ]
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"sysctl drop-in"* ]]
  [[ "$output" == *"modprobe hashsize"* ]]
  [[ "$output" == *"missing"* ]]
}

@test "audit: yellow warn (exit 0) when the table is past the fill threshold" {
  bash "$APPLY" >/dev/null
  # 85% of the 2097152 ceiling -> above the 70% warn line.
  "$ONIONARMOR_SYSCTL_CMD" -w net.netfilter.nf_conntrack_count=1782579
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"utilization"* ]]
  [[ "$output" == *"[warn]"* ]]
  [[ "$output" == *"%"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: a bad numeric env override is unscoreable, not a crash (exit 0)" {
  bash "$APPLY" >/dev/null
  ONIONARMOR_CT_MIN_MAX="notanumber" run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"unscoreable"* ]]
  [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}
