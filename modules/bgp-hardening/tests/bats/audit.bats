#!/usr/bin/env bats
# bgp-hardening audit.sh — green/yellow/red checks + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "test_audit_detects_wildcard_listener" {
  # bgpd bound to 0.0.0.0 (no -l in daemons) -> red.
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons ""
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"listener bind"* ]]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"0.0.0.0"* ]]
}

@test "test_audit_passes_specific_bind" {
  # bgpd bound to a specific IP -> the listener-bind check is green.
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4
  run bash "$AUDIT"
  [[ "$output" == *"[ ok ] listener bind"* ]]
  [[ "$output" == *"bgpd bound to 1.2.3.4 (specific)"* ]]
}

@test "audit: all green after a clean apply" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ] listener bind"* ]]
  [[ "$output" == *"[ ok ] firewall tcp/179"* ]]
  [[ "$output" == *"[ ok ] RPKI validation"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: red when the firewall has no managed tcp/179 table" {
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"firewall tcp/179"* ]]
  [[ "$output" == *"no managed nft table"* ]]
}

@test "audit: RPKI red when configured but routinator is down" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  # Validator goes away after apply configured FRR for it.
  printf 'inactive\n' > "$STUB_STATE/active/routinator"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"RPKI validation"* ]]
  [[ "$output" == *"routinator is not active"* ]]
}

@test "audit: RPKI yellow when not configured by this module" {
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4
  run bash "$AUDIT"
  [[ "$output" == *"not configured by this module"* ]]
}

@test "audit: FRR version on the advisory list is yellow, not red" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  FAKE_FRR_VERSION="10.5.0" run bash "$AUDIT"
  # 10.5.0 is flagged -> yellow line, but overall still exits 0 (no red).
  [ "$status" -eq 0 ]
  [[ "$output" == *"FRR version"* ]]
  [[ "$output" == *"advisory list"* ]]
}

@test "audit: old FRR (8.4.4) is flagged" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  FAKE_FRR_VERSION="8.4.4" run bash "$AUDIT"
  [[ "$output" == *"FRR version"* ]]
  [[ "$output" == *"8.4.4"* ]]
}
