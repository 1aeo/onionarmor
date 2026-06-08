#!/usr/bin/env bats
# bgp-hardening audit.sh — green/yellow/red checks + exit codes. Listener bind
# is the only hard requirement; firewall + RPKI are optional (green when absent).

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

@test "test_audit_does_not_yellow_on_missing_rpki" {
  # Default (stub-AS) posture: listener bind only, no firewall, no RPKI.
  # Audit must be ALL GREEN — optional controls being absent is not a warning.
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null            # default apply: listener bind only
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ] listener bind"* ]]
  [[ "$output" == *"[ ok ] firewall tcp/179"* ]]
  [[ "$output" == *"[ ok ] RPKI validation"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[warn]"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: all green after a full opt-in apply (bind + firewall + rpki)" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-firewall --enable-rpki >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ] listener bind"* ]]
  [[ "$output" == *"[ ok ] firewall tcp/179"* ]]
  [[ "$output" == *"[ ok ] RPKI validation"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: absent firewall is green (optional defense-in-depth, not red)" {
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4               # specific bind, but no firewall applied
  run bash "$AUDIT"
  [[ "$output" == *"[ ok ] firewall tcp/179"* ]]
  [[ "$output" == *"not configured (optional"* ]]
  ! [[ "$output" == *"[FAIL] firewall"* ]]
}

@test "audit: opted-in firewall whose table vanished is red (not green 'not configured')" {
  # Ownership marker present (apply --enable-firewall ran) but the nft table is
  # gone -> drift, must be red rather than a misleading green "not configured".
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4
  mkdir -p "$ONIONARMOR_BGP_STATE_DIR"
  printf '192.0.2.1\n' > "$ONIONARMOR_BGP_STATE_DIR/firewall.peers"
  : > "$NFT_STORE"   # table empty/gone
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"firewall tcp/179"* ]]
  [[ "$output" == *"the managed nft table"*"is gone"* ]]
}

@test "audit: opted-in firewall missing its default drop is red" {
  # A configured-but-broken firewall (operator opted in) is still a failure.
  seed_frr 1.2.3.4 192.0.2.1
  seed_daemons 1.2.3.4
  printf 'table inet onionarmor_bgp {\n    chain input {\n        tcp dport 179 ip saddr { 1.1.1.1 } accept\n    }\n}\n' > "$NFT_STORE"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"missing the default tcp/179 drop"* ]]
}

@test "audit: RPKI red when configured but routinator is down" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-rpki >/dev/null
  # Validator goes away after apply configured FRR for it.
  printf 'inactive\n' > "$STUB_STATE/active/routinator"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"RPKI validation"* ]]
  [[ "$output" == *"routinator is not active"* ]]
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
