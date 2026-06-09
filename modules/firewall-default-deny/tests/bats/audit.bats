#!/usr/bin/env bats
# firewall-default-deny audit.sh — status, policies, drift, latch reporting.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green-ish after a clean apply (latch pending = yellow)" {
  add_listener 0.0.0.0 443
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]   # latch-pending is yellow, not red
  [[ "$output" == *"[ ok ]"*"ufw active"* ]]
  [[ "$output" == *"deny incoming / allow outgoing"* ]]
  [[ "$output" == *"[ ok ]"*"IPv6 enabled"* ]]
  [[ "$output" == *"[warn]"*"safety latch"*"PENDING"* ]]
}

@test "audit: green safety-latch once the at job is cancelled" {
  bash "$APPLY" >/dev/null
  job="$(cat "$AT_QUEUE")"
  "$STUB/atrm" "$job"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ]"*"safety latch"*"no pending"* ]]
}

@test "audit: red + nonzero when ufw is inactive" {
  bash "$APPLY" >/dev/null
  "$STUB/ufw" disable
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"ufw active"* ]]
}

@test "audit: red when default incoming policy is not deny" {
  bash "$APPLY" >/dev/null
  printf 'allow\n' > "$UFW_STATE/default_in"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"default policy"* ]]
}

@test "audit: red when IPv6 is not enabled (v6 inbound unfiltered)" {
  bash "$APPLY" --no-ipv6 >/dev/null
  # apply --no-ipv6 leaves IPV6=no; audit (default expects ipv6) flags red
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"IPv6 enabled"* ]]
}

@test "audit: --no-ipv6 acknowledges v4-only as yellow (not red)" {
  bash "$APPLY" --no-ipv6 >/dev/null
  run bash "$AUDIT" --no-ipv6
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"*"IPv6 enabled"*"operator choice"* ]]
}

@test "audit: reports rule count + listener set" {
  add_listener 0.0.0.0 443
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"rule count"* ]]
  [[ "$output" == *"listeners (non-loopback)"*"443"* ]]
}

@test "audit: yellow on an unallowed (denied) listener" {
  bash "$APPLY" >/dev/null
  # a new unrecognised listener appears after apply
  add_listener 0.0.0.0 8080
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"*"unallowed listeners"*"8080"* ]]
}

@test "audit: red when ufw is not installed" {
  ONIONARMOR_FW_UFW="$SB/no-ufw" run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"ufw not installed"* ]]
}
