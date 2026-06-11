#!/usr/bin/env bats
# tor-config-baseline audit.sh — yellow/missing before apply, green after, the
# non-loopback advisory, OfflineMasterKey info, and exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: missing directives before apply are yellow (exit 0, no red)" {
  seed_instance relay1 "ORPort 9001"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"* ]]
  [[ "$output" == *"SigningKeyLifetime"* ]]
  [[ "$output" == *"green/yellow"* ]]
}

@test "audit: green for the stats/lifetime directives after apply" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ]"* ]]
  [[ "$output" == *"relay1 SigningKeyLifetime"* ]]
  [[ "$output" == *"relay1 DirReqStatistics"* ]]
}

@test "audit: a pre-existing loopback MetricsPort is reported green (operator bind preserved)" {
  seed_instance relay1 "ORPort 9001" "MetricsPort 127.0.0.1:9035"
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"operator loopback bind preserved"* ]]
}

@test "audit: a non-loopback MetricsPort is reported yellow (advisory, operator domain)" {
  seed_instance relay1 "ORPort 9001" "MetricsPort 203.0.113.10:9035"
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"NON-loopback bind"* ]]
}

@test "audit: OfflineMasterKey absent is yellow/info" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OfflineMasterKey"* ]]
  [[ "$output" == *"opt-in only"* ]]
}

@test "audit: OfflineMasterKey green after apply --confirm-offline-master-key" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OfflineMasterKey"* ]]
  [[ "$output" == *"enabled in managed block"* ]]
}

@test "audit: no instances -> yellow, exit 0" {
  rm -rf "$ONIONARMOR_TCB_INSTANCES_DIR"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"none found"* ]]
}

@test "audit: is read-only — does not edit the torrc" {
  seed_instance relay1 "ORPort 9001"
  before=$(cat "$(torrc_path relay1)")
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
}
