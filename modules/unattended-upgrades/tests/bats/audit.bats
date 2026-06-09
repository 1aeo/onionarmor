#!/usr/bin/env bats
# unattended-upgrades audit.sh — green/yellow/red reporting + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green after a clean apply" {
  bash "$APPLY" >/dev/null
  # a timestamped log line so 'last run' is green
  mkdir -p "$(dirname "$ONIONARMOR_UU_LOG")"
  printf '2026-06-01 03:00:01,123 INFO Starting unattended upgrades script\n' > "$ONIONARMOR_UU_LOG"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ]"*"service enabled"* ]]
  [[ "$output" == *"50 config present"* ]]
  [[ "$output" == *"last run"*"2026-06-01 03:00:01"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit: red + nonzero when service is masked" {
  bash "$APPLY" >/dev/null
  printf 'masked\n' > "$STUB_STATE/enabled/unattended-upgrades.service"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"masked"* ]]
}

@test "audit: red when a managed config file is missing" {
  bash "$APPLY" >/dev/null
  rm -f "$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"missing"* ]]
}

@test "audit: red when the managed config drifted" {
  bash "$APPLY" >/dev/null
  printf '\n// drift\n' >> "$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"DRIFTED"* ]]
}

@test "audit: yellow (still exit 0) when packages are held" {
  bash "$APPLY" >/dev/null
  printf 'linux-image-amd64\n' > "$FAKE_HOLDS"
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"*"apt holds"* ]]
  [[ "$output" == *"linux-image-amd64"* ]]
}

@test "audit: yellow last-run when no log exists yet" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"*"no log yet"* ]]
}
