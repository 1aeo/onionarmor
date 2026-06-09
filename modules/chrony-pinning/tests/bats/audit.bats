#!/usr/bin/env bats
# chrony-pinning audit.sh — green/yellow/red reporting + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green after a clean apply" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[ ok ]"*"chrony active"* ]]
  [[ "$output" == *"sources pinned"* ]]
  [[ "$output" == *"reachable stratum-1 sources"* ]]
  [[ "$output" == *"offset within 50ms"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit: red + nonzero when chrony is not active" {
  bash "$APPLY" >/dev/null
  printf 'inactive\n' > "$STUB_STATE/active/chrony.service"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"chrony active"* ]]
}

@test "audit: red when the sources file is missing" {
  bash "$APPLY" >/dev/null
  rm -f "$ONIONARMOR_CHR_SOURCES_DIR/onionarmor-stratum1.sources"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"missing"* ]]
}

@test "audit: red when timesyncd is not masked" {
  bash "$APPLY" >/dev/null
  printf 'enabled\n' > "$STUB_STATE/enabled/systemd-timesyncd.service"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"competing time daemon"* ]]
}

@test "audit: red when 0 reachable stratum-1 sources" {
  bash "$APPLY" >/dev/null
  FAKE_S1_COUNT=0 run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"0 reachable stratum-1"* ]]
}

@test "audit: yellow when only 1 reachable stratum-1 (no diversity)" {
  bash "$APPLY" >/dev/null
  FAKE_S1_COUNT=1 run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"*"no source diversity"* ]]
}

@test "audit: red when offset exceeds the threshold" {
  bash "$APPLY" >/dev/null
  # 0.2s = 200ms > 50ms
  FAKE_OFFSET=0.200000 run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"exceeds 50ms"* ]]
}

@test "audit: green offset reported in ms" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"last offset 0.012ms"* ]]
}
