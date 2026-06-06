#!/usr/bin/env bats
# kernel-reserved-ports revert.sh — drop-in removal, runtime reset, backup.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "test_revert_removes_drop_in: file deleted and runtime reset to default" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  [ -f "$DROPIN" ]
  [ "$(cat "$ONIONARMOR_KRP_PROC_FILE")" = "48010-48050" ]

  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  # sysctl reservation is cleared at runtime.
  [ -z "$(cat "$ONIONARMOR_KRP_PROC_FILE")" ]
  [ -z "$("$ONIONARMOR_SYSCTL_CMD" -n net.ipv4.ip_local_reserved_ports)" ]
}

@test "test_revert_creates_backup: backup.conf present after revert" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  backup="$ONIONARMOR_KRP_STATE_DIR/backup.conf"
  [ -f "$backup" ]
  grep -q 'net.ipv4.ip_local_reserved_ports = 48010-48050' "$backup"
}

@test "revert: removes the persisted apply-filters.conf state" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto --min-port 2000 >/dev/null
  filters="$ONIONARMOR_KRP_STATE_DIR/apply-filters.conf"
  [ -f "$filters" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$filters" ]
}

@test "revert: clears runtime via sysctl -w then --system" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  : > "$STUB_SYSCTL_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q -- '-w net.ipv4.ip_local_reserved_ports=' "$STUB_SYSCTL_LOG"
  grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "revert: no drop-in present is a clean no-op warning" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to back up"* ]]
  [ ! -e "$ONIONARMOR_KRP_STATE_DIR/backup.conf" ]
}

@test "revert: leaves the runtime untouched when no drop-in of ours is present" {
  # Regression: revert must not clobber an ip_local_reserved_ports value some
  # OTHER tool set when we have no drop-in (nothing of ours to undo).
  printf '40000-40010\n' > "$ONIONARMOR_KRP_PROC_FILE"
  : > "$STUB_SYSCTL_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"left as-is"* ]]
  [ "$(cat "$ONIONARMOR_KRP_PROC_FILE")" = "40000-40010" ]
  ! grep -q -- '-w net.ipv4.ip_local_reserved_ports=' "$STUB_SYSCTL_LOG"
}

@test "revert: summary reports the runtime as cleared on the normal path" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"runtime : net.ipv4.ip_local_reserved_ports — cleared"* ]]
}

@test "revert: ONIONARMOR_SKIP_RELOAD reports runtime untouched, not falsely cleared" {
  # Regression: the summary must not claim 'cleared' when we skipped the reset.
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  printf '48010-48050\n' > "$ONIONARMOR_KRP_PROC_FILE"
  ONIONARMOR_SKIP_RELOAD=yes run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"left untouched"* ]]
  ! [[ "$output" == *"— cleared"* ]]
  # The drop-in is still removed; only the live key is intentionally left.
  [ ! -e "$DROPIN" ]
}

@test "revert: writes audit-log entries" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'krp.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'krp.revert.backup' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'krp.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
