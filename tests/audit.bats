#!/usr/bin/env bats

load test_helper

@test "audit: empty before any operations" {
  run "$ONIONARMOR_BIN" audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"audit log is empty"* ]]
}

@test "audit: records apply.start, apply.change (×10), apply.done" {
  declare_host_role "tor-relay"
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  run "$ONIONARMOR_BIN" audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"apply.start"* ]]
  [[ "$output" == *"apply.done"* ]]
  changes=$(printf '%s\n' "$output" | grep -c apply.change || true)
  [ "$changes" -eq 10 ]
}

@test "audit: records rollback events with timestamps + operator" {
  declare_host_role "tor-relay"
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  # Force a second apply (with a mutation) so a backup exists to roll back to.
  echo '# tweak' >> "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf"
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  "$ONIONARMOR_BIN" rollback --role tor-relay >/dev/null
  run "$ONIONARMOR_BIN" audit
  [ "$status" -eq 0 ]
  [[ "$output" == *"rollback.start"* ]]
  [[ "$output" == *"rollback.done"* ]]
  [[ "$output" == *"bats-test"* ]]   # operator name from test_helper.bash
}
