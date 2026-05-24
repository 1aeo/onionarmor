#!/usr/bin/env bats

load test_helper

@test "rollback: refuses if no backup exists" {
  declare_host_role "tor-relay"
  run "$ONIONARMOR_BIN" rollback --role tor-relay
  [ "$status" -ne 0 ]
  [[ "$output" == *"no backups"* ]]
}

@test "rollback: restores most recent backup" {
  declare_host_role "tor-relay"
  # First apply: no prior managed file -> no backup.
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  managed="$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf"
  # Mutate the managed file to create a distinctive baseline state, then apply
  # again so the mutated file is backed up.
  echo '# baseline-marker' >> "$managed"
  baseline_md5=$(md5sum "$managed" | awk '{print $1}')
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  current_md5=$(md5sum "$managed" | awk '{print $1}')
  [ "$baseline_md5" != "$current_md5" ]

  run "$ONIONARMOR_BIN" rollback --role tor-relay
  [ "$status" -eq 0 ]
  restored_md5=$(md5sum "$managed" | awk '{print $1}')
  [ "$restored_md5" = "$baseline_md5" ]
  grep -q "rollback.start" "$ONIONARMOR_AUDIT_LOG"
  grep -q "rollback.done" "$ONIONARMOR_AUDIT_LOG"
}

@test "rollback: refuses with host role mismatch" {
  declare_host_role "workstation"
  run "$ONIONARMOR_BIN" rollback --role tor-relay
  [ "$status" -ne 0 ]
  [[ "$output" == *"host role mismatch"* ]]
}
