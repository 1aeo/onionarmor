#!/usr/bin/env bats

load test_helper

@test "apply: refuses without --role" {
  run "$ONIONARMOR_BIN" apply
  [ "$status" -ne 0 ]
  [[ "$output" == *"--role"* ]]
}

@test "apply: refuses if /etc/onionarmor/role.conf is missing" {
  run "$ONIONARMOR_BIN" apply --role tor-relay --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"host role is not declared"* ]]
}

@test "apply: refuses if host role.conf disagrees with --role" {
  declare_host_role "workstation"
  run "$ONIONARMOR_BIN" apply --role tor-relay --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"host role mismatch"* ]]
}

@test "apply --dry-run: shows the 10 changes but writes nothing" {
  declare_host_role "tor-relay"
  before_managed=$(ls "$ONIONARMOR_SYSCTL_DIR" 2>/dev/null | wc -l | awk '{print $1}')
  before_audit=$(test -f "$ONIONARMOR_AUDIT_LOG" && wc -l < "$ONIONARMOR_AUDIT_LOG" || echo 0)
  run "$ONIONARMOR_BIN" apply --role tor-relay --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"changes=10"* ]]
  [[ "$output" == *"noops=15"* ]]
  [[ "$output" == *"No changes written"* ]]
  after_managed=$(ls "$ONIONARMOR_SYSCTL_DIR" 2>/dev/null | wc -l | awk '{print $1}')
  after_audit=$(test -f "$ONIONARMOR_AUDIT_LOG" && wc -l < "$ONIONARMOR_AUDIT_LOG" || echo 0)
  [ "$before_managed" = "$after_managed" ]
  [ "$before_audit" = "$after_audit" ]
}

@test "apply: writes managed file + audit log, then diff is clean" {
  declare_host_role "tor-relay"
  run "$ONIONARMOR_BIN" apply --role tor-relay
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf" ]
  [ -f "$ONIONARMOR_AUDIT_LOG" ]
  grep -q "apply.start" "$ONIONARMOR_AUDIT_LOG"
  grep -q "apply.done" "$ONIONARMOR_AUDIT_LOG"
  grep -q "apply.change.*kernel.kptr_restrict.*old=1.*new=2" "$ONIONARMOR_AUDIT_LOG"
  # Post-apply diff should be all-clean.
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [[ "$output" == *"0/25 sysctls drift"* ]]
}

@test "apply: idempotent — second apply produces zero changes" {
  declare_host_role "tor-relay"
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  run "$ONIONARMOR_BIN" apply --role tor-relay
  [ "$status" -eq 0 ]
  [[ "$output" == *"changes=0"* ]]
  [[ "$output" == *"noops=25"* ]]
}

@test "apply: backs up the prior managed file" {
  declare_host_role "tor-relay"
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  # Mutate the managed file in place so the second apply has something to
  # back up that's visibly different from the freshly generated file.
  echo '# touched-by-test' >> "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf"
  run "$ONIONARMOR_BIN" apply --role tor-relay
  [ "$status" -eq 0 ]
  backups=$(ls "$ONIONARMOR_SYSCTL_DIR"/99-onionarmor-tor-relay.conf.bak.* 2>/dev/null | wc -l | awk '{print $1}')
  [ "$backups" -ge 1 ]
  grep -q "apply.backup" "$ONIONARMOR_AUDIT_LOG"
}

@test "apply --first-run: blocked without confirmation" {
  declare_host_role "tor-relay"
  ONIONARMOR_AUTO_CONFIRM=no run "$ONIONARMOR_BIN" apply --role tor-relay --first-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"cancelled"* ]]
  [ ! -f "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf" ]
}

@test "apply --first-run: proceeds with confirmation" {
  declare_host_role "tor-relay"
  ONIONARMOR_AUTO_CONFIRM=yes run "$ONIONARMOR_BIN" apply --role tor-relay --first-run
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf" ]
}
