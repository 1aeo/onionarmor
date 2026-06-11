#!/usr/bin/env bats
# tor-config-baseline apply.sh — confirm gate, enforced settings, preserve rules,
# control-port cookie auth, idempotency, reload, safety latch, dry-run.

load test_helper

# A relay torrc with an exit/family/contact identity to preserve and a bare
# (unauthenticated) ControlPort + a non-localhost MetricsPort absent.
seed_relay() {
  seed_instance relay1 <<'EOF'
Nickname placeholderrelay
ContactInfo operator <noreply@example.invalid>
MyFamily AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
FamilyId placeholderfamilyid
ExitRelay 0
SocksPort 0
ORPort 9001
ControlPort 9051
EOF
}

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: without --confirm-offline-master-key, dies and edits nothing" {
  seed_relay
  before=$(cat "$(torrc_path relay1)")
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--confirm-offline-master-key"* ]]
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
  [ -z "$(latch_jobid)" ]
}

@test "apply --confirm: adds OfflineMasterKey/SigningKeyLifetime + stats settings" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'OfflineMasterKey 1' "$t"
  grep -qx 'SigningKeyLifetime 60 days' "$t"
  grep -qx 'DirReqStatistics 0' "$t"
  grep -qx 'ConnDirectionStatistics 0' "$t"
  grep -qx 'ExtraInfoStatistics 0' "$t"
}

@test "apply --confirm: a ControlPort with no auth gets CookieAuthentication" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'CookieAuthentication 1' "$t"
  grep -q '^CookieAuthFile ' "$t"
}

@test "apply --confirm: ContactInfo / MyFamily / FamilyId / ExitRelay / SocksPort untouched" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'ContactInfo operator <noreply@example.invalid>' "$t"
  grep -qx 'MyFamily AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555' "$t"
  grep -qx 'FamilyId placeholderfamilyid' "$t"
  grep -qx 'ExitRelay 0' "$t"
  grep -qx 'SocksPort 0' "$t"
}

@test "apply --confirm: an existing localhost MetricsPort is PRESERVED, not duplicated" {
  seed_instance relay1 <<'EOF'
ORPort 9001
MetricsPort 127.0.0.1:9035
ControlPort 9051
CookieAuthentication 1
EOF
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'MetricsPort 127.0.0.1:9035' "$t"
  # exactly one MetricsPort line, and no 'auto' one added
  [ "$(grep -c '^MetricsPort ' "$t")" -eq 1 ]
  ! grep -q '^MetricsPort 127.0.0.1:auto' "$t"
}

@test "apply --confirm: an authenticated ControlPort does not get a second cookie line" {
  seed_instance relay1 <<'EOF'
ORPort 9001
ControlPort 127.0.0.1:9051
HashedControlPassword 16:DEADBEEF
EOF
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  ! grep -q '^CookieAuthentication ' "$t"
}

@test "apply --confirm: a wrong enforced value is corrected in place" {
  seed_instance relay1 <<'EOF'
ORPort 9001
SigningKeyLifetime 30 days
DirReqStatistics 1
ControlPort 127.0.0.1:9051
CookieAuthentication 1
EOF
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'SigningKeyLifetime 60 days' "$t"
  grep -qx 'DirReqStatistics 0' "$t"
  ! grep -q '^SigningKeyLifetime 30 days' "$t"
  ! grep -q '^DirReqStatistics 1' "$t"
}

@test "apply --confirm: missing localhost MetricsPort/ControlPort are added as auto" {
  seed_instance relay1 <<'EOF'
ORPort 9001
EOF
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  t=$(torrc_path relay1)
  grep -qx 'MetricsPort 127.0.0.1:auto' "$t"
  grep -qx 'ControlPort 127.0.0.1:auto' "$t"
}

@test "apply --confirm: idempotent — second run rewrites nothing" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  after_first=$(cat "$(torrc_path relay1)")
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  [[ "$output" == *"already compliant"* ]]
  [ "$(cat "$(torrc_path relay1)")" = "$after_first" ]
}

@test "apply --confirm: the affected instance is reloaded" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  reloaded relay1
}

@test "apply --confirm: latch armed — jobid persisted, restore.sh staged, cancel cmd printed" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  [ -n "$(latch_jobid)" ]
  [ -f "$ONIONARMOR_LATCH_STATE_DIR/tor-config-baseline/restore.sh" ]
  [[ "$output" == *"--cancel-safety-latch"* ]]
  [[ "$output" == *"atrm "* ]]
}

@test "apply --confirm: the staged restore script copies backups back + reloads" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  r="$ONIONARMOR_LATCH_STATE_DIR/tor-config-baseline/restore.sh"
  grep -q "reload tor@relay1" "$r"
  grep -q "$ONIONARMOR_TCB_STATE_DIR/backups/relay1.torrc" "$r"
}

@test "apply --no-safety-latch: edits applied, no latch armed" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key --no-safety-latch
  [ "$status" -eq 0 ]
  grep -qx 'OfflineMasterKey 1' "$(torrc_path relay1)"
  [ -z "$(latch_jobid)" ]
  [[ "$output" == *"no auto-revert scheduled"* ]]
}

@test "apply --cancel-safety-latch: cancels a pending latch, exits 0" {
  seed_relay
  bash "$APPLY" --confirm-offline-master-key >/dev/null
  [ -n "$(latch_jobid)" ]
  run bash "$APPLY" --cancel-safety-latch
  [ "$status" -eq 0 ]
  [ -z "$(latch_jobid)" ]
}

@test "apply: latch-arm failure aborts BEFORE editing any torrc" {
  seed_relay
  before=$(cat "$(torrc_path relay1)")
  TCB_AT_FAIL=1 run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -ne 0 ]
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
  ! reloaded relay1
}

@test "apply --dry-run: prints a plan, changes nothing, never reloads" {
  seed_relay
  before=$(cat "$(torrc_path relay1)")
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: tor-config-baseline"* ]]
  [[ "$output" == *"OfflineMasterKey"* ]]
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
  [ -z "$(latch_jobid)" ]
  [ ! -s "$SYSTEMCTL_LOG" ]
}

@test "apply --confirm: handles multiple instances + a top-level torrc" {
  seed_instance relay1 <<'EOF'
ORPort 9001
ControlPort 127.0.0.1:9051
CookieAuthentication 1
EOF
  seed_instance relay2 <<'EOF'
ORPort 9101
ControlPort 127.0.0.1:9151
CookieAuthentication 1
EOF
  printf 'ORPort 9201\n' > "$ONIONARMOR_TCB_TORRC"
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  grep -qx 'OfflineMasterKey 1' "$(torrc_path relay1)"
  grep -qx 'OfflineMasterKey 1' "$(torrc_path relay2)"
  grep -qx 'OfflineMasterKey 1' "$ONIONARMOR_TCB_TORRC"
  reloaded relay1
  reloaded relay2
  reloaded default
}

@test "apply: no torrc anywhere -> dies" {
  rm -rf "$ONIONARMOR_TCB_INSTANCES_DIR"
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -ne 0 ]
  [[ "$output" == *"no torrc found"* ]]
}

@test "apply --confirm: writes audit-log entries" {
  seed_relay
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  grep -q 'tcb.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.apply.edit' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.apply.reload' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: unknown option is rejected" {
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}
