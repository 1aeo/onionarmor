#!/usr/bin/env bats
# tor-config-baseline apply.sh — managed-block insertion, the preserve-if-loopback
# logic for Metrics/ControlPort, CookieAuth, OfflineMasterKey gating, operator
# directives left untouched, idempotency, reloads, dry-run, skip-reload, audit log.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: no instances -> clear failure, no changes" {
  rm -rf "$ONIONARMOR_TCB_INSTANCES_DIR"
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no tor instances found"* ]]
}

@test "apply: managed block inserted with the four stats/lifetime directives" {
  seed_instance relay1 "ORPort 9001" "Nickname examplerelay"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  body=$(block_body relay1)
  [[ "$body" == *"SigningKeyLifetime 60 days"* ]]
  [[ "$body" == *"DirReqStatistics 0"* ]]
  [[ "$body" == *"ConnDirectionStatistics 0"* ]]
  [[ "$body" == *"ExtraInfoStatistics 0"* ]]
  # well-formed begin/end markers present
  grep -q '^# >>> onionarmor tor-config-baseline (managed) >>>$' "$(torrc_path relay1)"
  grep -q '^# <<< onionarmor tor-config-baseline (managed) <<<$' "$(torrc_path relay1)"
}

@test "apply: a managed loopback MetricsPort + ControlPort are added by default" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  body=$(block_body relay1)
  [[ "$body" == *"MetricsPort 127.0.0.1:auto"* ]]
  [[ "$body" == *"ControlPort 127.0.0.1:auto"* ]]
}

@test "apply: a pre-existing loopback MetricsPort is preserved (no duplicate added)" {
  seed_instance relay1 "ORPort 9001" "MetricsPort 127.0.0.1:9035"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  # The managed block must NOT add its own MetricsPort.
  ! [[ "$(block_body relay1)" == *"MetricsPort"* ]]
  # The operator's line is still there, outside the block, unchanged.
  [[ "$(outside_block relay1)" == *"MetricsPort 127.0.0.1:9035"* ]]
}

@test "apply: a pre-existing NON-loopback MetricsPort is NOT overridden (warned)" {
  seed_instance relay1 "ORPort 9001" "MetricsPort 203.0.113.10:9035"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"NON-loopback"* ]]
  # We add nothing for MetricsPort and leave the operator's bind exactly as-is.
  ! [[ "$(block_body relay1)" == *"MetricsPort"* ]]
  [[ "$(outside_block relay1)" == *"MetricsPort 203.0.113.10:9035"* ]]
}

@test "apply: CookieAuthentication added when ControlPort in effect and no auth" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  body=$(block_body relay1)
  [[ "$body" == *"ControlPort 127.0.0.1:auto"* ]]
  [[ "$body" == *"CookieAuthentication 1"* ]]
  [[ "$body" == *"CookieAuthFile /var/run/tor/control.authcookie"* ]]
}

@test "apply: no CookieAuthentication when operator already set a HashedControlPassword" {
  seed_instance relay1 "ORPort 9001" "ControlPort 127.0.0.1:9051" "HashedControlPassword 16:ABCDEF"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  # ControlPort preserved (loopback) so the block adds none; no cookie auth added.
  ! [[ "$(block_body relay1)" == *"ControlPort"* ]]
  ! [[ "$(block_body relay1)" == *"CookieAuthentication"* ]]
}

@test "apply: OfflineMasterKey absent without the flag" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  ! [[ "$(block_body relay1)" == *"OfflineMasterKey"* ]]
  [[ "$output" == *"OfflineMasterKey: skipped"* ]]
}

@test "apply: OfflineMasterKey present WITH --confirm-offline-master-key" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY" --confirm-offline-master-key
  [ "$status" -eq 0 ]
  [[ "$(block_body relay1)" == *"OfflineMasterKey 1"* ]]
}

@test "apply: operator directives (ContactInfo/MyFamily/ORPort) left untouched and outside the block" {
  seed_instance relay1 \
    "ORPort 9001" \
    "ContactInfo operator@example.com" \
    "MyFamily AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555" \
    "Nickname examplerelay"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  out=$(outside_block relay1)
  [[ "$out" == *"ORPort 9001"* ]]
  [[ "$out" == *"ContactInfo operator@example.com"* ]]
  [[ "$out" == *"MyFamily AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"* ]]
  [[ "$out" == *"Nickname examplerelay"* ]]
  # And none of them leak into the managed block.
  body=$(block_body relay1)
  ! [[ "$body" == *"ContactInfo"* ]]
  ! [[ "$body" == *"MyFamily"* ]]
  ! [[ "$body" == *"ORPort"* ]]
  ! [[ "$body" == *"Nickname"* ]]
}

@test "apply: idempotent — second run reports 'already current' and writes nothing new" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  before=$(cat "$(torrc_path relay1)")
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  [ "$(cat "$(torrc_path relay1)")" = "$before" ]
}

@test "apply: idempotent second run does NOT reload" {
  seed_instance relay1 "ORPort 9001"
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSTEMCTL_LOG"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  ! grep -q 'reload tor@relay1' "$STUB_SYSTEMCTL_LOG"
}

@test "apply: systemctl reload tor@<name> logged per affected instance" {
  seed_instance relay1 "ORPort 9001"
  seed_instance relay2 "ORPort 9001"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'reload tor@relay1' "$STUB_SYSTEMCTL_LOG"
  grep -q 'reload tor@relay2' "$STUB_SYSTEMCTL_LOG"
}

@test "apply --dry-run: changes nothing and never reloads" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: tor-config-baseline"* ]]
  [[ "$output" == *"rendered managed block"* ]]
  # No managed block written into the torrc, no reload, no backup.
  ! grep -q 'onionarmor tor-config-baseline' "$(torrc_path relay1)"
  [ ! -s "$STUB_SYSTEMCTL_LOG" ]
  [ ! -e "$ONIONARMOR_TCB_STATE_DIR/relay1.torrc.bak" ]
}

@test "apply: ONIONARMOR_SKIP_RELOAD=yes skips the reload" {
  seed_instance relay1 "ORPort 9001"
  ONIONARMOR_SKIP_RELOAD=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"skipping reloads"* ]]
  [ ! -s "$STUB_SYSTEMCTL_LOG" ]
  # The torrc was still edited.
  grep -q 'onionarmor tor-config-baseline' "$(torrc_path relay1)"
}

@test "apply: backs up the original torrc once before editing" {
  seed_instance relay1 "ORPort 9001" "Nickname examplerelay"
  orig=$(cat "$(torrc_path relay1)")
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  bak="$ONIONARMOR_TCB_STATE_DIR/relay1.torrc.bak"
  [ -f "$bak" ]
  [ "$(cat "$bak")" = "$orig" ]
}

@test "apply: single-torrc fallback when no instances dir exists" {
  rm -rf "$ONIONARMOR_TCB_INSTANCES_DIR"
  printf 'ORPort 9001\n' > "$ONIONARMOR_TCB_TORRC"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'onionarmor tor-config-baseline' "$ONIONARMOR_TCB_TORRC"
  grep -q 'reload tor' "$STUB_SYSTEMCTL_LOG"
}

@test "apply: writes audit-log entries" {
  seed_instance relay1 "ORPort 9001"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'tcb.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.apply.instance' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'tcb.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: a reload failure surfaces exit 2 under verify" {
  seed_instance relay1 "ORPort 9001"
  TCB_SYSTEMCTL_RC=1 run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"returned nonzero"* ]]
}
