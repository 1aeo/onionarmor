#!/usr/bin/env bats
# chrony-pinning revert.sh — remove files, restore timesyncd, stop chrony.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes sources + conf, unmasks timesyncd, stops chrony" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_CHR_SOURCES_DIR/onionarmor-stratum1.sources" ]
  [ ! -e "$ONIONARMOR_CHR_CONF_DIR/onionarmor-stratum1.conf" ]
  grep -q 'unmask systemd-timesyncd.service' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/systemd-timesyncd.service")" = "enabled" ]
  grep -q 'stop chrony.service' "$STUB_STATE/systemctl.log"
  [[ "$output" == *"reverted."* ]]
}

@test "revert: restores the main chrony.conf when apply edited it" {
  printf 'driftfile /var/lib/chrony/chrony.drift\n' > "$ONIONARMOR_CHR_MAIN_CONF"
  orig="$(cat "$ONIONARMOR_CHR_MAIN_CONF")"
  bash "$APPLY" >/dev/null
  grep -q 'onionarmor chrony-pinning include block' "$ONIONARMOR_CHR_MAIN_CONF"  # edited
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$ONIONARMOR_CHR_MAIN_CONF")" = "$orig" ]
  [ ! -e "$ONIONARMOR_CHR_STATE_DIR/chrony.conf.orig" ]
}

@test "revert: leaves the main conf alone when apply never edited it" {
  before="$(cat "$ONIONARMOR_CHR_MAIN_CONF")"
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ "$(cat "$ONIONARMOR_CHR_MAIN_CONF")" = "$before" ]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'chr.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'chr.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "roundtrip: apply -> audit(green) -> revert -> audit(red)" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]   # chrony stopped + sources gone
}
