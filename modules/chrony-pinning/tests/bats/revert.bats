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

@test "revert: keeps state + fails when chrony stop doesn't take effect" {
  bash "$APPLY" >/dev/null
  # Force `systemctl stop chrony.service` to fail so the unit stays active.
  STUB_FAIL_VERB=stop STUB_FAIL_UNIT=chrony.service run bash "$REVERT"
  [ "$status" -ne 0 ]
  # State marker must survive so the next revert retries reconciliation.
  [ -f "$ONIONARMOR_CHR_STATE_DIR/state" ]
  # Must NOT claim a clean revert, and the audit log records the failure.
  [[ "$output" != *"reverted."* ]]
  grep -q 'chr.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'chr.revert.fail' "$ONIONARMOR_AUDIT_LOG"
  ! grep -q 'chr.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "revert: keeps state + fails when timesyncd won't come back up" {
  bash "$APPLY" >/dev/null
  # Force both timesyncd start paths to fail so it never comes active and the
  # clock is never handed off chrony.
  STUB_FAIL_VERB="enable start" STUB_FAIL_UNIT=systemd-timesyncd.service \
    run bash "$REVERT"
  [ "$status" -ne 0 ]
  [ -f "$ONIONARMOR_CHR_STATE_DIR/state" ]
  [[ "$output" != *"reverted."* ]]
  grep -q 'chr.revert.fail' "$ONIONARMOR_AUDIT_LOG"
  # chrony must be left running (stop never attempted).
  ! grep -q 'stop chrony.service' "$STUB_STATE/systemctl.log"
}
