#!/usr/bin/env bats
# systemd-hardening revert.sh — remove drop-ins, reload, restart unsandboxed.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes every managed drop-in and restarts the units" {
  bash "$APPLY" >/dev/null
  : > "$SC_STATE/systemctl.log"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d" ]   # empty .d removed
  grep -q 'daemon-reload' "$SC_STATE/systemctl.log"
  grep -q 'restart tor@0.service' "$SC_STATE/systemctl.log"
  [[ "$output" == *"reverted."* ]]
}

@test "revert: nothing to do when no drop-ins exist" {
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to revert"* ]]
}

@test "revert: leaves a foreign (non-managed) drop-in alone" {
  mkdir -p "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d"
  printf '[Service]\nLimitNOFILE=65536\n' \
    > "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # Not ours -> untouched.
  [ -f "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
  [[ "$output" == *"nothing to revert"* ]]
}

@test "revert: discovers drop-ins even if the unit is no longer autodetected" {
  bash "$APPLY" >/dev/null
  # Disable tor@1 (remove its wants entry) — drop-in still on disk.
  rm -f "$ONIONARMOR_SH_WANTS_DIRS/tor@1.service"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/tor@1.service.d/99-onionarmor-hardening.conf" ]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'sh.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sh.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "roundtrip: apply -> audit(green) -> revert -> audit(red: drop-ins gone)" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]   # drop-ins removed -> red
}
