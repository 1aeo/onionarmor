#!/usr/bin/env bats
# systemd-hardening apply.sh — detection, drop-ins, restart, AUTO-REVERT.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: lists units + rendered drop-ins, changes nothing" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: systemd-hardening"* ]]
  [[ "$output" == *"tor@0.service"* ]]
  [[ "$output" == *"onionleak-collector.service"* ]]
  [[ "$output" == *"NoNewPrivileges=yes"* ]]
  [[ "$output" == *"CAP_NET_BIND_SERVICE"* ]]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
}

@test "apply: writes a drop-in for every detected unit, restarts them" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  for u in tor@0.service tor@1.service onionwarden.service onionleak-collector.service onionleak-analyzer.service; do
    f="$ONIONARMOR_SH_DROPIN_ROOT/$u.d/99-onionarmor-hardening.conf"
    [ -f "$f" ]
    grep -q 'Managed by onionarmor' "$f"
    grep -q 'ProtectSystem=strict' "$f"
    grep -q "restart $u" "$SC_STATE/systemctl.log"
  done
  grep -q 'daemon-reload' "$SC_STATE/systemctl.log"
  [[ "$output" == *"applied."* ]]
}

@test "apply: per-unit capability sets are correct" {
  bash "$APPLY" >/dev/null
  tor="$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf"
  col="$ONIONARMOR_SH_DROPIN_ROOT/onionleak-collector.service.d/99-onionarmor-hardening.conf"
  ana="$ONIONARMOR_SH_DROPIN_ROOT/onionleak-analyzer.service.d/99-onionarmor-hardening.conf"
  war="$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d/99-onionarmor-hardening.conf"
  grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE$' "$tor"
  grep -q '^CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN$' "$col"
  grep -q '^CapabilityBoundingSet=$' "$ana"   # analyzer: drop all
  grep -q '^CapabilityBoundingSet=$' "$war"   # onionwarden: drop all (default)
}

@test "apply: per-unit ReadWritePaths are scoped" {
  bash "$APPLY" >/dev/null
  tor="$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf"
  grep -q '^ReadWritePaths=/var/lib/tor ' "$tor"
}

@test "apply: only managed units present -> drop-in only for those" {
  remove_unit onionwarden.service
  remove_unit onionleak-collector.service
  remove_unit onionleak-analyzer.service
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d/99-onionarmor-hardening.conf" ]
}

@test "apply: no managed units -> nothing to do, exit 0" {
  remove_unit tor@.service
  remove_unit onionwarden.service
  remove_unit onionleak-collector.service
  remove_unit onionleak-analyzer.service
  rm -f "$ONIONARMOR_SH_WANTS_DIRS"/tor@*.service
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no managed units present"* ]]
}

@test "apply: idempotent — second run changes/restarts nothing" {
  bash "$APPLY" >/dev/null
  : > "$SC_STATE/systemctl.log"   # clear the log
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  ! grep -q 'restart' "$SC_STATE/systemctl.log"
}

@test "apply --units: targets an explicit set, skipping autodetection" {
  run bash "$APPLY" --units tor@7.service
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_SH_DROPIN_ROOT/tor@7.service.d/99-onionarmor-hardening.conf" ]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d/99-onionarmor-hardening.conf" ]
}

@test "apply --no-restart: writes drop-ins but does not restart (safety net off)" {
  run bash "$APPLY" --no-restart
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
  ! grep -q 'restart' "$SC_STATE/systemctl.log"
  [[ "$output" == *"safety net is DISABLED"* ]]
}

@test "AUTO-REVERT: a unit that won't start hardened is recovered + exit 2" {
  # onionwarden fails to start WHILE its drop-in exists (too-tight scoping),
  # then comes up once apply removes the drop-in.
  export FAKE_FAIL_WITH_DROPIN="onionwarden.service"
  run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"auto-reverting"* ]] || [[ "$output" == *"REVERTED"* ]]
  # onionwarden's drop-in was removed; the others survive.
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d/99-onionarmor-hardening.conf" ]
  [ -f "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf" ]
  # and it was brought back up
  [ "$(cat "$SC_STATE/active/onionwarden.service")" = "active" ]
  grep -q 'sh.apply.autorevert' "$ONIONARMOR_AUDIT_LOG"
}

@test "AUTO-REVERT: still-down unit is surfaced (exit 2)" {
  export FAKE_FAIL_ALWAYS="onionwarden.service"
  run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"still failed"* ]] || [[ "$output" == *"manual intervention"* ]]
  [ ! -e "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d/99-onionarmor-hardening.conf" ]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'sh.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sh.apply.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sh.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
