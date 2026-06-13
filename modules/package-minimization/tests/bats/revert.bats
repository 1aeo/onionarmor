#!/usr/bin/env bats
# package-minimization revert.sh — reinstall the recorded removed set, clear the
# list on success, and a clean no-op when there is no state.

load test_helper

removed_list() { cat "$ONIONARMOR_PM_STATE_DIR/removed.list" 2>/dev/null; }

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: apply then revert reinstalls the recorded set" {
  set_role relay-guard
  seed_pkg gcc 5000
  seed_pkg make 1200
  seed_pkg gdb 8000
  bash "$APPLY" --yes >/dev/null
  # Removed by apply.
  ! pkg_installed gcc
  ! pkg_installed make
  ! pkg_installed gdb

  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"reverted."* ]]
  # All three reinstalled in the fake DB.
  pkg_installed gcc
  pkg_installed make
  pkg_installed gdb
  # apt-get install was invoked.
  grep -q 'install -y' "$PM_APT_LOG"
  # removed.list cleared on success.
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
}

@test "revert: no state file is a clean no-op" {
  set_role relay-guard
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to do"* ]]
  # No apt invocation.
  [ ! -s "$PM_APT_LOG" ]
}

@test "revert: empty removed.list is a clean no-op and is cleared" {
  set_role relay-guard
  mkdir -p "$ONIONARMOR_PM_STATE_DIR"
  : > "$ONIONARMOR_PM_STATE_DIR/removed.list"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to do"* ]]
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
  [ ! -s "$PM_APT_LOG" ]
}

@test "revert: ONIONARMOR_SKIP_RELOAD does not invoke apt and keeps the list" {
  set_role relay-guard
  seed_pkg gcc 5000
  bash "$APPLY" --yes >/dev/null
  [[ "$(removed_list)" == *"gcc"* ]]
  : > "$PM_APT_LOG"
  ONIONARMOR_SKIP_RELOAD=yes run bash "$REVERT"
  [ "$status" -eq 0 ]
  # No apt run; the package is still absent in the fake DB (apply removed it).
  [ ! -s "$PM_APT_LOG" ]
  ! pkg_installed gcc
  # List kept because nothing was actually reinstalled.
  [ -f "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
}

@test "revert: writes audit-log entries" {
  set_role relay-guard
  seed_pkg gcc 5000
  bash "$APPLY" --yes >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'pm.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pm.revert.install' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pm.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Establish an applied posture so a real revert would have work to do.
  bash "$APPLY" >/dev/null 2>&1 || true
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
