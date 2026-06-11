#!/usr/bin/env bats
# package-minimization apply.sh — removal of installed target packages, the
# removed.list record, role gating, dry-run, the confirm prompt, idempotency,
# and audit-log entries.

load test_helper

removed_list() { cat "$ONIONARMOR_PM_STATE_DIR/removed.list" 2>/dev/null; }

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: removes installed target packages and records removed.list" {
  set_role relay-guard
  seed_pkg gcc 5000
  seed_pkg make 1200
  seed_pkg gdb 8000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"applied."* ]]
  # The packages are gone from the fake DB.
  ! pkg_installed gcc
  ! pkg_installed make
  ! pkg_installed gdb
  # ...recorded for revert (sorted, deduped).
  [ -f "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
  [[ "$(removed_list)" == *"gcc"* ]]
  [[ "$(removed_list)" == *"make"* ]]
  [[ "$(removed_list)" == *"gdb"* ]]
  # apt-get remove was actually invoked.
  grep -q 'remove -y' "$PM_APT_LOG"
}

@test "apply: only installed targets are removed (absent ones ignored)" {
  set_role relay-mid
  seed_pkg gcc 5000
  # make/gdb/tcpdump/strace are NOT installed.
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  ! pkg_installed gcc
  [[ "$(removed_list)" == *"gcc"* ]]
  ! [[ "$(removed_list)" == *"make"* ]]
}

@test "apply: role=build-host skips (no removal)" {
  set_role build-host
  seed_pkg gcc 5000
  seed_pkg gdb 8000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"skipping"* ]]
  [[ "$output" == *"build-host"* ]]
  # Nothing removed.
  pkg_installed gcc
  pkg_installed gdb
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
  ! grep -q 'remove -y' "$PM_APT_LOG"
}

@test "apply: role=ci skips (no removal)" {
  set_role ci
  seed_pkg gcc 5000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"skipping"* ]]
  pkg_installed gcc
}

@test "apply: unset/other role proceeds (toolchain removable on a relay)" {
  # No role file written at all.
  seed_pkg gcc 5000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  ! pkg_installed gcc
}

@test "apply --dry-run: removes nothing, prints the plan + reclaimable total" {
  set_role relay-exit
  seed_pkg gcc 5000
  seed_pkg gdb 8000
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"gcc"* ]]
  [[ "$output" == *"total reclaimable"* ]]
  # Nothing actually removed; no apt invocation; no state recorded.
  pkg_installed gcc
  pkg_installed gdb
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
  [ ! -s "$PM_APT_LOG" ]
}

@test "apply: confirm-no aborts cleanly without removing" {
  set_role relay-guard
  seed_pkg gcc 5000
  # No --yes, and auto-confirm says NO.
  ONIONARMOR_AUTO_CONFIRM=no run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cancelled"* ]]
  pkg_installed gcc
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
  ! grep -q 'remove -y' "$PM_APT_LOG"
}

@test "apply: nothing installed => clean nothing-to-remove exit 0" {
  set_role relay-guard
  # Fake DB is empty.
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remove"* ]]
  [ ! -e "$ONIONARMOR_PM_STATE_DIR/removed.list" ]
}

@test "apply: idempotent — second run finds nothing to remove" {
  set_role relay-guard
  seed_pkg gcc 5000
  seed_pkg make 1200
  bash "$APPLY" --yes >/dev/null
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remove"* ]]
}

@test "apply: ONIONARMOR_SKIP_RELOAD records the set but does not invoke apt" {
  set_role relay-guard
  seed_pkg gcc 5000
  ONIONARMOR_SKIP_RELOAD=yes run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  # apt never ran, so the package is still "installed" in the fake DB...
  pkg_installed gcc
  # ...but the planned removal set was recorded.
  [[ "$(removed_list)" == *"gcc"* ]]
  [ ! -s "$PM_APT_LOG" ]
}

@test "apply: writes audit-log entries" {
  set_role relay-guard
  seed_pkg gcc 5000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  grep -q 'pm.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pm.apply.remove' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pm.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: a skip on build-host writes a pm.apply.skip audit entry" {
  set_role build-host
  seed_pkg gcc 5000
  run bash "$APPLY" --yes
  [ "$status" -eq 0 ]
  grep -q 'pm.apply.skip' "$ONIONARMOR_AUDIT_LOG"
}
