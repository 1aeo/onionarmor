#!/usr/bin/env bats
# package-minimization apply.sh — dry-run, confirm gate, purge, role skip,
# idempotency, state recording, audit-log lines.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: lists present removable pkgs + reclaim estimate, changes nothing" {
  install_pkg gcc 5000
  install_pkg tcpdump 1200
  install_pkg vim 3000   # not in the removable set — must be ignored
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: package-minimization"* ]]
  [[ "$output" == *"gcc"* ]]
  [[ "$output" == *"tcpdump"* ]]
  [[ "$output" != *"vim"* ]]
  [[ "$output" == *"Reclaimable"* ]]
  # Nothing purged.
  [ ! -s "$STUB_APT_LOG" ]
}

@test "apply --dry-run: purges nothing and writes no state" {
  install_pkg gcc 5000
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  ! grep -q 'purge' "$STUB_APT_LOG"
  [ ! -e "$ONIONARMOR_PKG_STATE_DIR/removed.list" ]
}

@test "apply: bare run without --confirm REFUSES and purges nothing" {
  install_pkg gcc 5000
  install_pkg gdb 2000
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to remove"* ]]
  ! grep -q 'purge' "$STUB_APT_LOG"
  [ ! -e "$ONIONARMOR_PKG_STATE_DIR/removed.list" ]
}

@test "apply: bare run with nothing installed is a clean no-op (no confirm needed)" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to do"* ]]
  ! grep -q 'purge' "$STUB_APT_LOG"
}

@test "apply --confirm: purges exactly the installed removable packages" {
  install_pkg gcc 5000
  install_pkg tcpdump 1200
  install_pkg strace 800
  install_pkg vim 3000     # not removable — must NOT be purged
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  apt_purged gcc
  apt_purged tcpdump
  apt_purged strace
  ! apt_purged vim
  [[ "$output" == *"applied."* ]]
}

@test "apply --confirm: records removed packages to the state dir" {
  install_pkg gcc 5000
  install_pkg gdb 2000
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  state="$ONIONARMOR_PKG_STATE_DIR/removed.list"
  [ -f "$state" ]
  grep -qx gcc "$state"
  grep -qx gdb "$state"
}

@test "apply --confirm: a package not installed is skipped (only installed ones purged)" {
  install_pkg gcc 5000   # gdb/tcpdump deliberately NOT installed
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  apt_purged gcc
  ! apt_purged gdb
  ! apt_purged tcpdump
}

@test "apply --confirm: idempotent — second run finds nothing left to remove" {
  install_pkg gcc 5000
  bash "$APPLY" --confirm >/dev/null
  : > "$STUB_APT_LOG"     # clear the log so we can assert the second run purges nothing
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to do"* ]]
  ! grep -q 'purge' "$STUB_APT_LOG"
}

@test "apply: build-host role SKIPS removal entirely (no purge), even with --confirm" {
  set_role build-host
  install_pkg gcc 5000
  install_pkg tcpdump 1200
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  [[ "$output" == *"build-host"* ]]
  [[ "$output" == *"skipping package removal"* ]]
  ! grep -q 'purge' "$STUB_APT_LOG"
  [ ! -e "$ONIONARMOR_PKG_STATE_DIR/removed.list" ]
}

@test "apply: a non-build-host role does NOT skip" {
  set_role tor-relay
  install_pkg gcc 5000
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  apt_purged gcc
}

@test "apply --confirm: writes audit-log entries" {
  install_pkg gcc 5000
  run bash "$APPLY" --confirm
  [ "$status" -eq 0 ]
  grep -q 'pkg.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pkg.apply.removed' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'pkg.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: --confirm via oa_confirm yes (no flag) purges" {
  ONIONARMOR_AUTO_CONFIRM=yes install_pkg gcc 5000
  install_pkg gcc 5000
  ONIONARMOR_AUTO_CONFIRM=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  apt_purged gcc
}

@test "apply: unknown option is rejected" {
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}
