#!/usr/bin/env bats
# unattended-upgrades revert.sh — restore defaults / remove ours, mask service.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: removes our config when there was no prior default" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades" ]
  [ ! -e "$ONIONARMOR_UU_APT_CONFD/20auto-upgrades" ]
  [[ "$output" == *"reverted."* ]]
  [[ "$output" == *"WARNING"* ]]
}

@test "revert: restores the backed-up distro default" {
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  printf '// distro default\nUnattended-Upgrade::Foo "bar";\n' > "$f50"
  bash "$APPLY" >/dev/null
  grep -q 'Managed by onionarmor' "$f50"   # ours is now in place
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -f "$f50" ]
  grep -q 'distro default' "$f50"          # original restored
  ! grep -q 'Managed by onionarmor' "$f50"
  # backup consumed
  [ ! -e "$ONIONARMOR_UU_STATE_DIR/50unattended-upgrades.orig" ]
}

@test "revert: disables + masks the service" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'disable unattended-upgrades.service now=1' "$STUB_STATE/systemctl.log"
  grep -q 'mask unattended-upgrades.service' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/unattended-upgrades.service")" = "masked" ]
}

@test "revert: fails (nonzero) when masking the service fails" {
  bash "$APPLY" >/dev/null
  FAKE_SYSTEMCTL_FAIL="mask" run bash "$REVERT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not mask"* ]]
  [[ "$output" == *"MASK FAILED"* ]]
}

@test "revert: leaves an unmanaged operator file alone" {
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  # operator file present, module never applied (no backup, not managed)
  printf '// operator hand-edit\n' > "$f50"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [ -f "$f50" ]
  grep -q 'operator hand-edit' "$f50"
  [[ "$output" == *"leaving"* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'uu.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'uu.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "roundtrip: apply -> audit(green) -> revert -> audit(red)" {
  bash "$APPLY" >/dev/null
  mkdir -p "$(dirname "$ONIONARMOR_UU_LOG")"
  printf '2026-06-01 03:00:01,000 INFO run\n' > "$ONIONARMOR_UU_LOG"
  run bash "$AUDIT"; [ "$status" -eq 0 ]
  bash "$REVERT" >/dev/null
  run bash "$AUDIT"; [ "$status" -eq 1 ]   # service masked + configs gone
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Establish an applied posture so a real revert would have work to do.
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
