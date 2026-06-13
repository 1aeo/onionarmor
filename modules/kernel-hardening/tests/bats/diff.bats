#!/usr/bin/env bats
# kernel-hardening diff.sh — read-only preview. Must never write the drop-in or
# call `sysctl -w` / `sysctl --system`, and must surface drift between the live
# (non-hardened) kernel state and the KSPP targets the module would write.

load test_helper

DIFF() { bash "$MOD_ROOT/diff.sh" "$@"; }

@test "diff: syntax check (bash -n)" {
  run bash -n "$MOD_ROOT/diff.sh"
  [ "$status" -eq 0 ]
}

@test "diff: previews drift on a non-hardened host and writes nothing" {
  # Fresh sandbox: the stub sysctl reports 0 for every unloaded key, so every
  # KSPP key whose target is non-zero (11 of the 15) shows as "→ harden".
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"WOULD-BE"* ]]
  [[ "$output" == *"→ harden"* ]]                       # non-zero delta entries
  [[ "$output" == *"11/15 KSPP keys would change"* ]]
  # No host changes: no drop-in written, no write/reload of sysctl.
  [ ! -e "$DROPIN" ]
  ! grep -q -- '-w' "$STUB_SYSCTL_LOG"
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "diff: a key already at its KSPP target reads (no change)" {
  # Harden one key in the live state; it must show no drift while others do.
  "$ONIONARMOR_SYSCTL_CMD" -w kernel.kptr_restrict=2 >/dev/null
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel.kptr_restrict"*"(no change)"* ]]
  [[ "$output" == *"kernel.kexec_load_disabled"*"→ harden"* ]]
  [ ! -e "$DROPIN" ]
}

@test "diff: after apply, nothing would change" {
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSCTL_LOG"
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"0/15 KSPP keys would change"* ]]
  ! [[ "$output" == *"→ harden"* ]]
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}
