#!/usr/bin/env bats
# kernel-reserved-ports diff.sh — read-only preview. Must compute the would-be
# reservation for the given flags, compare it to the live value, and write
# nothing (no drop-in, no `sysctl -w` / `--system`).

load test_helper

DIFF() { bash "$MOD_ROOT/diff.sh" "$@"; }

@test "diff: syntax check (bash -n)" {
  run bash -n "$MOD_ROOT/diff.sh"
  [ "$status" -eq 0 ]
}

@test "diff: explicit range previews as → reserve and writes nothing" {
  run DIFF --reserved-range 9050-9090
  [ "$status" -eq 0 ]
  [[ "$output" == *"net.ipv4.ip_local_reserved_ports"* ]]
  [[ "$output" == *"WOULD-BE"*"9050-9090"* ]]
  [[ "$output" == *"→ reserve"* ]]
  [ ! -e "$DROPIN" ]
  ! grep -q -- '-w' "$STUB_SYSCTL_LOG"
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "diff: live value already equal reads (no change)" {
  "$ONIONARMOR_SYSCTL_CMD" -w net.ipv4.ip_local_reserved_ports=9050-9090 >/dev/null 2>&1 || true
  printf '9050-9090\n' > "$ONIONARMOR_KRP_PROC_FILE"
  run DIFF --reserved-range 9050-9090
  [ "$status" -eq 0 ]
  [[ "$output" == *"(no change)"* ]]
  [ ! -e "$DROPIN" ]
}

@test "diff: --auto with detected loopback ports previews a covering range" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48010"
  run DIFF --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"48010"* ]]
  [ ! -e "$DROPIN" ]
}

@test "diff: no flags reports nothing to reserve" {
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"no ranges to reserve"* ]]
  [ ! -e "$DROPIN" ]
}

@test "diff: --auto with no detected ports calls out the empty detection" {
  # No torrc instances seeded -> --auto finds nothing. Distinct from no-flags.
  run DIFF --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"--auto detected no loopback tor ports"* ]]
  [ ! -e "$DROPIN" ]
}

@test "diff: apply hint reflects both --auto and --reserved-range together" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48010"
  run DIFF --auto --reserved-range 9050-9090
  [ "$status" -eq 0 ]
  [[ "$output" == *"Apply with: onionarmor apply --module kernel-reserved-ports --auto --reserved-range 9050-9090"* ]]
  [ ! -e "$DROPIN" ]
}
