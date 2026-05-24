#!/usr/bin/env bats

load test_helper

@test "round-trip: apply -> diff clean -> mutate -> rollback -> diff restored" {
  declare_host_role "tor-relay"

  # 1. Initial diff: 10/25 drift (synthetic Debian-13 fresh-install baseline).
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [ "$status" -eq 0 ]
  [[ "$output" == *"10/25 sysctls drift"* ]]

  # 2. apply: produces 10 changes.
  run "$ONIONARMOR_BIN" apply --role tor-relay
  [ "$status" -eq 0 ]
  [[ "$output" == *"changes=10"* ]]

  # 3. diff is clean post-apply.
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [ "$status" -eq 0 ]
  [[ "$output" == *"0/25 sysctls drift"* ]]

  # 4. Mutate the managed file so a real backup point exists.
  echo '# pre-second-apply marker' >> "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf"

  # 5. Simulate operator drift by manually changing kernel.kptr_restrict back
  #    in the live state, then re-apply (idempotency double-check) and verify
  #    diff still 0 (apply re-corrected the live drift).
  sed -i.bak 's/kernel.kptr_restrict = 2/kernel.kptr_restrict = 0/' "$FAKE_SYSCTL_STATE"
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [[ "$output" == *"1/25 sysctls drift"* ]]
  "$ONIONARMOR_BIN" apply --role tor-relay >/dev/null
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [[ "$output" == *"0/25 sysctls drift"* ]]

  # 6. Rollback (to the mutated pre-second-apply file): managed file regains
  #    the marker comment we appended in step 4.
  "$ONIONARMOR_BIN" rollback --role tor-relay >/dev/null
  grep -q '# pre-second-apply marker' "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf"
}
