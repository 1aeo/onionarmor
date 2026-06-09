#!/usr/bin/env bats
# systemd-hardening audit.sh — per-unit drop-in + effective-directive checks.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green after a clean apply" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"tor@0.service:"* ]]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"NoNewPrivileges"*"effective=yes"* ]]
  [[ "$output" == *"all green"* ]]
}

@test "audit: red + nonzero when a drop-in is missing" {
  bash "$APPLY" >/dev/null
  rm -rf "$ONIONARMOR_SH_DROPIN_ROOT/onionwarden.service.d"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"*"missing"* ]]
}

@test "audit: red when a managed drop-in drifted" {
  bash "$APPLY" >/dev/null
  echo '# drift' >> "$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"DRIFTED"* ]]
}

@test "audit: red when effective directive is wrong" {
  bash "$APPLY" >/dev/null
  # Tamper the effective value: rewrite ProtectSystem in the drop-in (the fake
  # systemctl show reads the drop-in) so it no longer matches the posture too,
  # but force a mismatch only on the show side by editing in place.
  f="$ONIONARMOR_SH_DROPIN_ROOT/tor@0.service.d/99-onionarmor-hardening.conf"
  sed 's/^ProtectSystem=strict/ProtectSystem=full/' "$f" > "$f.x" && mv "$f.x" "$f"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"ProtectSystem"*"expected 'strict'"* ]]
}

@test "audit: yellow (exit 0) when no managed units present" {
  remove_unit tor@.service
  remove_unit onionwarden.service
  remove_unit onionleak-collector.service
  remove_unit onionleak-analyzer.service
  rm -f "$ONIONARMOR_SH_WANTS_DIRS"/tor@*.service
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"none present"* ]]
}

@test "audit: reports CapabilityBoundingSet per unit" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"CapabilityBoundingSet"*"CAP_NET_BIND_SERVICE"* ]]
  [[ "$output" == *"drop all"* ]]   # analyzer / onionwarden
}
