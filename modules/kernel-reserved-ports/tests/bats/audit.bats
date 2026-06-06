#!/usr/bin/env bats
# kernel-reserved-ports audit.sh — green/yellow/red checks + exit codes,
# including the reservation-drift detector.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green after a clean --auto apply" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$AUDIT" --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"runtime matches drop-in"* ]]
  [[ "$output" == *"tor ports covered"* ]]
  [[ "$output" == *"all green"* ]]
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: RED + exit 1 when the drop-in is missing" {
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"drop-in present"* ]]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"missing"* ]]
}

@test "audit: RED + exit 1 when runtime drifts from the drop-in" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  # Simulate the kernel value being changed out from under the drop-in.
  printf '1-2\n' > "$ONIONARMOR_KRP_PROC_FILE"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"runtime matches drop-in"* ]]
  [[ "$output" == *"[FAIL]"* ]]
}

@test "test_audit_detects_drift: drop-in covers fewer ports than torrc now needs" {
  # Reserve 48001-48249, but the relays have since moved to 49000-49250.
  bash "$APPLY" --reserved-range 48001-48249 >/dev/null
  seed_instance relay1 "MetricsPort 127.0.0.1:49000"
  seed_instance relay2 "MetricsPort 127.0.0.1:49100"
  seed_instance relay3 "MetricsPort 127.0.0.1:49200"
  seed_instance relay4 "MetricsPort 127.0.0.1:49250"
  run bash "$AUDIT" --auto
  [ "$status" -eq 1 ]
  [[ "$output" == *"tor ports covered"* ]]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"drift"* ]]
  # The uncovered band is named explicitly.
  [[ "$output" == *"49000-49250"* ]]
  # And the current (stale) reservation is shown.
  [[ "$output" == *"48001-48249"* ]]
}

@test "audit without --auto: tor-port coverage is a yellow (not checked)" {
  bash "$APPLY" --reserved-range 9050-9090 >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"pass --auto"* ]]
}

@test "audit --auto with no drop-in: red (missing) + yellow coverage, no false drift" {
  # Regression: a missing drop-in is one root cause — check (a) reds it. The
  # coverage check must not pile on a misleading 'drift' red for the same thing.
  seed_metrics_fleet 48010 48050
  run bash "$AUDIT" --auto
  [ "$status" -eq 1 ]
  [[ "$output" == *"no reservation in place yet"* ]]
  # No coverage-check "drift:" finding (the red epilogue's "drifted" is fine).
  ! [[ "$output" == *"drift:"* ]]
  ! [[ "$output" == *"NOT reserved"* ]]
}

@test "audit --auto uses apply-time --listen-ip filter (no false drift)" {
  # Regression: apply with --listen-ip 127.0.0.2 detects only ports on that IP;
  # audit --auto (without repeating the flag) must use the same filter, not
  # default to all loopback addresses and falsely report drift.
  seed_instance relay1 "MetricsPort 127.0.0.1:48001" "MetricsPort 127.0.0.2:48002"
  bash "$APPLY" --auto --listen-ip 127.0.0.2 >/dev/null
  # The drop-in has only 48002 (127.0.0.2), not 48001 (127.0.0.1).
  run bash "$AUDIT" --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
  # Must NOT report 48001 as uncovered drift.
  ! [[ "$output" == *"drift"* ]]
  ! [[ "$output" == *"48001"* ]]
}

@test "audit --auto honors explicit --listen-ip over persisted filters" {
  # When audit is given an explicit filter, it must use that, not the persisted one.
  seed_instance relay1 "MetricsPort 127.0.0.1:48001" "MetricsPort 127.0.0.2:48002"
  bash "$APPLY" --auto --listen-ip 127.0.0.2 >/dev/null
  # Explicitly ask audit to check 127.0.0.1 (different from apply's 127.0.0.2).
  run bash "$AUDIT" --auto --listen-ip 127.0.0.1
  [ "$status" -eq 1 ]
  # 48001 is on 127.0.0.1, which is NOT in the drop-in (only 48002 is), so drift.
  [[ "$output" == *"drift"* ]]
  [[ "$output" == *"48001"* ]]
}

@test "audit --auto uses apply-time --min-port filter (no false drift)" {
  # Regression: apply with --min-port 2000 ignores ports below 2000; audit
  # --auto (without repeating the flag) must use the same filter.
  seed_instance relay1 "SocksPort 127.0.0.1:1500" "MetricsPort 127.0.0.1:48001"
  bash "$APPLY" --auto --min-port 2000 >/dev/null
  # The drop-in has only 48001 (>= 2000), not 1500 (< 2000).
  run bash "$AUDIT" --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
  # Must NOT report 1500 as uncovered drift.
  ! [[ "$output" == *"drift"* ]]
  ! [[ "$output" == *"1500"* ]]
}

@test "audit --auto with an explicit non-zero --auto-buffer does not abort (set -e)" {
  # Regression: krp_load_apply_filters must return success even when the current
  # --auto-buffer/--min-port is non-default. A trailing `cond && assign` that
  # evaluates false would return non-zero and, as a bare call under set -e, kill
  # audit before any check ran.
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$AUDIT" --auto --auto-buffer 50
  # The reservation (48010-48050) still covers the detected ports → green, and
  # crucially the audit RAN to completion rather than aborting at exit 1.
  [ "$status" -eq 0 ]
  [[ "$output" == *"tor ports covered"* ]]
}
