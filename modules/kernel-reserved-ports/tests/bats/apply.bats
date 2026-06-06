#!/usr/bin/env bats
# kernel-reserved-ports apply.sh — auto-detection, range compaction, manual
# ranges, buffering, the loopback filter, dry-run, and verification.

load test_helper

# Extract the managed reservation string from the drop-in file.
dropin_value() {
  sed -n 's/^net\.ipv4\.ip_local_reserved_ports = //p' "$DROPIN"
}

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: requires --auto or --reserved-range" {
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--auto and/or --reserved-range"* ]]
  [ ! -e "$DROPIN" ]
}

@test "test_auto_detect_metrics_port_range: 48010..48050 -> 48010-48050" {
  seed_metrics_fleet 48010 48020 48030 48040 48050
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  [ "$(dropin_value)" = "48010-48050" ]
}

@test "test_auto_detect_multiple_disjoint_bands: two disjoint reservations" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48001" "ControlPort 127.0.0.1:29000"
  seed_instance relay2 "MetricsPort 127.0.0.1:48012" "ControlPort 127.0.0.1:29012"
  seed_instance relay3 "MetricsPort 127.0.0.1:48025" "ControlPort 127.0.0.1:29025"
  seed_instance relay4 "MetricsPort 127.0.0.1:48038" "ControlPort 127.0.0.1:29038"
  seed_instance relay5 "MetricsPort 127.0.0.1:48050" "ControlPort 127.0.0.1:29050"
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "29000-29050,48001-48050" ]
}

@test "test_auto_buffer_extends_range: --auto-buffer 10 widens both sides" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48001"
  seed_instance relay2 "MetricsPort 127.0.0.1:48050"
  run bash "$APPLY" --auto --auto-buffer 10
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "47991-48060" ]
}

@test "test_listen_ip_filter: non-loopback port is excluded by default" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48001" "SocksPort 64.65.62.190:443"
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "48001-48001" ]
  ! [[ "$(dropin_value)" == *"443"* ]]
}

@test "--listen-ip restricts auto-detect to a single loopback address" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48001" "MetricsPort 127.0.0.2:48002"
  run bash "$APPLY" --auto --listen-ip 127.0.0.2
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "48002-48002" ]
}

@test "test_manual_range_overrides: --reserved-range only, torrc ignored" {
  seed_metrics_fleet 48010 48020 48030
  run bash "$APPLY" --reserved-range 9050-9090
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "9050-9090" ]
  # No --auto: the torrc ports must not appear.
  ! [[ "$(dropin_value)" == *"48010"* ]]
}

@test "test_combined_auto_and_manual: both flags merge into one drop-in" {
  seed_instance relay1 "MetricsPort 127.0.0.1:48001"
  seed_instance relay2 "MetricsPort 127.0.0.1:48050"
  run bash "$APPLY" --auto --reserved-range 9090-9099
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "9090-9099,48001-48050" ]
}

@test "test_dry_run_no_state_change: prints plan, writes nothing" {
  seed_metrics_fleet 48010 48050
  run bash "$APPLY" --auto --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: kernel-reserved-ports"* ]]
  [[ "$output" == *"48010-48050"* ]]
  [[ "$output" == *"before (live)"* ]]
  # No drop-in, and sysctl was never asked to --system.
  [ ! -e "$DROPIN" ]
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "apply --auto: loads the key and verifies live == drop-in" {
  seed_metrics_fleet 48010 48050
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  grep -q -- '--system' "$STUB_SYSCTL_LOG"
  [ "$(cat "$ONIONARMOR_KRP_PROC_FILE")" = "48010-48050" ]
  [[ "$output" == *"matches drop-in"* ]]
  [[ "$output" == *"applied."* ]]
}

@test "apply: comma-separated --reserved-range list is honoured" {
  run bash "$APPLY" --reserved-range 48001-48249,29000-29299
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "29000-29299,48001-48249" ]
}

@test "apply: repeated --reserved-range flags accumulate" {
  run bash "$APPLY" --reserved-range 9050-9090 --reserved-range 9090-9099
  [ "$status" -eq 0 ]
  # 9050-9090 and 9090-9099 overlap/touch -> merge into one.
  [ "$(dropin_value)" = "9050-9099" ]
}

@test "apply: idempotent — second run rewrites nothing" {
  seed_metrics_fleet 48010 48050
  bash "$APPLY" --auto >/dev/null
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
}

@test "apply --auto with no loopback tor ports: fails clearly" {
  seed_instance relay1 "ORPort 64.65.62.190:9001"
  run bash "$APPLY" --auto
  [ "$status" -ne 0 ]
  [[ "$output" == *"no loopback tor ports"* ]]
  [ ! -e "$DROPIN" ]
}

@test "apply: malformed --reserved-range is rejected" {
  run bash "$APPLY" --reserved-range 48001..48050
  [ "$status" -ne 0 ]
  [[ "$output" == *"malformed"* || "$output" == *"non-numeric"* ]]
}

@test "apply: --reserved-range with start > end is rejected" {
  run bash "$APPLY" --reserved-range 48050-48001
  [ "$status" -ne 0 ]
  [[ "$output" == *"start > end"* ]]
}

@test "apply: reads /etc/tor/torrc.all and /run/tor-instances/*.defaults" {
  printf 'MetricsPort 127.0.0.1:48100\n' > "$ONIONARMOR_KRP_TORRC_ALL"
  printf 'ControlPort 127.0.0.1:29100\n' > "$ONIONARMOR_KRP_TOR_RUN_DIR/snoopdogg.defaults"
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "29100-29100,48100-48100" ]
}

@test "apply: ignores well-known ports below --min-port" {
  seed_instance relay1 "SocksPort 127.0.0.1:53" "MetricsPort 127.0.0.1:48001"
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ "$(dropin_value)" = "48001-48001" ]
}

@test "apply: a value-taking flag with no value dies cleanly (no shift error)" {
  run bash "$APPLY" --reserved-range 9050-9090 --auto-buffer
  [ "$status" -ne 0 ]
  [[ "$output" == *"--auto-buffer requires a value"* ]]
  ! [[ "$output" == *"shift"* ]]
}

@test "apply: a noisy 'sysctl --system' exit does NOT fail apply when verify matches" {
  # Regression: verify is authoritative. If --system exits nonzero (e.g. an
  # unrelated drop-in failed) but the live value + /proc match, apply succeeds.
  seed_metrics_fleet 48010 48050
  KRP_SYSCTL_SYSTEM_RC=1 run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  [ "$(cat "$ONIONARMOR_KRP_PROC_FILE")" = "48010-48050" ]
  [[ "$output" == *"matches drop-in"* ]]
}

@test "apply --no-verify: a failed 'sysctl --system' still fails the apply (exit 2)" {
  # With verification off, the reload exit code is the only success signal.
  seed_metrics_fleet 48010 48050
  KRP_SYSCTL_SYSTEM_RC=1 run bash "$APPLY" --auto --no-verify
  [ "$status" -eq 2 ]
}

@test "apply: writes audit-log entries" {
  seed_metrics_fleet 48010 48050
  run bash "$APPLY" --auto
  [ "$status" -eq 0 ]
  grep -q 'krp.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'krp.apply.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'krp.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
