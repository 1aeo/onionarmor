#!/usr/bin/env bats
# firewall-default-deny apply.sh — listener inventory, rules, safety latch.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: prints plan + manifest, changes nothing" {
  add_listener 0.0.0.0 443
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: firewall-default-deny"* ]]
  [[ "$output" == *"deny incoming / allow outgoing"* ]]
  [[ "$output" == *"allow 22/tcp"* ]]
  [[ "$output" == *"allow 443/tcp"* ]]
  [ ! -e "$ONIONARMOR_FW_STATE_DIR/rules.manifest" ]
  [ "$(cat "$UFW_STATE/active")" = "inactive" ]
  # no at job scheduled on dry-run
  [ ! -s "$AT_QUEUE" ]
}

@test "apply: empty listener set -> only SSH allow + default-deny + latch" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  [ -f "$m" ]
  grep -q '^allow 22/tcp$' "$m"
  [ "$(grep -c '^allow ' "$m")" -eq 1 ]
  # ufw enabled + defaults
  [ "$(cat "$UFW_STATE/active")" = "active" ]
  [ "$(cat "$UFW_STATE/default_in")" = "deny" ]
  grep -q '22/tcp ALLOW IN' "$UFW_STATE/rules"
  # safety latch scheduled + cancel instruction printed
  [ -s "$AT_QUEUE" ]
  job="$(cat "$AT_QUEUE")"
  [[ "$output" == *"SSH SAFETY LATCH ACTIVE"* ]]
  [[ "$output" == *"atrm $job"* ]]
  [ "$(cat "$ONIONARMOR_FW_STATE_DIR/safety-latch.job")" = "$job" ]
}

@test "apply: detects a non-22 SSH port from sshd_config (fleet uses 33311)" {
  printf 'Port 33311\n' > "$ONIONARMOR_FW_SSHD_CONFIG"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  grep -q '^allow 33311/tcp$' "$m"
  ! grep -q '^allow 22/tcp$' "$m"
}

@test "apply: known-safe public listeners (80/443) get allow rules" {
  add_listener 0.0.0.0 443
  add_listener 0.0.0.0 80
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  grep -q '^allow 443/tcp$' "$m"
  grep -q '^allow 80/tcp$' "$m"
}

@test "apply: loopback metrics ports are SKIPPED (no allow, not denied)" {
  add_listener 127.0.0.1 9051      # tor ControlPort on loopback
  add_listener6 ::1 9052           # loopback v6
  add_listener 0.0.0.0 443
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  grep -q '^allow 443/tcp$' "$m"
  ! grep -q '9051' "$m"
  ! grep -q '9052' "$m"
  # loopback ports are not reported as denied either
  ! [[ "$output" == *"9051"* ]]
}

@test "apply: BGP/179 listener -> restricted rule from /etc/frr/daemons bind" {
  add_listener 0.0.0.0 179
  seed_frr_daemons 192.0.2.1
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  grep -q '^allow to 192.0.2.1 port 179 proto tcp$' "$m"
  # never a blanket allow 179/tcp
  ! grep -q '^allow 179/tcp$' "$m"
}

@test "apply: BGP/179 -> per-peer source rules when neighbors are configured" {
  add_listener 0.0.0.0 179
  seed_frr_neighbors 192.0.2.7 192.0.2.8
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  grep -q '^allow from 192.0.2.7 to any port 179 proto tcp$' "$m"
  grep -q '^allow from 192.0.2.8 to any port 179 proto tcp$' "$m"
}

@test "apply: BGP/179 with no peer info -> denied + warned" {
  add_listener 0.0.0.0 179
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  ! grep -q '179' "$m"
  [[ "$output" == *"DENYING unrecognised listener port(s)"* ]]
  [[ "$output" == *"179"* ]]
}

@test "apply: unrecognised listener is DENIED + warned; --allow exposes it" {
  add_listener 0.0.0.0 8080
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  m="$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  ! grep -q '8080' "$m"
  [[ "$output" == *"DENYING"*"8080"* ]]

  # now opt in
  run bash "$APPLY" --allow 8080
  [ "$status" -eq 0 ]
  grep -q '^allow 8080/tcp$' "$ONIONARMOR_FW_STATE_DIR/rules.manifest"
}

@test "apply: --allow accepts an explicit /tcp suffix but rejects other protos" {
  add_listener 0.0.0.0 8080
  run bash "$APPLY" --allow 8080/tcp
  [ "$status" -eq 0 ]
  grep -q '^allow 8080/tcp$' "$ONIONARMOR_FW_STATE_DIR/rules.manifest"
  # a non-tcp proto must fail loudly rather than be silently applied as tcp
  run bash "$APPLY" --allow 53/udp --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"only supports tcp"* ]]
}

@test "apply: enables IPv6 in /etc/default/ufw before enabling" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -qi '^IPV6=yes' "$ONIONARMOR_FW_UFW_DEFAULTS"
}

@test "apply --no-ipv6: leaves IPV6=no" {
  run bash "$APPLY" --no-ipv6
  [ "$status" -eq 0 ]
  grep -qi '^IPV6=no' "$ONIONARMOR_FW_UFW_DEFAULTS"
}

@test "apply --no-safety-latch: schedules no at job, warns about console" {
  run bash "$APPLY" --no-safety-latch
  [ "$status" -eq 0 ]
  [ ! -s "$AT_QUEUE" ]
  [[ "$output" == *"no auto-disable scheduled"* ]]
}

@test "apply: errors if 'at' is missing and latch requested" {
  ONIONARMOR_FW_AT="$SB/no-at" run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"'at' not found"* ]]
}

@test "apply: errors if ufw is missing (no silent install)" {
  ONIONARMOR_FW_UFW="$SB/no-ufw" run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"ufw not found"* ]]
  [[ "$output" == *"apt install ufw"* ]]
}

@test "apply: idempotent — second run is a no-op (no new latch)" {
  add_listener 0.0.0.0 443
  bash "$APPLY" >/dev/null
  first_job="$(cat "$AT_QUEUE")"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already applied"* ]]
  # queue unchanged: no second job scheduled
  [ "$(cat "$AT_QUEUE")" = "$first_job" ]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'fw.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'fw.apply.latch' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'fw.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
