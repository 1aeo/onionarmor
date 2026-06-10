#!/usr/bin/env bats
# chrony-pinning apply.sh — sources/conf, timesyncd masking, verify, idempotency.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: prints plan + config, changes nothing" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: chrony-pinning"* ]]
  [[ "$output" == *"server time-a-g.nist.gov"* ]]
  [[ "$output" == *"ptbtime1.ptb.de"* ]]
  [[ "$output" == *"makestep 1.0 3"* ]]
  [ ! -e "$ONIONARMOR_CHR_SOURCES_DIR/onionarmor-stratum1.sources" ]
}

@test "apply: writes sources + conf, masks timesyncd, restarts chrony" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  src="$ONIONARMOR_CHR_SOURCES_DIR/onionarmor-stratum1.sources"
  conf="$ONIONARMOR_CHR_CONF_DIR/onionarmor-stratum1.conf"
  [ -f "$src" ]
  [ -f "$conf" ]
  grep -q 'Managed by onionarmor' "$src"
  # 4 stratum-1 + 2 stratum-2 + 1 pool = 6 server lines and 1 pool line
  [ "$(grep -c '^server ' "$src")" -eq 6 ]
  grep -q '^pool pool.ntp.org' "$src"
  grep -q '^makestep 1.0 3' "$conf"
  grep -q '^rtcsync' "$conf"
  grep -q '^leapsectz right/UTC' "$conf"
  # timesyncd masked, chrony restarted + active
  grep -q 'mask systemd-timesyncd.service' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/systemd-timesyncd.service")" = "masked" ]
  grep -q 'restart chrony.service' "$STUB_STATE/systemctl.log"
  [[ "$output" == *"applied."* ]]
}

@test "apply: 4 stratum-1 sources are geographically/operationally diverse" {
  bash "$APPLY" >/dev/null
  src="$ONIONARMOR_CHR_SOURCES_DIR/onionarmor-stratum1.sources"
  grep -q 'time-a-g.nist.gov' "$src"   # NIST US
  grep -q 'tick.usno.navy.mil' "$src"  # USNO US
  grep -q 'ptbtime1.ptb.de' "$src"     # PTB EU
  grep -q 'ntp.nict.jp' "$src"         # NICT APAC
}

@test "apply: verify passes with >=2 reachable stratum-1" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"reachable stratum-1 sources"* ]]
}

@test "apply: verify fails (exit 2) when <2 reachable stratum-1" {
  FAKE_S1_COUNT=1 run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"reachable stratum-1"* ]]
}

@test "apply: installs chrony when absent" {
  ONIONARMOR_CHR_CHRONYD="$SB/nope-d" ONIONARMOR_CHR_CHRONYC="$SB/nope-c" \
    run bash "$APPLY" --no-verify
  [ "$status" -eq 0 ]
  grep -q 'install -y --no-install-recommends chrony' "$STUB/apt-get.log"
}

@test "apply: idempotent — second run rewrites nothing" {
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
}

@test "apply --no-mask-timesyncd: leaves timesyncd alone" {
  run bash "$APPLY" --no-mask-timesyncd
  [ "$status" -eq 0 ]
  [ "$(cat "$STUB_STATE/enabled/systemd-timesyncd.service")" = "enabled" ]
  ! grep -q 'mask systemd-timesyncd' "$STUB_STATE/systemctl.log"
}

@test "apply: appends sourcedir/confdir when the main conf lacks them" {
  # main conf without sourcedir/confdir -> apply must add an include block + back up
  printf 'driftfile /var/lib/chrony/chrony.drift\n' > "$ONIONARMOR_CHR_MAIN_CONF"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'onionarmor chrony-pinning include block' "$ONIONARMOR_CHR_MAIN_CONF"
  grep -q "^sourcedir $ONIONARMOR_CHR_SOURCES_DIR" "$ONIONARMOR_CHR_MAIN_CONF"
  grep -q "^confdir $ONIONARMOR_CHR_CONF_DIR" "$ONIONARMOR_CHR_MAIN_CONF"
  [ -f "$ONIONARMOR_CHR_STATE_DIR/chrony.conf.orig" ]
}

@test "apply: does NOT touch a main conf that already has sourcedir/confdir" {
  before="$(cat "$ONIONARMOR_CHR_MAIN_CONF")"
  bash "$APPLY" >/dev/null
  [ "$(cat "$ONIONARMOR_CHR_MAIN_CONF")" = "$before" ]
  [ ! -e "$ONIONARMOR_CHR_STATE_DIR/chrony.conf.orig" ]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'chr.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'chr.apply.sources' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'chr.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
