# Test helper for the chrony-pinning module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (systemctl, apt-get, chronyc, chronyd) so the suite is fully
# offline and never changes the real host. The mock chronyc emits a realistic
# `-n sources` table and `tracking` block, both controllable via env:
#   FAKE_S1_COUNT   number of reachable stratum-1 rows (default 4)
#   FAKE_OFFSET     last offset in seconds (default 0.000012)
# mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04's older bats.

setup() {
  MOD_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export MOD_ROOT
  REPO_ROOT="$(cd "$MOD_ROOT/../.." && pwd)"
  export REPO_ROOT
  export ONIONARMOR_PREFIX="$REPO_ROOT"

  APPLY="$MOD_ROOT/apply.sh"
  AUDIT="$MOD_ROOT/audit.sh"
  REVERT="$MOD_ROOT/revert.sh"
  export APPLY AUDIT REVERT

  SB="$(mktemp -d)"
  export SB
  STUB="$SB/stubs"
  export STUB
  export STUB_STATE="$SB/systemctl-state"
  mkdir -p "$STUB" "$STUB_STATE/active" "$STUB_STATE/enabled"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_CHR_SOURCES_DIR="$SB/etc/chrony/sources.d"
  export ONIONARMOR_CHR_CONF_DIR="$SB/etc/chrony/conf.d"
  export ONIONARMOR_CHR_MAIN_CONF="$SB/etc/chrony/chrony.conf"
  export ONIONARMOR_CHR_STATE_DIR="$SB/var/lib/onionarmor/chrony-pinning"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_CHR_SOURCES_DIR" "$ONIONARMOR_CHR_CONF_DIR" "$(dirname "$ONIONARMOR_CHR_MAIN_CONF")"

  # A modern chrony.conf already pulls in sources.d / conf.d.
  {
    printf 'sourcedir %s\n' "$ONIONARMOR_CHR_SOURCES_DIR"
    printf 'confdir %s\n' "$ONIONARMOR_CHR_CONF_DIR"
    printf 'driftfile /var/lib/chrony/chrony.drift\n'
  } > "$ONIONARMOR_CHR_MAIN_CONF"

  export FAKE_S1_COUNT=4
  export FAKE_OFFSET=0.000012

  _build_stubs

  export ONIONARMOR_CHR_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_CHR_APT="$STUB/apt-get"
  export ONIONARMOR_CHR_CHRONYC="$STUB/chronyc"
  export ONIONARMOR_CHR_CHRONYD="$STUB/chronyd"

  # Initial service state: chrony stopped, timesyncd running + enabled.
  printf 'inactive\n' > "$STUB_STATE/active/chrony.service"
  printf 'disabled\n' > "$STUB_STATE/enabled/chrony.service"
  printf 'active\n'   > "$STUB_STATE/active/systemd-timesyncd.service"
  printf 'enabled\n'  > "$STUB_STATE/enabled/systemd-timesyncd.service"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

_build_stubs() {
  # systemctl: stateful per-unit active/enabled; logs verbs.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
S="${STUB_STATE:?}"; mkdir -p "$S/active" "$S/enabled"
verb=$1; shift
now=0; unit=""
for a in "$@"; do
  case "$a" in
    --now) now=1 ;;
    -*) ;;
    *) [ -z "$unit" ] && unit="$a" ;;
  esac
done
printf '%s %s now=%s\n' "$verb" "$unit" "$now" >> "$S/systemctl.log"
af="$S/active/$unit"; ef="$S/enabled/$unit"
case "$verb" in
  is-active)  cat "$af" 2>/dev/null || echo inactive ;;
  is-enabled) cat "$ef" 2>/dev/null || echo disabled ;;
  mask)       echo masked > "$ef";   [ "$now" = 1 ] && echo inactive > "$af" ;;
  unmask)     echo disabled > "$ef" ;;
  disable)    echo disabled > "$ef"; [ "$now" = 1 ] && echo inactive > "$af" ;;
  enable)     echo enabled > "$ef";  [ "$now" = 1 ] && echo active > "$af" ;;
  start)      echo active > "$af" ;;
  stop)       echo inactive > "$af" ;;
  restart|reload) echo active > "$af" ;;
esac
exit 0
EOF

  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
echo "$*" >> "${STUB:?}/apt-get.log"
exit 0
EOF

  # chronyd: presence-only stub (command -v must succeed).
  cat > "$STUB/chronyd" <<'EOF'
#!/bin/sh
exit 0
EOF

  # chronyc: mock `-n sources` and `tracking`.
  cat > "$STUB/chronyc" <<'EOF'
#!/bin/sh
case "$*" in
  *sources*)
    echo 'MS Name/IP address         Stratum Poll Reach LastRx Last sample'
    echo '==============================================================================='
    i=0
    while [ "$i" -lt "${FAKE_S1_COUNT:-4}" ]; do
      printf '^* 192.0.2.%-18s 1   6   377    21    +12us[  +13us] +/-  8ms\n' "$((10 + i))"
      i=$((i + 1))
    done
    # one stratum-2 fallback row
    echo '^+ 192.0.2.200              2   6   377    19    -30us[  -28us] +/- 18ms'
    ;;
  *tracking*)
    echo 'Reference ID    : C0000202 (192.0.2.2)'
    echo 'Stratum         : 2'
    echo 'Ref time (UTC)  : Mon Jun 08 03:00:00 2026'
    printf 'Last offset     : +%s seconds\n' "${FAKE_OFFSET:-0.000012}"
    echo 'RMS offset      : 0.000020000 seconds'
    echo 'System time     : 0.000001234 seconds slow of NTP time'
    ;;
  *) : ;;
esac
exit 0
EOF

  chmod +x "$STUB"/*
}
