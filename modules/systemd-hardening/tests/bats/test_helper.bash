# Test helper for the systemd-hardening module bats suite.
#
# Builds a throwaway sandbox of fixture unit files + a fake `systemctl` so the
# suite drives the whole module without real systemd. The fake systemctl:
#   * daemon-reload / restart  -> logged; restart sets the unit active UNLESS the
#     unit is in $FAKE_FAIL_ALWAYS, or in $FAKE_FAIL_WITH_DROPIN while its
#     managed drop-in still exists (models a too-tight ReadWritePaths that the
#     module's auto-revert then has to recover from).
#   * is-active                -> per-unit state file (default active).
#   * show --property=P --value -> reads the unit's managed drop-in.
# `sleep` is stubbed to a no-op so the 30s settle loop runs instantly.

setup() {
  MOD_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export MOD_ROOT
  REPO_ROOT="$(cd "$MOD_ROOT/../.." && pwd)"
  export REPO_ROOT
  export ONIONARMOR_PREFIX="$REPO_ROOT"
  FIXTURES="$MOD_ROOT/tests/fixtures/systemd-units"
  export FIXTURES

  APPLY="$MOD_ROOT/apply.sh"
  AUDIT="$MOD_ROOT/audit.sh"
  REVERT="$MOD_ROOT/revert.sh"
  export APPLY AUDIT REVERT

  SB="$(mktemp -d)"
  export SB
  STUB="$SB/stubs"
  export STUB
  export SC_STATE="$SB/sc-state"
  mkdir -p "$STUB" "$SC_STATE/active"

  # --- sandbox systemd tree ---
  export ONIONARMOR_SH_DROPIN_ROOT="$SB/etc/systemd/system"
  export ONIONARMOR_SH_UNIT_DIRS="$SB/etc/systemd/system"
  export ONIONARMOR_SH_WANTS_DIRS="$SB/etc/systemd/system/multi-user.target.wants"
  export ONIONARMOR_SH_STATE_DIR="$SB/var/lib/onionarmor/systemd-hardening"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_SH_DROPIN_ROOT" "$ONIONARMOR_SH_WANTS_DIRS"

  # Fast settle loop.
  export ONIONARMOR_SH_RESTART_TIMEOUT=3
  export ONIONARMOR_SH_RESTART_INTERVAL=1

  # Install the candidate unit files + two enabled tor instances by default.
  cp "$FIXTURES"/*.service "$ONIONARMOR_SH_DROPIN_ROOT/"
  enable_tor_instance 0
  enable_tor_instance 1

  # Failure-injection sets (space-separated unit names).
  export FAKE_FAIL_ALWAYS=""
  export FAKE_FAIL_WITH_DROPIN=""

  _build_stubs
  export ONIONARMOR_SH_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_SH_SLEEP="$STUB/sleep"
  export ONIONARMOR_SH_SHA256="$STUB/sha256sum"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# enable_tor_instance <n>: drop a wants entry so detection sees tor@<n>.service.
enable_tor_instance() {
  : > "$ONIONARMOR_SH_WANTS_DIRS/tor@$1.service"
}

# remove_unit <unit>: make a unit "absent" by deleting its fixture file.
remove_unit() {
  rm -f "$ONIONARMOR_SH_UNIT_DIRS/$1"
}

_build_stubs() {
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
S="${SC_STATE:?}"; mkdir -p "$S/active"
root="${ONIONARMOR_SH_DROPIN_ROOT:?}"
name="${ONIONARMOR_SH_DROPIN_NAME:-99-onionarmor-hardening.conf}"
verb=$1; shift

# Parse unit + show flags.
unit=""; prop=""; value_only=0
for a in "$@"; do
  case "$a" in
    --property=*) prop="${a#--property=}" ;;
    --value)      value_only=1 ;;
    -*)           ;;
    *)            [ -z "$unit" ] && unit="$a" ;;
  esac
done
echo "$verb $unit $*" >> "$S/systemctl.log"

in_set() { # in_set <unit> <set-string>
  for x in $2; do [ "$x" = "$1" ] && return 0; done; return 1
}

case "$verb" in
  daemon-reload) exit 0 ;;
  is-active) cat "$S/active/$unit" 2>/dev/null || echo inactive ;;
  start|restart)
    dropin="$root/$unit.d/$name"
    if in_set "$unit" "${FAKE_FAIL_ALWAYS:-}"; then
      echo inactive > "$S/active/$unit"; exit 1
    fi
    if in_set "$unit" "${FAKE_FAIL_WITH_DROPIN:-}" && [ -f "$dropin" ]; then
      echo inactive > "$S/active/$unit"; exit 1
    fi
    echo active > "$S/active/$unit"; exit 0
    ;;
  stop) echo inactive > "$S/active/$unit"; exit 0 ;;
  show)
    dropin="$root/$unit.d/$name"
    val=""
    [ -n "$prop" ] && [ -f "$dropin" ] && \
      val=$(grep -E "^$prop=" "$dropin" 2>/dev/null | head -1 | sed "s/^$prop=//")
    if [ "$value_only" = 1 ]; then printf '%s\n' "$val"; else printf '%s=%s\n' "$prop" "$val"; fi
    exit 0
    ;;
  *) exit 0 ;;
esac
EOF

  cat > "$STUB/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF

  cat > "$STUB/sha256sum" <<'EOF'
#!/bin/sh
f=$1
if [ -f "$f" ]; then
  h=$(cksum "$f" | awk '{print $1}')
  printf '%016x  %s\n' "$h" "$f"
  exit 0
fi
exit 1
EOF

  chmod +x "$STUB"/*
}
