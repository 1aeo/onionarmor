# Test helper for the kernel-hardening module bats suite.
#
# Builds a throwaway sandbox with a stub `sysctl` that emulates kernel sysctl
# state through a flat key=value file. `--system` loads our drop-in's keys into
# that state; `-n KEY` reads it; `-w KEY=VAL` sets it. Fully offline; never
# touches the real host. mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04's
# older bats.

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
  mkdir -p "$STUB"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_SYSCTL_DIR="$SB/etc/sysctl.d"
  export ONIONARMOR_KH_STATE_DIR="$SB/var/lib/onionarmor/kernel-hardening"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  : "${ONIONARMOR_KH_DROPIN_NAME:=99-onionarmor-kernel-hardening.conf}"
  export ONIONARMOR_KH_DROPIN_NAME
  export DROPIN="$ONIONARMOR_SYSCTL_DIR/$ONIONARMOR_KH_DROPIN_NAME"

  # Fake kernel sysctl state.
  export KH_STATE="$SB/proc/sysctl-state"
  mkdir -p "$ONIONARMOR_SYSCTL_DIR" "$(dirname "$KH_STATE")"
  : > "$KH_STATE"

  _build_stubs
  export ONIONARMOR_SYSCTL_CMD="$STUB/sysctl"
  export STUB_SYSCTL_LOG="$SB/sysctl.log"
  : > "$STUB_SYSCTL_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_sysctl KEY VALUE : preset a live kernel value (an insecure default).
seed_sysctl() {
  printf '%s=%s\n' "$1" "$2" >> "$KH_STATE"
}

# live_sysctl KEY : read the current stubbed kernel value.
live_sysctl() {
  "$ONIONARMOR_SYSCTL_CMD" -n "$1"
}

_build_stubs() {
  cat > "$STUB/sysctl" <<'EOF'
#!/bin/sh
LOG="${STUB_SYSCTL_LOG:-/dev/null}"
STATE="${KH_STATE:?}"
DROPIN="${ONIONARMOR_SYSCTL_DIR:?}/${ONIONARMOR_KH_DROPIN_NAME:-99-onionarmor-kernel-hardening.conf}"
printf '%s\n' "$*" >> "$LOG"
set_kv() {
  k=$1; v=$2; tmp="$STATE.tmp.$$"
  grep -v "^$k=" "$STATE" 2>/dev/null > "$tmp" || :
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  mv "$tmp" "$STATE"
}
case "$1" in
  --system)
    if [ -f "$DROPIN" ]; then
      # Load each "key = val" line from the drop-in into the fake kernel state.
      while IFS= read -r line; do
        case "$line" in \#*|'') continue ;; esac
        k=$(printf '%s' "$line" | sed -n 's/^[[:space:]]*\([^=]*[^= ]\)[[:space:]]*=.*/\1/p')
        v=$(printf '%s' "$line" | sed -n 's/^[^=]*=[[:space:]]*//p')
        [ -n "$k" ] && set_kv "$k" "$v"
      done < "$DROPIN"
    fi
    exit "${KH_SYSCTL_SYSTEM_RC:-0}"
    ;;
  -w)
    kv=$2; k=${kv%%=*}; v=${kv#*=}
    set_kv "$k" "$v"
    ;;
  -n)
    grep "^$2=" "$STATE" 2>/dev/null | tail -1 | sed 's/^[^=]*=//'
    ;;
esac
exit 0
EOF
  chmod +x "$STUB"/*
}
