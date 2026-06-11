# Test helper for the kernel-hardening module bats suite.
#
# Builds a throwaway sandbox: a stub `sysctl` that emulates the kernel's
# per-key runtime state through a fake state dir. `--system` loads the managed
# keys from the drop-in into that state; `-w key=val` sets one key; `-n key`
# prints a key (defaulting to a "wrong" pre-hardening value for keys not yet
# loaded, so drift is visible before apply). Fully offline; never touches the
# real host. We use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the
# older bats packaged on ubuntu-22.04.

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

  # Derive DROPIN from the same knob lib.sh uses, so a test overriding the
  # filename exercises the real production contract, not a hardcoded path.
  : "${ONIONARMOR_KH_DROPIN_NAME:=99-onionarmor-kernel-hardening.conf}"
  export ONIONARMOR_KH_DROPIN_NAME
  export DROPIN="$ONIONARMOR_SYSCTL_DIR/$ONIONARMOR_KH_DROPIN_NAME"

  # The stub keeps fake per-key kernel state here.
  export KH_FAKE_STATE="$SB/kernel-state"
  mkdir -p "$ONIONARMOR_SYSCTL_DIR" "$KH_FAKE_STATE"

  _build_stubs
  export ONIONARMOR_SYSCTL_CMD="$STUB/sysctl"

  export STUB_SYSCTL_LOG="$SB/sysctl.log"
  : > "$STUB_SYSCTL_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# desired_keys: emit "key value" pairs (the canonical KSPP set) so tests can
# assert against the same source of truth the module renders from.
desired_keys() {
  sed -n 's/^\([a-z0-9._]*\) = \(.*\)$/\1 \2/p' "$DROPIN"
}

_build_stubs() {
  # sysctl stub: emulate the kernel's per-key runtime state through files under
  # $KH_FAKE_STATE (one file per key, key name with '/' for '.').
  #   sysctl --system     -> load every managed key from the drop-in into state
  #   sysctl -w KEY=VALUE  -> set one key's state
  #   sysctl -n KEY        -> echo the key's state; for a key never loaded, echo
  #                           a deliberately "wrong" pre-hardening value (0) so
  #                           drift is visible before apply.
  cat > "$STUB/sysctl" <<'EOF'
#!/bin/sh
LOG="${STUB_SYSCTL_LOG:-/dev/null}"
STATE="${KH_FAKE_STATE:?}"
DROPIN="${ONIONARMOR_SYSCTL_DIR:?}/${ONIONARMOR_KH_DROPIN_NAME:-99-onionarmor-kernel-hardening.conf}"
printf '%s\n' "$*" >> "$LOG"

keyfile() { printf '%s/%s' "$STATE" "$(printf '%s' "$1" | tr '/' '.')"; }

case "$1" in
  --system)
    if [ -f "$DROPIN" ]; then
      # Load every "key = value" line from the drop-in into the fake state.
      sed -n 's/^[[:space:]]*\([a-z0-9._]*\)[[:space:]]*=[[:space:]]*\(.*\)$/\1 \2/p' "$DROPIN" \
      | while read -r k v; do
          [ -n "$k" ] || continue
          printf '%s' "$v" > "$(keyfile "$k")"
        done
    fi
    exit "${KH_SYSCTL_SYSTEM_RC:-0}"
    ;;
  -w)
    kv=$2; k=${kv%%=*}; v=${kv#*=}
    printf '%s' "$v" > "$(keyfile "$k")"
    ;;
  -n)
    f=$(keyfile "$2")
    if [ -f "$f" ]; then
      cat "$f"
    else
      # Pre-hardening default for any key not yet loaded: 0 (drift vs KSPP).
      printf '0'
    fi
    ;;
esac
exit 0
EOF
  chmod +x "$STUB"/*
}
