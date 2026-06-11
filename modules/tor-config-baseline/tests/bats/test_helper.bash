# Test helper for the tor-config-baseline module bats suite.
#
# Builds a throwaway sandbox: per-instance torrc trees the module manages, plus a
# stub `systemctl` that logs every `reload <unit>` call to a sandbox log instead
# of touching the real host. Fully offline; never touches the real host or tor.
# We use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the older bats
# packaged on ubuntu-22.04.

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
  export ONIONARMOR_TCB_INSTANCES_DIR="$SB/etc/tor/instances"
  export ONIONARMOR_TCB_TORRC="$SB/etc/tor/torrc"
  export ONIONARMOR_TCB_STATE_DIR="$SB/var/lib/onionarmor/tor-config-baseline"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"

  mkdir -p "$ONIONARMOR_TCB_INSTANCES_DIR" "$(dirname "$ONIONARMOR_TCB_TORRC")"

  _build_stubs
  export ONIONARMOR_TCB_SYSTEMCTL="$STUB/systemctl"
  export STUB_SYSTEMCTL_LOG="$SB/systemctl.log"
  : > "$STUB_SYSTEMCTL_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_instance <name> <torrc-line...> : create
# $ONIONARMOR_TCB_INSTANCES_DIR/<name>/torrc with the given directive lines.
seed_instance() {
  local name="$1"; shift
  local dir="$ONIONARMOR_TCB_INSTANCES_DIR/$name"
  mkdir -p "$dir"
  printf '%s\n' "$@" > "$dir/torrc"
}

# torrc_path <name> : echo the torrc path for instance <name>.
torrc_path() {
  printf '%s/%s/torrc\n' "$ONIONARMOR_TCB_INSTANCES_DIR" "$1"
}

# block_body <name> : print only the managed-block lines (markers included).
block_body() {
  awk '/^# >>> onionarmor tor-config-baseline/{f=1} f{print} /^# <<< onionarmor tor-config-baseline/{f=0}' \
    "$(torrc_path "$1")"
}

# outside_block <name> : print only the lines OUTSIDE the managed block.
outside_block() {
  awk '/^# >>> onionarmor tor-config-baseline/{f=1} !f{print} /^# <<< onionarmor tor-config-baseline/{f=0}' \
    "$(torrc_path "$1")"
}

_build_stubs() {
  # systemctl stub: log every invocation's args to a sandbox log so tests can
  # assert which `reload tor@<name>` calls fired. Never touches the real host.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
LOG="${STUB_SYSTEMCTL_LOG:-/dev/null}"
printf '%s\n' "$*" >> "$LOG"
exit "${TCB_SYSTEMCTL_RC:-0}"
EOF
  chmod +x "$STUB"/*
}
