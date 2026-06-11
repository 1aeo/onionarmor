# Test helper for the tor-config-baseline module bats suite.
#
# Builds a throwaway sandbox with a fake /etc/tor/instances/<name>/torrc tree and
# stub binaries for every external command the module touches (systemctl, at,
# atrm). The systemctl stub records each `reload tor@<inst>` to a log so tests can
# assert which instances were reloaded; the at/atrm stubs mirror the firewall
# suite's stateful queue. Fully offline, needs no root, never touches real tor.
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
  mkdir -p "$STUB"

  # --- sandbox paths the module reads/manages ---
  export ONIONARMOR_TCB_INSTANCES_DIR="$SB/etc/tor/instances"
  export ONIONARMOR_TCB_TORRC="$SB/etc/tor/torrc"
  export ONIONARMOR_TCB_STATE_DIR="$SB/var/lib/onionarmor/tor-config-baseline"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_TCB_INSTANCES_DIR"

  # --- safety-latch env into the sandbox ---
  export ONIONARMOR_LATCH_STATE_DIR="$SB/var/lib/onionarmor/latch"
  export ONIONARMOR_LATCH_TIMEOUT_MIN=5

  # at queue + counter + systemctl reload log
  export AT_QUEUE="$SB/at-queue"
  export AT_COUNTER="$SB/at-counter"
  export SYSTEMCTL_LOG="$SB/systemctl.log"
  : > "$AT_QUEUE"
  printf '0\n' > "$AT_COUNTER"
  : > "$SYSTEMCTL_LOG"

  _build_stubs
  export ONIONARMOR_TCB_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_AT_CMD="$STUB/at"
  export ONIONARMOR_ATRM_CMD="$STUB/atrm"

  # Ensure the stub dir is on PATH so `command -v at` in apply finds our stub.
  export PATH="$STUB:$PATH"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_instance <name> <torrc-content...> : create instances/<name>/torrc. The
# content is taken from stdin (heredoc) when no extra args are given.
seed_instance() {
  local name=$1; shift
  local dir="$ONIONARMOR_TCB_INSTANCES_DIR/$name"
  mkdir -p "$dir"
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$@" > "$dir/torrc"
  else
    cat > "$dir/torrc"
  fi
}

# torrc_path <name> : print the torrc path for instance <name>.
torrc_path() { printf '%s/%s/torrc\n' "$ONIONARMOR_TCB_INSTANCES_DIR" "$1"; }

# count_lines <pattern> <file> : grep -c convenience that never trips set -e.
count_match() { grep -c "$1" "$2" 2>/dev/null || true; }

# reloaded <inst> : true if the systemctl stub recorded a reload of tor@<inst>.
reloaded() { grep -qx "reload tor@$1" "$SYSTEMCTL_LOG"; }

# latch_jobid : the jobid persisted by the latch (empty if none).
latch_jobid() {
  cat "$ONIONARMOR_LATCH_STATE_DIR/tor-config-baseline/jobid" 2>/dev/null || true
}

_build_stubs() {
  # systemctl: record each "reload tor@<inst>" invocation, succeed.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${SYSTEMCTL_LOG:?}"
exit "${TCB_SYSTEMCTL_RC:-0}"
EOF

  # at: enqueue a job id, print "job N at <when>" on stderr (like real at).
  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat >/dev/null    # consume the scheduled command on stdin
if [ "${TCB_AT_FAIL:-0}" = "1" ]; then
  echo "at: cannot connect to atd" >&2
  exit 1
fi
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${AT_QUEUE:?}"
echo "warning: commands will be executed using /bin/sh" >&2
echo "job $n at Mon Jun  8 03:00:00 2026" >&2
exit 0
EOF

  # atrm: remove a job id from the queue.
  cat > "$STUB/atrm" <<'EOF'
#!/bin/sh
q="${AT_QUEUE:?}"; tmp="$q.tmp"
grep -vx "$1" "$q" > "$tmp" 2>/dev/null || :
mv "$tmp" "$q"
exit 0
EOF

  chmod +x "$STUB"/*
}
