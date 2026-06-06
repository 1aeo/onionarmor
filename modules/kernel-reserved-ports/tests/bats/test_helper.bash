# Test helper for the kernel-reserved-ports module bats suite.
#
# Builds a throwaway sandbox: a stub `sysctl` that emulates the kernel's
# ip_local_reserved_ports state through a fake /proc file, plus sandbox torrc
# trees the --auto detector reads. Fully offline; never touches the real host.
# We use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the older
# bats packaged on ubuntu-22.04.

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
  export ONIONARMOR_KRP_STATE_DIR="$SB/var/lib/onionarmor/kernel-reserved-ports"
  export ONIONARMOR_KRP_PROC_FILE="$SB/proc/ip_local_reserved_ports"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  export DROPIN="$ONIONARMOR_SYSCTL_DIR/99-onionarmor-reserved-ports.conf"

  # --- sandbox torrc sources for --auto ---
  export ONIONARMOR_KRP_TOR_INSTANCES_DIR="$SB/etc/tor/instances"
  export ONIONARMOR_KRP_TOR_RUN_DIR="$SB/run/tor-instances"
  export ONIONARMOR_KRP_TORRC_ALL="$SB/etc/tor/torrc.all"
  export ONIONARMOR_KRP_TORRC="$SB/etc/tor/torrc"

  mkdir -p "$ONIONARMOR_SYSCTL_DIR" \
           "$(dirname "$ONIONARMOR_KRP_PROC_FILE")" \
           "$ONIONARMOR_KRP_TOR_INSTANCES_DIR" \
           "$ONIONARMOR_KRP_TOR_RUN_DIR" \
           "$(dirname "$ONIONARMOR_KRP_TORRC")"

  # Kernel starts with an empty reservation.
  : > "$ONIONARMOR_KRP_PROC_FILE"

  _build_stubs
  export ONIONARMOR_SYSCTL_CMD="$STUB/sysctl"

  # The stub needs to know which drop-in to read and which /proc file to drive.
  export STUB_SYSCTL_LOG="$SB/sysctl.log"
  : > "$STUB_SYSCTL_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_instance <name> <torrc-line...> : create
# $TOR_INSTANCES_DIR/<name>/torrc with the given directive lines.
seed_instance() {
  local name="$1"; shift
  local dir="$ONIONARMOR_KRP_TOR_INSTANCES_DIR/$name"
  mkdir -p "$dir"
  printf '%s\n' "$@" > "$dir/torrc"
}

# Convenience: a fleet of instances each with one MetricsPort on loopback.
# seed_metrics_fleet 48010 48020 48030 ...
seed_metrics_fleet() {
  local i=1 p
  for p in "$@"; do
    seed_instance "relay$i" "MetricsPort 127.0.0.1:$p"
    i=$((i + 1))
  done
}

_build_stubs() {
  # sysctl stub: emulate the kernel's ip_local_reserved_ports through a fake
  # /proc file.
  #   sysctl --system        -> load the managed key from the drop-in (if any)
  #   sysctl -w KEY=VALUE     -> set the runtime value (empty VALUE clears it)
  #   sysctl -n KEY           -> echo the runtime value
  cat > "$STUB/sysctl" <<'EOF'
#!/bin/sh
LOG="${STUB_SYSCTL_LOG:-/dev/null}"
PROC="${ONIONARMOR_KRP_PROC_FILE:?}"
DROPIN="${ONIONARMOR_SYSCTL_DIR:?}/99-onionarmor-reserved-ports.conf"
KEY="net.ipv4.ip_local_reserved_ports"
printf '%s\n' "$*" >> "$LOG"
case "$1" in
  --system)
    if [ -f "$DROPIN" ]; then
      v=$(sed -n "s/^[[:space:]]*net\.ipv4\.ip_local_reserved_ports[[:space:]]*=[[:space:]]*//p" "$DROPIN" | tail -1)
      printf '%s' "$v" > "$PROC"
    fi
    # Emulate a noisy --system that still loads our key (e.g. an unrelated
    # drop-in failed): apply our value, then exit nonzero if asked to.
    exit "${KRP_SYSCTL_SYSTEM_RC:-0}"
    ;;
  -w)
    kv=$2; k=${kv%%=*}; val=${kv#*=}
    [ "$k" = "$KEY" ] && printf '%s' "$val" > "$PROC"
    ;;
  -n)
    [ "$2" = "$KEY" ] && { cat "$PROC" 2>/dev/null || printf ''; }
    ;;
esac
exit 0
EOF
  chmod +x "$STUB"/*
}
