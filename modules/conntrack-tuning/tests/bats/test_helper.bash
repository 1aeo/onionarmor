# Test helper for the conntrack-tuning module bats suite.
#
# Builds a throwaway sandbox: a stub `sysctl` that emulates per-key kernel
# runtime state through a fake state dir (the repo's shared tests/fixtures/
# fake-sysctl has no `-w`, and this module needs to set nf_conntrack_count and
# simulate live drift), a fake /proc marker to toggle "is nf_conntrack loaded",
# and sandbox sysctl.d / modprobe.d trees. Fully offline; never touches the real
# host. We use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the older
# bats packaged on ubuntu-22.04.
#
# By default the sandbox simulates a LOADED tracker (marker present) with a low
# live table count, so an apply lands all-green. Use ct_set_unloaded to drop the
# marker, and `$ONIONARMOR_SYSCTL_CMD -w key=val` to drive live values.

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
  STUB="$SB/stubs"; mkdir -p "$STUB"
  export STUB

  # --- sandbox paths the module manages ---
  export ONIONARMOR_SYSCTL_DIR="$SB/etc/sysctl.d"
  export ONIONARMOR_MODPROBE_DIR="$SB/etc/modprobe.d"
  export ONIONARMOR_CT_STATE_DIR="$SB/var/lib/onionarmor/conntrack-tuning"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"

  # Tracker presence marker (present => loaded; ct_set_unloaded removes it).
  export ONIONARMOR_CT_PROC_MARKER="$SB/proc/nf_conntrack_max"

  # Derive the managed paths from the same knobs lib.sh uses.
  : "${ONIONARMOR_CT_DROPIN_NAME:=99-conntrack-tuning.conf}"
  : "${ONIONARMOR_CT_MODPROBE_NAME:=nf_conntrack.conf}"
  export ONIONARMOR_CT_DROPIN_NAME ONIONARMOR_CT_MODPROBE_NAME
  export SYSCTL_DROPIN="$ONIONARMOR_SYSCTL_DIR/$ONIONARMOR_CT_DROPIN_NAME"
  export MODPROBE_DROPIN="$ONIONARMOR_MODPROBE_DIR/$ONIONARMOR_CT_MODPROBE_NAME"

  # The stub keeps fake per-key kernel state here (one file per key).
  export CT_FAKE_STATE="$SB/kernel-state"
  mkdir -p "$ONIONARMOR_SYSCTL_DIR" "$ONIONARMOR_MODPROBE_DIR" \
           "$(dirname "$ONIONARMOR_AUDIT_LOG")" "$(dirname "$ONIONARMOR_CT_PROC_MARKER")" \
           "$CT_FAKE_STATE"

  _build_sysctl_stub
  export ONIONARMOR_SYSCTL_CMD="$STUB/sysctl"

  # Default: tracker loaded, with a small live table count so utilization is
  # green until a test seeds it higher.
  ct_set_loaded
  "$ONIONARMOR_SYSCTL_CMD" -w net.netfilter.nf_conntrack_count=1000
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# ct_set_loaded / ct_set_unloaded: toggle the simulated nf_conntrack presence.
ct_set_loaded()   { : > "$ONIONARMOR_CT_PROC_MARKER"; }
ct_set_unloaded() { rm -f "$ONIONARMOR_CT_PROC_MARKER"; }

_build_sysctl_stub() {
  # sysctl stub: emulate per-key runtime state through files under $CT_FAKE_STATE
  # (one file per key).
  #   sysctl -n KEY        echo the key's state, or nothing if never set
  #                        (unreadable => empty, so the audit's unscoreable path
  #                        is exercised).
  #   sysctl -w KEY=VALUE  set one key's state.
  #   sysctl --system      load every "key = value" line from each *.conf under
  #                        $ONIONARMOR_SYSCTL_DIR (skipping .bak files) into state.
  cat > "$STUB/sysctl" <<'EOF'
#!/bin/sh
STATE="${CT_FAKE_STATE:?}"
keyfile() { printf '%s/%s' "$STATE" "$1"; }

case "${1:-}" in
  -n)
    f=$(keyfile "$2")
    [ -f "$f" ] && cat "$f"
    ;;
  -w)
    kv=$2; k=${kv%%=*}; v=${kv#*=}
    printf '%s' "$v" > "$(keyfile "$k")"
    ;;
  --system)
    d=${ONIONARMOR_SYSCTL_DIR:-/etc/sysctl.d}
    [ -d "$d" ] || exit 0
    for f in "$d"/*.conf; do
      [ -f "$f" ] || continue
      case "$f" in *.bak*) continue ;; esac
      sed -n 's/^[[:space:]]*\(net[a-z0-9._]*\)[[:space:]]*=[[:space:]]*\(.*\)$/\1 \2/p' "$f" \
      | while read -r k v; do
          [ -n "$k" ] || continue
          printf '%s' "$v" > "$(keyfile "$k")"
        done
    done
    ;;
esac
exit 0
EOF
  chmod +x "$STUB/sysctl"
}
