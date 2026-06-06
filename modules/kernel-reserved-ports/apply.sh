#!/usr/bin/env bash
# MODULE: Kernel reserved ports — reserve loopback tor ports from the ephemeral source-port pool (anti-collision).
#
# apply.sh — write net.ipv4.ip_local_reserved_ports for the relay's loopback
# service ports. Idempotent; supports --dry-run. The ports are auto-detected
# from torrc (--auto) and/or given explicitly (--reserved-range).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

krp_parse_flags "$@"

[ "$KRP_AUTO" -eq 1 ] || [ -n "$KRP_RANGES" ] \
  || die "kernel-reserved-ports: nothing to do — pass --auto and/or --reserved-range <start-end>"

dropin=$(krp_dropin_path)
ranges=$(krp_compute_ranges)
canon=$(krp_canon "$ranges")
before=$(krp_sysctl_runtime)

if [ -z "$ranges" ]; then
  if [ "$KRP_AUTO" -eq 1 ]; then
    die "kernel-reserved-ports: --auto found no loopback tor ports in $(krp_torrc_sources | paste -sd, - 2>/dev/null || true) — pass --reserved-range explicitly"
  fi
  die "kernel-reserved-ports: no ranges to reserve"
fi

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-in + before/after, change nothing.
# ---------------------------------------------------------------------------
if [ "$KRP_DRY_RUN" -eq 1 ]; then
  info "dry-run: kernel-reserved-ports (no host changes)"
  cat <<EOF

PLAN
  drop-in           -> $dropin
  sysctl key        -> $KRP_SYSCTL_KEY
  reservation       -> $ranges
  auto-detect       -> $([ "$KRP_AUTO" -eq 1 ] && echo "yes (buffer=$KRP_AUTO_BUFFER, listen=${KRP_LISTEN_IP:-all-loopback})" || echo no)
  manual ranges     -> ${KRP_RANGES:-none}
  planned command   -> $ONIONARMOR_SYSCTL_CMD --system

SYSCTL $KRP_SYSCTL_KEY
  before (live)     -> ${before:-<empty>}
  after  (planned)  -> $ranges

--- drop-in ($dropin) ---
$(krp_render_dropin "$ranges")
EOF
  exit 0
fi

audit_log krp.apply.start "ranges=$ranges auto=$KRP_AUTO buffer=$KRP_AUTO_BUFFER listen=${KRP_LISTEN_IP:-all-loopback}"

# ---------------------------------------------------------------------------
# 1. Write the managed drop-in (idempotent: skip if byte-identical).
# ---------------------------------------------------------------------------
rendered=$(krp_render_dropin "$ranges")
mkdir -p "$ONIONARMOR_SYSCTL_DIR" || die "cannot create $ONIONARMOR_SYSCTL_DIR"
if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$rendered" ]; then
  info "drop-in already current: $dropin"
else
  tmp="$dropin.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$dropin" || { rm -f "$tmp"; die "cannot move $tmp -> $dropin"; }
  audit_log krp.apply.dropin "wrote=$dropin ranges=$ranges"
  info "wrote drop-in: $dropin"
fi

# ---------------------------------------------------------------------------
# 2. Load it into the running kernel.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping sysctl --system"
elif "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1; then
  info "applied via $ONIONARMOR_SYSCTL_CMD --system"
else
  warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero; drop-in written but the key may not be live"
  reload_failed=1
fi

# ---------------------------------------------------------------------------
# 3. Verify (default on): live sysctl value AND /proc both match the drop-in.
#
# Verification, when it runs, is AUTHORITATIVE: if the live kernel value and
# /proc both match the drop-in, the apply succeeded — even if `sysctl --system`
# returned nonzero (it can fail over an unrelated drop-in while still loading
# ours). Only when verification is skipped/disabled does the reload exit code
# become the success signal, so a silent reload failure still fails the apply.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$KRP_VERIFY" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  live=$(krp_sysctl_runtime)
  if [ "$(krp_canon "$live")" = "$canon" ]; then
    info "verify: $KRP_SYSCTL_KEY = $live (matches drop-in)"
  else
    warn "verify: $KRP_SYSCTL_KEY is '$live', expected '$ranges'"; verify_failed=1
  fi

  if [ -r "$ONIONARMOR_KRP_PROC_FILE" ]; then
    proc=$(cat "$ONIONARMOR_KRP_PROC_FILE" 2>/dev/null || true)
    if [ "$(krp_canon "$proc")" = "$canon" ]; then
      info "verify: $ONIONARMOR_KRP_PROC_FILE = $proc"
    else
      warn "verify: $ONIONARMOR_KRP_PROC_FILE is '$proc', expected '$ranges'"; verify_failed=1
    fi
  else
    warn "verify: cannot read $ONIONARMOR_KRP_PROC_FILE (skipping /proc cross-check)"
  fi
elif [ "$reload_failed" -eq 1 ]; then
  # No verification ran (disabled or skipped) — the reload status is all we have.
  warn "verify skipped; treating the nonzero sysctl --system as a failure"
  verify_failed=1
fi

audit_log krp.apply.done "ranges=$ranges verify_failed=$verify_failed"

audit_hint="onionarmor audit  --module kernel-reserved-ports"
[ "$KRP_AUTO" -eq 1 ] && audit_hint="$audit_hint --auto"

cat <<EOF

[kernel-reserved-ports] applied.
  drop-in     : $dropin
  reservation : $ranges
  sysctl key  : $KRP_SYSCTL_KEY

Check status any time:  $audit_hint
Undo the reservation:   onionarmor revert --module kernel-reserved-ports
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
