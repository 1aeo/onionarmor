#!/usr/bin/env bash
# MODULE: Conntrack tuning — raise nf_conntrack table ceiling + timeout + hashsize so a busy relay cannot pin the table full (tailscale hosts).
#
# apply.sh — render the two managed drop-ins (sysctl.d ceiling/timeout +
# modprobe.d hashsize), back up any existing ones, write them atomically, and
# load the sysctl values via `sysctl --system`. Idempotent; supports --dry-run
# and post-apply verification.
#
# The drop-ins are written even on a host that has not yet loaded nf_conntrack
# (pre-emptive: they simply take effect if/when the module is later loaded, e.g.
# when tailscale rolls out). Live verification is skipped in that case.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ct_parse_flags "$@"

# Refuse to write garbage values if an operator overrode a target with non-numeric input.
ct_is_uint "$ONIONARMOR_CT_MIN_MAX"             || die "conntrack-tuning: ONIONARMOR_CT_MIN_MAX must be a non-negative integer: $ONIONARMOR_CT_MIN_MAX"
ct_is_uint "$ONIONARMOR_CT_MAX_TCP_ESTABLISHED" || die "conntrack-tuning: ONIONARMOR_CT_MAX_TCP_ESTABLISHED must be a non-negative integer: $ONIONARMOR_CT_MAX_TCP_ESTABLISHED"
ct_is_uint "$ONIONARMOR_CT_HASHSIZE"            || die "conntrack-tuning: ONIONARMOR_CT_HASHSIZE must be a non-negative integer: $ONIONARMOR_CT_HASHSIZE"

sysctl_dropin=$(ct_sysctl_dropin_path)
modprobe_dropin=$(ct_modprobe_dropin_path)
sysctl_backup=$(ct_sysctl_backup_path)
modprobe_backup=$(ct_modprobe_backup_path)
sysctl_rendered=$(ct_render_sysctl_dropin)
modprobe_rendered=$(ct_render_modprobe_dropin)

loaded=no
ct_module_loaded && loaded=yes

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-ins + before(live)/after, change nothing.
# ---------------------------------------------------------------------------
if [ "$CT_DRY_RUN" -eq 1 ]; then
  info "dry-run: conntrack-tuning (no host changes)"
  cat <<EOF

PLAN
  sysctl drop-in    -> $sysctl_dropin
  modprobe drop-in  -> $modprobe_dropin
  module loaded     -> $loaded
  planned command   -> $ONIONARMOR_SYSCTL_CMD --system

SYSCTL (before live / after desired)
EOF
  printf "$_OA_FMT_SYSCTL_ROW" "KEY" "CURRENT" "TARGET" "STATUS"
  printf "$_OA_FMT_SYSCTL_ROW" "$_OA_DASH_SYSCTL_ROW" "$_OA_DASH_SYSCTL_COL" "$_OA_DASH_SYSCTL_COL" "------"
  for pair in "$CT_KEY_MAX=$ONIONARMOR_CT_MIN_MAX" "$CT_KEY_TCP_ESTABLISHED=$ONIONARMOR_CT_MAX_TCP_ESTABLISHED"; do
    key=${pair%%=*}; want=${pair#*=}
    live=$(ct_sysctl_runtime "$key")
    if [ "$live" = "$want" ]; then st="ok"; else st="change"; fi
    printf "$_OA_FMT_SYSCTL_ROW" "$key" "${live:-<empty>}" "$want" "$st"
  done
  cat <<EOF

--- sysctl drop-in ($sysctl_dropin) ---
$sysctl_rendered

--- modprobe drop-in ($modprobe_dropin) ---
$modprobe_rendered

Note: hashsize takes effect when nf_conntrack is (re)loaded — typically at the
next reboot. The sysctl ceiling/timeout load immediately via sysctl --system.
EOF
  exit 0
fi

audit_log ct.apply.start "sysctl_dropin=$sysctl_dropin modprobe_dropin=$modprobe_dropin loaded=$loaded verify=$CT_VERIFY"

# ---------------------------------------------------------------------------
# 1. Back up any existing drop-ins before overwriting them.
# ---------------------------------------------------------------------------
ct_backup_existing() {
  # ct_backup_existing <live-path> <backup-path> <rendered-content>
  # Capture the PRE-onionarmor file exactly once so revert can restore it. Skip
  # when: the live file is absent (nothing to save); a backup already exists
  # (preserve the original — a re-apply must never clobber it with our managed
  # content); or the live file is already byte-identical to what we will write
  # (it is our own managed drop-in, not an operator original worth saving).
  [ -f "$1" ] || return 0
  [ -f "$2" ] && return 0
  [ "$(cat "$1")" = "$3" ] && return 0
  mkdir -p "$ONIONARMOR_CT_STATE_DIR" || die "cannot create $ONIONARMOR_CT_STATE_DIR"
  cp -p "$1" "$2" \
    || audit_fail_die ct.apply.fail "stage=backup" "failed to back up $1 -> $2"
  info "backed up existing drop-in -> $2"
}
ct_backup_existing "$sysctl_dropin"   "$sysctl_backup"   "$sysctl_rendered"
ct_backup_existing "$modprobe_dropin" "$modprobe_backup" "$modprobe_rendered"

# ---------------------------------------------------------------------------
# 2. Write the managed drop-ins (atomic; skip rewrite if byte-identical).
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_SYSCTL_DIR"   || die "cannot create $ONIONARMOR_SYSCTL_DIR"
mkdir -p "$ONIONARMOR_MODPROBE_DIR" || die "cannot create $ONIONARMOR_MODPROBE_DIR"

wrote_any=0
if oa_write_if_changed "$sysctl_dropin" "$sysctl_rendered"; then
  audit_log ct.apply.dropin "wrote=$sysctl_dropin"
  info "wrote sysctl drop-in: $sysctl_dropin"; wrote_any=1
else
  info "sysctl drop-in already current: $sysctl_dropin"
fi

if oa_write_if_changed "$modprobe_dropin" "$modprobe_rendered"; then
  audit_log ct.apply.dropin "wrote=$modprobe_dropin"
  info "wrote modprobe drop-in: $modprobe_dropin"; wrote_any=1
else
  info "modprobe drop-in already current: $modprobe_dropin"
fi

[ "$wrote_any" -eq 1 ] || info "drop-ins already current — no changes"

# ---------------------------------------------------------------------------
# 3. Load the sysctl ceiling/timeout into the running kernel. Only meaningful
# when nf_conntrack is loaded — the keys do not exist otherwise.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "$loaded" != "yes" ]; then
  info "nf_conntrack not loaded — drop-ins persisted; live keys will apply when the module loads"
elif [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping sysctl --system"
elif "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1; then
  info "applied via $ONIONARMOR_SYSCTL_CMD --system"
else
  warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero; drop-ins written but keys may not be live"
  reload_failed=1
fi

# ---------------------------------------------------------------------------
# 4. Verify (default on, only when loaded): each live sysctl matches the target.
#
# When it runs, verification is AUTHORITATIVE: matching live values mean success
# even if `sysctl --system` returned nonzero (it can fail over an unrelated
# drop-in while still loading ours). Only with --no-verify does the reload exit
# code become the success signal.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$loaded" = "yes" ] && [ "$CT_VERIFY" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  for pair in "$CT_KEY_MAX=$ONIONARMOR_CT_MIN_MAX" "$CT_KEY_TCP_ESTABLISHED=$ONIONARMOR_CT_MAX_TCP_ESTABLISHED"; do
    key=${pair%%=*}; want=${pair#*=}
    live=$(ct_sysctl_runtime "$key")
    if [ "$live" = "$want" ]; then
      info "verify: $key = $live"
    elif [ -z "$live" ]; then
      warn "verify: $key is unreadable (skipping)"
    else
      warn "verify: $key is '$live', expected '$want'"; verify_failed=1
    fi
  done
elif [ "$reload_failed" -eq 1 ]; then
  warn "verify disabled; treating the nonzero sysctl --system as a failure"
  verify_failed=1
fi

audit_log ct.apply.done "verify_failed=$verify_failed loaded=$loaded"

cat <<EOF

[conntrack-tuning] applied.
  sysctl drop-in   : $sysctl_dropin
  modprobe drop-in : $modprobe_dropin
  module loaded    : $loaded

Check status any time:  onionarmor audit  --module conntrack-tuning
Undo the tuning:        onionarmor revert --module conntrack-tuning
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
