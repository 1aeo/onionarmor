#!/usr/bin/env bash
# MODULE: Kernel hardening — write & load the KSPP-recommended sysctl hardening drop-in (default-on, low-risk).
#
# apply.sh — render the KSPP kernel-hardening sysctl drop-in, back up any
# existing one, write it atomically, and load it via `sysctl --system`.
# Idempotent; supports --dry-run and post-apply verification.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

dropin=$(kh_dropin_path)
backup=$(kh_backup_path)
rendered=$(kh_render_dropin)

# ---------------------------------------------------------------------------
# kh_live_matches: return 0 iff every key's live value already equals desired.
# Used to short-circuit a reload when nothing would change.
# ---------------------------------------------------------------------------
kh_live_matches() {
  local key want live
  while read -r key want; do
    live=$(kh_sysctl_runtime "$key")
    [ "$(kh_normalise "$live")" = "$(kh_normalise "$want")" ] || return 1
  done < <(kh_each_key)
  return 0
}

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-in + before(live)/after, change nothing.
# ---------------------------------------------------------------------------
if [ "$KH_DRY_RUN" -eq 1 ]; then
  info "dry-run: kernel-hardening (no host changes)"
  cat <<EOF

PLAN
  drop-in           -> $dropin
  keys              -> $(kh_each_key | grep -c .) KSPP sysctls
  planned command   -> $ONIONARMOR_SYSCTL_CMD --system

SYSCTL (before live / after desired)
EOF
  printf "$_OA_FMT_SYSCTL_ROW" "KEY" "CURRENT" "TARGET" "STATUS"
  printf "$_OA_FMT_SYSCTL_ROW" "$_OA_DASH_SYSCTL_ROW" "$_OA_DASH_SYSCTL_COL" "$_OA_DASH_SYSCTL_COL" "------"
  while read -r key want; do
    live=$(kh_sysctl_runtime "$key")
    if [ "$(kh_normalise "$live")" = "$(kh_normalise "$want")" ]; then
      st="ok"
    else
      st="change"
    fi
    printf "$_OA_FMT_SYSCTL_ROW" "$key" "${live:-<empty>}" "$want" "$st"
  done < <(kh_each_key)
  cat <<EOF

--- drop-in ($dropin) ---
$rendered
EOF
  exit 0
fi

audit_log kh.apply.start "dropin=$dropin verify=$KH_VERIFY"

# ---------------------------------------------------------------------------
# Idempotence: if the drop-in already byte-matches AND (when verifying) the live
# values already match, there is nothing to do — skip the reload entirely.
# ---------------------------------------------------------------------------
if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$rendered" ]; then
  if [ "$KH_VERIFY" -eq 0 ] || kh_live_matches; then
    audit_log kh.apply.done "already-current=1"
    info "kernel-hardening already current: $dropin"
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# 1. Back up any existing drop-in before overwriting it.
# ---------------------------------------------------------------------------
if [ -f "$dropin" ]; then
  mkdir -p "$ONIONARMOR_KH_STATE_DIR" || die "cannot create $ONIONARMOR_KH_STATE_DIR"
  cp -p "$dropin" "$backup" \
    || audit_fail_die kh.apply.fail "stage=backup" "failed to back up $dropin -> $backup"
  info "backed up existing drop-in -> $backup"
fi

# ---------------------------------------------------------------------------
# 2. Write the managed drop-in (atomic; skip rewrite if byte-identical).
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_SYSCTL_DIR" || die "cannot create $ONIONARMOR_SYSCTL_DIR"
if oa_write_if_changed "$dropin" "$rendered"; then
  audit_log kh.apply.dropin "wrote=$dropin keys=$(kh_each_key | grep -c .)"
  info "wrote drop-in: $dropin"
else
  info "drop-in already current: $dropin"
fi

# ---------------------------------------------------------------------------
# 3. Load it into the running kernel.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping sysctl --system"
elif "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1; then
  info "applied via $ONIONARMOR_SYSCTL_CMD --system"
else
  warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero; drop-in written but keys may not all be live"
  reload_failed=1
fi

# ---------------------------------------------------------------------------
# 4. Verify (default on): each live sysctl value matches the KSPP target.
#
# Verification, when it runs, is AUTHORITATIVE: if every live value matches the
# drop-in, the apply succeeded — even if `sysctl --system` returned nonzero (it
# can fail over an unrelated drop-in while still loading ours). Only when
# verification is disabled does the reload exit code become the success signal,
# so a silent reload failure still fails the apply.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$KH_VERIFY" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  while read -r key want; do
    live=$(kh_sysctl_runtime "$key")
    if [ "$(kh_normalise "$live")" = "$(kh_normalise "$want")" ]; then
      info "verify: $key = $live"
    elif [ -z "$live" ]; then
      warn "verify: $key is unreadable on this kernel (skipping)"
    else
      warn "verify: $key is '$live', expected '$want'"; verify_failed=1
    fi
  done < <(kh_each_key)
elif [ "$reload_failed" -eq 1 ]; then
  # No verification ran (disabled) — the reload status is all we have.
  warn "verify disabled; treating the nonzero sysctl --system as a failure"
  verify_failed=1
fi

audit_log kh.apply.done "verify_failed=$verify_failed"

cat <<EOF

[kernel-hardening] applied.
  drop-in : $dropin
  keys    : $(kh_each_key | grep -c .) KSPP sysctls
  source  : https://kspp.github.io/Recommended_Settings

Check status any time:  onionarmor audit  --module kernel-hardening
Undo the hardening:     onionarmor revert --module kernel-hardening
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
