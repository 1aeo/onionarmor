#!/usr/bin/env bash
# MODULE: kernel hardening — KSPP recommended sysctls (dmesg/kptr/bpf/perf/ASLR/ptrace/kexec + net anti-spoofing). Very low risk; recommended-on.
#
# apply.sh — write the KSPP sysctl set to 99-onionarmor-kernel-hardening.conf and
# load it with `sysctl --system`. Idempotent; supports --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

kh_parse_flags "$@"

dropin=$(kh_dropin_path)
rendered=$(kh_render_dropin)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-in + before/after per key, change
# nothing.
# ---------------------------------------------------------------------------
if [ "$KH_DRY_RUN" -eq 1 ]; then
  info "dry-run: kernel-hardening (no host changes)"
  cat <<EOF

PLAN
  drop-in           -> $dropin
  planned command   -> $ONIONARMOR_SYSCTL_CMD --system

SYSCTL (before -> target)
EOF
  printf '%s\n' "$KH_TARGETS" | while read -r key val; do
    [ -n "$key" ] || continue
    before=$(kh_sysctl_runtime "$key" | tr '\t' ' ')
    printf '  %-42s %-14s -> %s\n' "$key" "${before:-<unset>}" "$val"
  done
  printf '\n--- drop-in (%s) ---\n%s\n' "$dropin" "$rendered"
  exit 0
fi

audit_log kh.apply.start "dropin=$dropin"

# ---------------------------------------------------------------------------
# 1. Write the managed drop-in (idempotent: skip if byte-identical). Back up the
#    previous managed drop-in first so revert can restore it.
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_SYSCTL_DIR" || die "cannot create $ONIONARMOR_SYSCTL_DIR"
if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$rendered" ]; then
  info "drop-in already current: $dropin"
  wrote=0
else
  if [ -f "$dropin" ]; then
    mkdir -p "$ONIONARMOR_KH_STATE_DIR" || die "cannot create $ONIONARMOR_KH_STATE_DIR"
    cp -p "$dropin" "$(kh_backup_path)" \
      || audit_fail_die kh.apply.fail "stage=backup" "failed to back up $dropin"
  fi
  tmp="$dropin.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$dropin" || { rm -f "$tmp"; die "cannot move $tmp -> $dropin"; }
  audit_log kh.apply.dropin "wrote=$dropin"
  info "wrote drop-in: $dropin"
  wrote=1
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
  warn "$ONIONARMOR_SYSCTL_CMD --system returned nonzero; drop-in written but some keys may not be live"
  reload_failed=1
fi

# ---------------------------------------------------------------------------
# 3. Verify (default on): every managed key's live value matches the target.
#    Verification is AUTHORITATIVE: a noisy `sysctl --system` (e.g. an unrelated
#    drop-in failed) does not fail the apply if our keys all match. Only when
#    verification is skipped does the reload exit code become the signal.
# ---------------------------------------------------------------------------
verify_failed=0
mismatches=""
if [ "$KH_VERIFY" -eq 1 ] && [ "${ONIONARMOR_SKIP_RELOAD:-}" != "yes" ]; then
  while read -r key val; do
    [ -n "$key" ] || continue
    live=$(kh_sysctl_runtime "$key")
    if [ "$(kh_norm "$live")" = "$(kh_norm "$val")" ]; then
      continue
    fi
    # An unreadable key (module/sysctl absent on this kernel) is a warning, not a
    # hard failure — some keys (e.g. kexec_load_disabled) may not exist on older
    # kernels. A readable-but-wrong value is a real verify failure.
    if [ -z "$live" ]; then
      warn "verify: $key is not readable on this kernel (skipping)"
    else
      warn "verify: $key is '$live', expected '$val'"
      mismatches="$mismatches $key"
      verify_failed=1
    fi
  done <<EOF
$KH_TARGETS
EOF
  [ "$verify_failed" -eq 0 ] && info "verify: all readable KSPP keys match the drop-in"
elif [ "$reload_failed" -eq 1 ]; then
  warn "verify skipped; treating the nonzero sysctl --system as a failure"
  verify_failed=1
fi

audit_log kh.apply.done "wrote=$wrote verify_failed=$verify_failed mismatches=${mismatches:-none}"

cat <<EOF

[kernel-hardening] applied.
  drop-in : $dropin
  sysctls : $(printf '%s\n' "$KH_TARGETS" | grep -c .) KSPP keys

Check status any time:  onionarmor audit  --module kernel-hardening
Undo the posture:       onionarmor revert --module kernel-hardening
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
