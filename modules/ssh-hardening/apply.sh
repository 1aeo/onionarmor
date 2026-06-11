#!/usr/bin/env bash
# MODULE: ssh hardening — Mozilla-OpenSSH sshd drop-in (no root/password login, modern Kex/Cipher/MAC, no forwarding) + weak host-key pruning; 5-min SSH safety latch. Medium-HIGH risk; recommended-off.
#
# apply.sh — write the Mozilla-OpenSSH hardening drop-in to
# 99-onionarmor-hardening.conf, arm a 5-minute auto-revert latch, validate with
# `sshd -t`, reload sshd, then prune weak host keys. Idempotent; --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sshd_parse_flags "$@"

dropin=$(sshd_dropin_path)
backup=$(sshd_backup_path)
preexist_marker=$(sshd_preexist_path)
restore=$(sshd_restore_path)
rendered=$(sshd_render_dropin)

# ---------------------------------------------------------------------------
# --cancel-safety-latch: disarm a pending auto-revert and exit. Independent of
# any config change so the operator can run it the moment they've confirmed they
# can still SSH in.
# ---------------------------------------------------------------------------
if [ "$SSHD_CANCEL_LATCH" -eq 1 ]; then
  if oa_latch_cancel "$SSHD_LATCH_MODULE"; then
    info "ssh-hardening: pending safety latch cancelled"
  else
    info "ssh-hardening: no safety latch was armed (nothing to cancel)"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-in + the planned validation + latch
# plan, change nothing.
# ---------------------------------------------------------------------------
if [ "$SSHD_DRY_RUN" -eq 1 ]; then
  info "dry-run: ssh-hardening (no host changes)"
  cat <<EOF

PLAN
  drop-in           -> $dropin
  validate          -> $ONIONARMOR_SSHD_SSHD_CMD -t
  reload            -> $ONIONARMOR_SSHD_SYSTEMCTL reload $ONIONARMOR_SSHD_UNIT
  safety latch      -> $([ "$SSHD_SAFETY_LATCH" -eq 1 ] && echo "at now + $ONIONARMOR_LATCH_TIMEOUT_MIN min (auto-revert: restore prior sshd config + reload)" || echo "DISABLED (--no-safety-latch; console access required)")
  host keys         -> remove ssh_host_dsa_key* + ssh_host_ecdsa_key*; regen RSA if < ${ONIONARMOR_SSHD_RSA_MIN_BITS} bits ($ONIONARMOR_SSHD_HOSTKEY_DIR)

--- drop-in ($dropin) ---
$rendered
EOF
  exit 0
fi

audit_log sshd.apply.start "dropin=$dropin latch=$SSHD_SAFETY_LATCH"

# ---------------------------------------------------------------------------
# Idempotency: if the drop-in is already byte-identical AND (when requested) a
# latch is already armed, there is nothing to do — and we must NOT stack a fresh
# latch. We still run host-key pruning (cheap, best-effort, self-idempotent).
# ---------------------------------------------------------------------------
dropin_current=0
if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$rendered" ]; then
  dropin_current=1
fi

# ---------------------------------------------------------------------------
# 1. Back up the pre-apply state so the latch's restore script can put it back.
#    Record whether the drop-in pre-existed (so restore removes vs. restores).
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_SSHD_STATE_DIR" || die "cannot create state dir $ONIONARMOR_SSHD_STATE_DIR"
mkdir -p "$ONIONARMOR_SSHD_DROPIN_DIR" || die "cannot create drop-in dir $ONIONARMOR_SSHD_DROPIN_DIR"

if [ -f "$dropin" ]; then
  cp -p "$dropin" "$backup" \
    || audit_fail_die sshd.apply.fail "stage=backup" "failed to back up $dropin -> $backup"
  printf '1\n' > "$preexist_marker"
else
  rm -f "$backup" 2>/dev/null || true
  printf '0\n' > "$preexist_marker"
fi
preexisted=$(cat "$preexist_marker")

# ---------------------------------------------------------------------------
# 2. Render the restore script + ARM the latch BEFORE touching the live config,
#    so a reload that locks us out always has a scheduled undo. A failure to arm
#    is fatal (a risky change with no auto-revert is exactly what the latch
#    exists to prevent) unless --no-safety-latch was passed.
# ---------------------------------------------------------------------------
latch_armed=0
if [ "$SSHD_SAFETY_LATCH" -eq 1 ]; then
  if oa_latch_is_armed "$SSHD_LATCH_MODULE" && [ "$dropin_current" -eq 1 ]; then
    info "drop-in already current and a safety latch is already armed — not stacking a new latch"
  else
    # Cancel any stale latch first so we never stack two auto-reverts.
    if oa_latch_is_armed "$SSHD_LATCH_MODULE"; then
      oa_latch_cancel "$SSHD_LATCH_MODULE" >/dev/null 2>&1 || true
    fi
    sshd_render_restore "$dropin" "$backup" "$preexisted" \
      "$ONIONARMOR_SSHD_SSHD_CMD" "$ONIONARMOR_SSHD_SYSTEMCTL" "$ONIONARMOR_SSHD_UNIT" > "$restore" \
      || die "cannot render restore script -> $restore"
    chmod +x "$restore" 2>/dev/null || true
    if ! oa_latch_arm "$SSHD_LATCH_MODULE" "$restore" "$ONIONARMOR_LATCH_TIMEOUT_MIN"; then
      # Could not schedule — abort WITHOUT touching the live config. Roll back the
      # backup/marker bookkeeping so a retry starts clean.
      [ "$preexisted" = "0" ] && rm -f "$preexist_marker" 2>/dev/null || true
      audit_fail_die sshd.apply.fail "stage=latch-arm" "could not arm the SSH safety latch (is atd installed and running? 'apt install at && systemctl enable --now atd') — re-run with --no-safety-latch only if you have console access"
    fi
    latch_armed=1
  fi
else
  warn "--no-safety-latch: no auto-revert scheduled — a wrong config will lock you out. Make sure you have console access."
fi

# ---------------------------------------------------------------------------
# 3. Write the drop-in (idempotent via oa_write_if_changed).
# ---------------------------------------------------------------------------
if oa_write_if_changed "$dropin" "$rendered"; then
  audit_log sshd.apply.dropin "wrote=$dropin"
  info "wrote drop-in: $dropin"
  wrote=1
else
  info "drop-in already current: $dropin"
  wrote=0
fi

# ---------------------------------------------------------------------------
# 4. VALIDATE the resulting config. NEVER reload a config that fails `sshd -t`:
#    remove our drop-in (restore the backup if one pre-existed), cancel the
#    latch, and die.
# ---------------------------------------------------------------------------
if ! "$ONIONARMOR_SSHD_SSHD_CMD" -t >/dev/null 2>&1; then
  if [ "$preexisted" = "1" ] && [ -f "$backup" ]; then
    cp -p "$backup" "$dropin" 2>/dev/null || rm -f "$dropin"
  else
    rm -f "$dropin"
  fi
  [ "$latch_armed" -eq 1 ] && oa_latch_cancel "$SSHD_LATCH_MODULE" >/dev/null 2>&1
  audit_fail_die sshd.apply.fail "stage=validate" "'$ONIONARMOR_SSHD_SSHD_CMD -t' rejected the hardened config — drop-in removed, latch cancelled, sshd NOT reloaded"
fi
info "validated: $ONIONARMOR_SSHD_SSHD_CMD -t passed"

# ---------------------------------------------------------------------------
# 5. Reload sshd so the new config takes effect on the next connection. (Active
#    sessions are unaffected — hence the latch protects the NEXT login.)
# ---------------------------------------------------------------------------
reload_failed=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping sshd reload"
elif "$ONIONARMOR_SSHD_SYSTEMCTL" reload "$ONIONARMOR_SSHD_UNIT" >/dev/null 2>&1; then
  info "reloaded sshd ($ONIONARMOR_SSHD_SYSTEMCTL reload $ONIONARMOR_SSHD_UNIT)"
else
  warn "$ONIONARMOR_SSHD_SYSTEMCTL reload $ONIONARMOR_SSHD_UNIT returned nonzero — config written but sshd may not have picked it up"
  reload_failed=1
fi

# ---------------------------------------------------------------------------
# 6. Host keys (best-effort, AFTER the config is safely applied — warn, never
#    die): prune weak DSA + ECDSA host keys, regenerate a sub-min-bit RSA key.
# ---------------------------------------------------------------------------
removed_keys=""
for stem in ssh_host_dsa_key ssh_host_ecdsa_key; do
  for f in "$ONIONARMOR_SSHD_HOSTKEY_DIR/$stem" "$ONIONARMOR_SSHD_HOSTKEY_DIR/$stem.pub"; do
    if [ -e "$f" ]; then
      if rm -f "$f"; then
        removed_keys="$removed_keys $f"
      else
        warn "could not remove weak host key: $f"
      fi
    fi
  done
done
[ -n "$removed_keys" ] && { audit_log sshd.apply.hostkeys "removed=$removed_keys"; info "removed weak host keys:$removed_keys"; }

rsa_key="$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_rsa_key"
rsa_regenerated=0
if [ -f "$rsa_key" ]; then
  bits=$(sshd_rsa_bits "$rsa_key")
  case "$bits" in
    (*[!0-9]*|"")
      warn "could not determine RSA host-key strength for $rsa_key — leaving as-is" ;;
    (*)
      if [ "$bits" -lt "$ONIONARMOR_SSHD_RSA_MIN_BITS" ]; then
        info "RSA host key is $bits bits (< $ONIONARMOR_SSHD_RSA_MIN_BITS) — regenerating at $ONIONARMOR_SSHD_RSA_MIN_BITS"
        rm -f "$rsa_key" "$rsa_key.pub" 2>/dev/null || true
        if "$ONIONARMOR_SSHD_KEYGEN_CMD" -q -t rsa -b "$ONIONARMOR_SSHD_RSA_MIN_BITS" -N '' -f "$rsa_key" >/dev/null 2>&1; then
          rsa_regenerated=1
          audit_log sshd.apply.hostkeys "regenerated=$rsa_key bits=$ONIONARMOR_SSHD_RSA_MIN_BITS"
          info "regenerated RSA host key at $ONIONARMOR_SSHD_RSA_MIN_BITS bits: $rsa_key"
        else
          warn "ssh-keygen failed to regenerate $rsa_key — leaving the weak key in place"
        fi
      fi ;;
  esac
fi

audit_log sshd.apply.done "wrote=$wrote latch_armed=$latch_armed reload_failed=$reload_failed rsa_regenerated=$rsa_regenerated"

# ---------------------------------------------------------------------------
# 7. Summary. When the latch is armed, prominently print BOTH cancel commands and
#    tell the operator to confirm access THEN cancel within the window.
# ---------------------------------------------------------------------------
cat <<EOF

[ssh-hardening] applied.
  drop-in : $dropin
  posture : Mozilla OpenSSH guidelines (no root/password login, modern algos, no forwarding)
EOF
if [ "$latch_armed" -eq 1 ]; then
  cat <<EOF

  *** SSH SAFETY LATCH ARMED — sshd config auto-reverts in $ONIONARMOR_LATCH_TIMEOUT_MIN minutes. ***
  Open a NEW ssh session now and confirm you can still log in. THEN cancel within
  $ONIONARMOR_LATCH_TIMEOUT_MIN minutes, or the host auto-reverts to its prior sshd config:

      atrm $OA_LATCH_JOBID
      # (or, generally:)  $(oa_latch_cancel_cmd "$SSHD_LATCH_MODULE")
  If you do NOT cancel and you cannot log in, the latch restores the old config for you.
EOF
fi
cat <<EOF

Check status any time:  onionarmor audit  --module ssh-hardening
Undo the posture:       onionarmor revert --module ssh-hardening
EOF

[ "$reload_failed" -eq 0 ] || { warn "apply finished but the sshd reload reported problems above"; exit 2; }
