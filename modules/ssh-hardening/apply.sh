#!/usr/bin/env bash
# MODULE: ssh-hardening — Mozilla OpenSSH "modern" sshd_config.d drop-in (no root/password login, modern KEX/ciphers/MACs), weak host-key cleanup, 5-min SSH safety latch.
#
# apply.sh — write the hardening drop-in, validate with `sshd -t`, schedule a
# 5-minute auto-restore latch, THEN reload sshd. Weak DSA/ECDSA host keys are
# removed and a sub-4096-bit RSA host key is regrown. Idempotent; --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ssh_parse_flags "$@"

dropin=$(ssh_dropin_path)
bak=$(ssh_backup_path)
latch_state=$(ssh_latch_state_path)
rendered=$(ssh_render_dropin)
allow_set=$(ssh_allow_user_set)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered drop-in, change nothing.
# ---------------------------------------------------------------------------
if [ "$SSH_DRY_RUN" -eq 1 ]; then
  info "dry-run: ssh-hardening (no host changes)"
  cat <<EOF

PLAN
  drop-in        -> $dropin
  AllowUsers     -> ${allow_set:-<none detected — AllowUsers omitted to avoid lockout>}
  host keys      -> $([ "$SSH_HOST_KEYS" -eq 1 ] && echo "remove DSA/ECDSA; regrow RSA if < $ONIONARMOR_SSH_RSA_MIN_BITS-bit" || echo "untouched (--no-host-keys)")
  safety latch   -> $([ "$SSH_SAFETY_LATCH" -eq 1 ] && echo "at now + $SSH_LATCH_MIN min (auto-restore prior config + reload $ONIONARMOR_SSH_UNIT)" || echo "DISABLED (--no-safety-latch)")

--- rendered drop-in ($dropin) ---
$rendered
EOF
  if [ -z "$allow_set" ]; then
    printf '\nWARNING: no logged-in / configured users detected — AllowUsers will be OMITTED.\n'
    printf '  Pass --allow-user <name> to scope SSH to specific accounts.\n'
  fi
  exit 0
fi

audit_log ssh.apply.start "latch=$SSH_SAFETY_LATCH host_keys=$SSH_HOST_KEYS allow=${allow_set:-none}"
mkdir -p "$ONIONARMOR_SSH_STATE_DIR" || die "cannot create state dir $ONIONARMOR_SSH_STATE_DIR"
mkdir -p "$ONIONARMOR_SSH_CONFD_DIR" || die "cannot create $ONIONARMOR_SSH_CONFD_DIR"

# ---------------------------------------------------------------------------
# Idempotency: drop-in already byte-matches AND no latch needs reconciling AND
# host keys already clean -> nothing to do.
# ---------------------------------------------------------------------------
if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$rendered" ]; then
  pending=$(ssh_latch_pending)
  weak=$(ssh_weak_hostkeys)
  rsa_bits=$(ssh_rsa_bits)
  rsa_small=0
  if [ "$SSH_HOST_KEYS" -eq 1 ] && [ -n "$rsa_bits" ] && [ "$rsa_bits" -lt "$ONIONARMOR_SSH_RSA_MIN_BITS" ]; then rsa_small=1; fi
  host_keys_clean=1
  if [ "$SSH_HOST_KEYS" -eq 1 ] && { [ -n "$weak" ] || [ "$rsa_small" -eq 1 ]; }; then host_keys_clean=0; fi
  if [ "$host_keys_clean" -eq 1 ] && { [ "$SSH_SAFETY_LATCH" -eq 1 ] || [ -z "$pending" ]; }; then
    info "drop-in already current and host keys clean — nothing to do"
    printf '\n[ssh-hardening] already applied (no changes).\n'
    if [ -n "$pending" ]; then
      printf '  NOTE: a safety latch is still pending (at job %s). Cancel it once your session is confirmed: atrm %s\n' "$pending" "$pending"
    fi
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# 1. Back up the prior drop-in (so the latch can restore it). If none existed,
#    we leave no .bak — the latch then removes our drop-in instead.
# ---------------------------------------------------------------------------
if [ -f "$dropin" ]; then
  cp -p "$dropin" "$bak" || die "cannot back up existing drop-in to $bak"
  audit_log ssh.apply.backup "saved=$bak"
else
  rm -f "$bak" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Write the new drop-in, then validate the whole sshd config with `sshd -t`.
#    On failure, restore the prior state and abort WITHOUT reloading.
# ---------------------------------------------------------------------------
tmp="$dropin.tmp.$$"
printf '%s\n' "$rendered" > "$tmp" || { rm -f "$tmp"; die "cannot write $tmp"; }
mv "$tmp" "$dropin" || { rm -f "$tmp"; die "cannot install drop-in $dropin"; }

if ! test_out=$(ssh_config_test); then
  warn "sshd -t rejected the hardened config — restoring prior state, NOT reloading:"
  printf '%s\n' "$test_out" >&2
  if [ -f "$bak" ]; then cp -p "$bak" "$dropin"; else rm -f "$dropin"; fi
  audit_fail_die ssh.apply.fail "stage=sshd-t" "hardened config failed sshd -t (prior config restored)"
fi
audit_log ssh.apply.dropin "wrote=$dropin"

if [ -z "$allow_set" ]; then
  warn "no logged-in / configured users detected — AllowUsers OMITTED (pass --allow-user to scope logins)"
fi

# ---------------------------------------------------------------------------
# 3. Host-key surgery (optional): remove weak DSA/ECDSA keys, regrow small RSA.
#    Backups of removed/old keys go to the state dir so revert can restore them.
# ---------------------------------------------------------------------------
if [ "$SSH_HOST_KEYS" -eq 1 ]; then
  keybak="$ONIONARMOR_SSH_STATE_DIR/hostkeys.bak"
  mkdir -p "$keybak" || warn "cannot create host-key backup dir $keybak"
  while IFS= read -r wk; do
    [ -n "$wk" ] || continue
    if cp -p "$wk" "$keybak/" 2>/dev/null && rm -f "$wk"; then
      info "removed weak host key: $wk"
      audit_log ssh.apply.hostkey "removed=$wk"
    else
      warn "could not remove weak host key: $wk"
    fi
  done <<EOF
$(ssh_weak_hostkeys)
EOF

  rsa_bits=$(ssh_rsa_bits)
  if [ -n "$rsa_bits" ] && [ "$rsa_bits" -lt "$ONIONARMOR_SSH_RSA_MIN_BITS" ]; then
    info "RSA host key is $rsa_bits-bit (< $ONIONARMOR_SSH_RSA_MIN_BITS) — regenerating"
    rsa_key="$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_rsa_key"
    cp -p "$rsa_key" "$keybak/" 2>/dev/null || true
    cp -p "$rsa_key.pub" "$keybak/" 2>/dev/null || true
    rm -f "$rsa_key" "$rsa_key.pub"
    if "$ONIONARMOR_SSH_KEYGEN" -q -t rsa -b "$ONIONARMOR_SSH_RSA_MIN_BITS" -N '' -f "$rsa_key" 2>/dev/null; then
      audit_log ssh.apply.hostkey "regen=rsa bits=$ONIONARMOR_SSH_RSA_MIN_BITS"
      info "regenerated RSA host key at $ONIONARMOR_SSH_RSA_MIN_BITS-bit"
    else
      warn "ssh-keygen failed to regrow RSA host key — restoring the old one"
      cp -p "$keybak/ssh_host_rsa_key" "$rsa_key" 2>/dev/null || true
      cp -p "$keybak/ssh_host_rsa_key.pub" "$rsa_key.pub" 2>/dev/null || true
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4. SAFETY LATCH: schedule the auto-restore `at` job BEFORE reloading, so a
#    config the operator's client can't authenticate against cannot strand them.
# ---------------------------------------------------------------------------
latch_job=""
if [ "$SSH_SAFETY_LATCH" -eq 1 ]; then
  if ! command -v "$ONIONARMOR_SSH_AT" >/dev/null 2>&1; then
    die "ssh-hardening: 'at' not found — needed for the SSH safety latch. Install it (apt install at) or re-run with --no-safety-latch (console access required)."
  fi
  old_job=$(ssh_latch_pending)
  if [ -n "$old_job" ]; then
    "$ONIONARMOR_SSH_ATRM" "$old_job" >/dev/null 2>&1 \
      && info "cancelled previous safety-latch at job $old_job" \
      || warn "could not cancel previous safety-latch at job $old_job"
  fi
  latch_out=$(ssh_latch_command | "$ONIONARMOR_SSH_AT" now + "$SSH_LATCH_MIN" minutes 2>&1 || true)
  latch_job=$(printf '%s\n' "$latch_out" | grep -oE 'job[[:space:]]+[0-9]+' | awk '{print $2}' | head -1)
  if [ -z "$latch_job" ]; then
    # Could not schedule the latch: restore prior config and refuse to reload.
    if [ -f "$bak" ]; then cp -p "$bak" "$dropin"; else rm -f "$dropin"; fi
    audit_fail_die ssh.apply.fail "stage=latch-parse output=$latch_out" "could not schedule the safety latch — restored prior config, NOT reloading (use --no-safety-latch with console access to skip)"
  fi
else
  old_job=$(ssh_latch_pending)
  if [ -n "$old_job" ]; then
    "$ONIONARMOR_SSH_ATRM" "$old_job" >/dev/null 2>&1 \
      && { info "cancelled previous safety-latch at job $old_job (--no-safety-latch)"; rm -f "$latch_state" 2>/dev/null || true; } \
      || warn "could not cancel previous safety-latch at job $old_job"
  fi
  warn "--no-safety-latch: no auto-restore scheduled — make sure you have console access"
fi

# ---------------------------------------------------------------------------
# 5. Reload sshd (config already validated). Active connections are NOT dropped
#    by a reload; the latch protects the NEXT login attempt.
# ---------------------------------------------------------------------------
reload_failed=0
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — drop-in written but sshd not reloaded"
else
  if "$ONIONARMOR_SSH_SYSTEMCTL" reload "$ONIONARMOR_SSH_UNIT" >/dev/null 2>&1; then
    info "reloaded $ONIONARMOR_SSH_UNIT"
  else
    reload_failed=1
    warn "systemctl reload $ONIONARMOR_SSH_UNIT failed — config is staged but not live"
  fi
fi

# Record the latch job only after the reload attempt, so revert/audit can see it.
if [ -n "$latch_job" ]; then
  if printf '%s\n' "$latch_job" > "$latch_state" 2>/dev/null; then
    audit_log ssh.apply.latch "job=$latch_job minutes=$SSH_LATCH_MIN"
  else
    "$ONIONARMOR_SSH_ATRM" "$latch_job" >/dev/null 2>&1 \
      && warn "could not record latch state — cancelled job $latch_job to avoid an untracked auto-restore" \
      || warn "could not record latch state AND failed to cancel job $latch_job — run: atrm $latch_job"
    latch_job=""
  fi
fi

# ---------------------------------------------------------------------------
# 6. Verify (default on): the drop-in is present and sshd -t still passes.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$SSH_VERIFY" -eq 1 ]; then
  if [ -f "$dropin" ] && ssh_config_test >/dev/null 2>&1; then
    info "verify: drop-in present and sshd -t passes"
  else
    warn "verify: drop-in missing or sshd -t failing after apply"; verify_failed=1
  fi
fi

audit_log ssh.apply.done "reload_failed=$reload_failed verify_failed=$verify_failed latch_job=${latch_job:-none}"

cat <<EOF

[ssh-hardening] applied.
  drop-in    : $dropin
  AllowUsers : ${allow_set:-<omitted>}
  host keys  : $([ "$SSH_HOST_KEYS" -eq 1 ] && echo "weak removed; RSA >= $ONIONARMOR_SSH_RSA_MIN_BITS-bit" || echo "untouched")
EOF
if [ -n "$latch_job" ]; then
  cat <<EOF

  *** SSH SAFETY LATCH ACTIVE — the prior config auto-restores in $SSH_LATCH_MIN minutes. ***
  Open a NEW SSH session to confirm you can still log in, THEN cancel the latch:

      atrm $latch_job

  If you do NOT cancel it, onionarmor will restore the previous SSH config
  automatically (so a bad key/AllowUsers cannot lock you out).
EOF
fi
cat <<EOF

Check status any time:  onionarmor audit  --module ssh-hardening
Undo the hardening:     onionarmor revert --module ssh-hardening
EOF

if [ "$verify_failed" -ne 0 ] || [ "$reload_failed" -ne 0 ]; then
  warn "apply finished with problems (see above)"; exit 2
fi
