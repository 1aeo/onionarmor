#!/usr/bin/env bash
# MODULE: account-hygiene — lock/de-sudo leftover cloud-init users, enforce a sudo allowlist, refuse shared UID-0 accounts, flag blanket NOPASSWD sudoers; 5-min sudo safety latch.
#
# apply.sh — snapshot the current sudo-group membership, schedule a 5-minute
# auto-restore latch, then remove sudo from cloud-init + non-allowlisted users
# and lock the cloud-init accounts. Shared UID-0 accounts and blanket NOPASSWD
# sudoers are reported (never auto-deleted/edited). Idempotent; --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

acct_parse_flags "$@"

snapshot=$(acct_snapshot_path)
restore=$(acct_restore_path)
latch_state=$(acct_latch_state_path)

# ---------------------------------------------------------------------------
# Build the plan (pure reads).
# ---------------------------------------------------------------------------
cloudinit=$(acct_cloudinit_sudo_users | sed '/^$/d' | sort -u || true)

# Removals: "user group" pairs to strip. Cloud-init users lose sudo from every
# group they're in; allowlist violators lose the offending group.
removals=$(
  {
    for u in $cloudinit; do
      for g in $ONIONARMOR_ACCT_SUDO_GROUPS; do
        acct_user_in_group "$u" "$g" && printf '%s %s\n' "$u" "$g"
      done
    done
    [ "$ACCT_ENFORCE_ALLOWLIST" -eq 1 ] && acct_allowlist_violations
  } | sed '/^$/d' | sort -u || true
)

# Locks: cloud-init users currently unlocked.
locks=$(
  for u in $cloudinit; do
    acct_user_locked "$u" || printf '%s\n' "$u"
  done | sed '/^$/d' | sort -u || true
)

uid0_extra=$(acct_uid0_accounts | grep -vx root || true)
nopasswd=$(acct_nopasswd_all_files || true)

n_removals=$(printf '%s' "$removals" | grep -c . || true)
n_locks=$(printf '%s' "$locks" | grep -c . || true)

# ---------------------------------------------------------------------------
# Dry run.
# ---------------------------------------------------------------------------
if [ "$ACCT_DRY_RUN" -eq 1 ]; then
  info "dry-run: account-hygiene (no host changes)"
  cat <<EOF

PLAN
  cloud-init sudo users -> ${cloudinit:-<none>}
  sudo removals         -> $n_removals membership(s)$([ -n "$removals" ] && printf ':\n%s' "$(printf '%s\n' "$removals" | sed 's/^/      /')")
  lock accounts         -> ${locks:-<none>}
  purge (userdel -r)    -> $([ "$ACCT_PURGE" -eq 1 ] && echo "${cloudinit:-<none>}" || echo "DISABLED (default; pass --purge)")
  safety latch          -> $([ "$ACCT_SAFETY_LATCH" -eq 1 ] && echo "at now + $ACCT_LATCH_MIN min (restore prior membership)" || echo "DISABLED")
EOF
  [ -n "$uid0_extra" ] && printf '\n  RED: shared UID-0 account(s) other than root: %s (NOT auto-removed)\n' "$(printf '%s' "$uid0_extra" | tr '\n' ' ')"
  [ -n "$nopasswd" ] && printf '\n  RED: blanket NOPASSWD: ALL in: %s (scope these tightly)\n' "$(printf '%s' "$nopasswd" | tr '\n' ' ')"
  exit 0
fi

# ---------------------------------------------------------------------------
# Nothing to change?
# ---------------------------------------------------------------------------
if [ "$n_removals" -eq 0 ] && [ "$n_locks" -eq 0 ] && { [ "$ACCT_PURGE" -eq 0 ] || [ -z "$cloudinit" ]; }; then
  info "account-hygiene: no leftover sudo/cloud-init accounts to clean"
  [ -n "$uid0_extra" ] && warn "shared UID-0 account(s) other than root present: $(printf '%s' "$uid0_extra" | tr '\n' ' ') — remove manually"
  [ -n "$nopasswd" ] && warn "blanket NOPASSWD: ALL present in: $(printf '%s' "$nopasswd" | tr '\n' ' ') — scope tightly"
  printf '\n[account-hygiene] already clean (no changes).\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# Confirm (default-off module: removing sudo is destructive).
# ---------------------------------------------------------------------------
if [ "$ACCT_ASSUME_YES" -eq 0 ]; then
  oa_confirm "Remove sudo from $n_removals membership(s) and lock $n_locks account(s)?" \
    || die "account-hygiene: cancelled by operator"
fi

audit_log acct.apply.start "removals=$n_removals locks=$n_locks purge=$ACCT_PURGE latch=$ACCT_SAFETY_LATCH"
mkdir -p "$ONIONARMOR_ACCT_STATE_DIR" || die "cannot create state dir $ONIONARMOR_ACCT_STATE_DIR"

# ---------------------------------------------------------------------------
# 1. Snapshot + render the restore script (re-add removed memberships, unlock
#    re-locked accounts) — used by both the latch and `revert`.
# ---------------------------------------------------------------------------
{
  printf '#!/bin/sh\n'
  printf '# Managed by onionarmor (module: account-hygiene) — auto-restore prior accounts.\n'
  while IFS=' ' read -r u g; do
    [ -n "$u" ] || continue
    printf "'%s' -a '%s' '%s' >/dev/null 2>&1 || true\n" "$ONIONARMOR_ACCT_GPASSWD" "$u" "$g"
  done <<EOF
$removals
EOF
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    printf "'%s' -U '%s' >/dev/null 2>&1 || true\n" "$ONIONARMOR_ACCT_USERMOD" "$u"
  done <<EOF
$locks
EOF
} > "$restore" || die "cannot write restore script $restore"
chmod +x "$restore" 2>/dev/null || true
printf '%s\n' "$removals" > "$snapshot" 2>/dev/null || warn "could not write snapshot $snapshot"
audit_log acct.apply.snapshot "restore=$restore"

# ---------------------------------------------------------------------------
# 2. SAFETY LATCH: schedule the auto-restore BEFORE removing anything.
# ---------------------------------------------------------------------------
latch_job=""
if [ "$ACCT_SAFETY_LATCH" -eq 1 ]; then
  if ! command -v "$ONIONARMOR_ACCT_AT" >/dev/null 2>&1; then
    die "account-hygiene: 'at' not found — needed for the sudo safety latch. Install it (apt install at) or re-run with --no-safety-latch (console access required)."
  fi
  old_job=$(acct_latch_pending)
  if [ -n "$old_job" ]; then
    "$ONIONARMOR_ACCT_ATRM" "$old_job" >/dev/null 2>&1 \
      && info "cancelled previous safety-latch at job $old_job" \
      || warn "could not cancel previous safety-latch at job $old_job"
  fi
  latch_out=$(printf "sh '%s'\n" "$restore" | "$ONIONARMOR_ACCT_AT" now + "$ACCT_LATCH_MIN" minutes 2>&1 || true)
  latch_job=$(printf '%s\n' "$latch_out" | grep -oE 'job[[:space:]]+[0-9]+' | awk '{print $2}' | head -1)
  if [ -z "$latch_job" ]; then
    audit_fail_die acct.apply.fail "stage=latch-parse output=$latch_out" "could not schedule the safety latch — refusing to remove sudo (use --no-safety-latch with console access to skip)"
  fi
  if printf '%s\n' "$latch_job" > "$latch_state" 2>/dev/null; then
    audit_log acct.apply.latch "job=$latch_job minutes=$ACCT_LATCH_MIN"
  else
    "$ONIONARMOR_ACCT_ATRM" "$latch_job" >/dev/null 2>&1 || true
    die "could not record latch state — cancelled the job, NOT proceeding"
  fi
else
  old_job=$(acct_latch_pending)
  if [ -n "$old_job" ]; then
    "$ONIONARMOR_ACCT_ATRM" "$old_job" >/dev/null 2>&1 \
      && { info "cancelled previous safety-latch at job $old_job (--no-safety-latch)"; rm -f "$latch_state" 2>/dev/null || true; } \
      || warn "could not cancel previous safety-latch at job $old_job"
  fi
  warn "--no-safety-latch: no auto-restore scheduled — make sure you have console access"
fi

# ---------------------------------------------------------------------------
# 3. Apply: strip sudo memberships, lock cloud-init users, optional purge.
# ---------------------------------------------------------------------------
while IFS=' ' read -r u g; do
  [ -n "$u" ] || continue
  if "$ONIONARMOR_ACCT_GPASSWD" -d "$u" "$g" >/dev/null 2>&1; then
    info "removed $u from group $g"
    audit_log acct.apply.desudo "user=$u group=$g"
  else
    warn "could not remove $u from group $g"
  fi
done <<EOF
$removals
EOF

while IFS= read -r u; do
  [ -n "$u" ] || continue
  if "$ONIONARMOR_ACCT_USERMOD" -L "$u" >/dev/null 2>&1; then
    info "locked account $u"
    audit_log acct.apply.lock "user=$u"
  else
    warn "could not lock account $u"
  fi
done <<EOF
$locks
EOF

if [ "$ACCT_PURGE" -eq 1 ] && [ -n "$cloudinit" ]; then
  warn "--purge: userdel -r is NOT reversible by the latch (group restore only)"
  for u in $cloudinit; do
    if "$ONIONARMOR_ACCT_USERDEL" -r "$u" >/dev/null 2>&1; then
      info "deleted user $u (userdel -r)"
      audit_log acct.apply.userdel "user=$u"
    else
      warn "could not userdel $u"
    fi
  done
fi

# Report (do not auto-fix) shared UID-0 + blanket NOPASSWD.
[ -n "$uid0_extra" ] && warn "shared UID-0 account(s) other than root: $(printf '%s' "$uid0_extra" | tr '\n' ' ') — remove manually (NOT auto-deleted)"
[ -n "$nopasswd" ] && warn "blanket NOPASSWD: ALL in: $(printf '%s' "$nopasswd" | tr '\n' ' ') — scope tightly (NOT auto-edited)"

# ---------------------------------------------------------------------------
# 4. Verify: removals took effect.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$ACCT_VERIFY" -eq 1 ]; then
  while IFS=' ' read -r u g; do
    [ -n "$u" ] || continue
    if acct_user_in_group "$u" "$g"; then
      warn "verify: $u still in group $g"; verify_failed=1
    fi
  done <<EOF
$removals
EOF
  [ "$verify_failed" -eq 0 ] && info "verify: sudo removals took effect"
fi

audit_log acct.apply.done "verify_failed=$verify_failed latch_job=${latch_job:-none}"

cat <<EOF

[account-hygiene] applied.
  sudo removed : $n_removals membership(s)
  locked       : ${locks:-<none>}
EOF
if [ -n "$latch_job" ]; then
  cat <<EOF

  *** SUDO SAFETY LATCH ACTIVE — prior group membership auto-restores in $ACCT_LATCH_MIN minutes. ***
  Confirm you still have sudo (e.g. 'sudo -v'), THEN cancel the latch:

      atrm $latch_job

  If you do NOT cancel it, onionarmor restores the previous sudo membership.
EOF
fi
cat <<EOF

Check status any time:  onionarmor audit  --module account-hygiene
Undo this change:       onionarmor revert --module account-hygiene
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
