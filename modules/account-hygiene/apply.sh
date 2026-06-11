#!/usr/bin/env bash
# MODULE: account hygiene — lock + de-sudo cloud-init default accounts, enforce an operator sudo allowlist, assert only root is UID 0, flag NOPASSWD:ALL. Medium risk; recommended-off; 5-min safety latch.
#
# apply.sh — tighten local account / sudo posture. Builds a plan of every
# account/group change, snapshots the current state, renders a /bin/sh restore
# script and arms a 5-minute safety latch, THEN mutates. A bare apply (no
# --dry-run, no --confirm) refuses to change anything so it can never silently
# lock the operator out. Idempotent; --dry-run previews.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ah_parse_flags "$@"

# ---------------------------------------------------------------------------
# --cancel-safety-latch: disarm a pending latch and exit (no other work).
# ---------------------------------------------------------------------------
if [ "$AH_CANCEL_LATCH" -eq 1 ]; then
  if oa_latch_cancel "$AH_MODULE"; then
    exit 0
  else
    info "no pending safety latch for $AH_MODULE — nothing to cancel"
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# Build the plan. We compute, against the current account/group state:
#   - cloud_lock   : cloud defaults present + not already locked
#   - cloud_desudo : cloud defaults present + still in the sudo group
#   - strangers    : "<user> <group>" pairs in a priv group but not allowlisted
#   - uid0_extra   : non-root accounts with UID 0 (a hard problem; we never fix)
#   - nopasswd     : sudoers.d files with a blanket NOPASSWD: ALL (we never edit)
# The plan is computed once and reused by dry-run, the snapshot, and the
# mutation loop so they cannot drift.
# ---------------------------------------------------------------------------
allowlist_missing=0
ah_allowlist_exists || allowlist_missing=1

# Cloud-init defaults present on this host.
present_cloud=$(ah_present_cloud_defaults)

# Which present cloud accounts still need locking / de-sudoing.
cloud_lock=""
cloud_desudo=""
if [ -n "$present_cloud" ]; then
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    ah_account_locked "$u" || cloud_lock="$cloud_lock $u"
    if ah_in_group "$u" sudo; then cloud_desudo="$cloud_desudo $u"; fi
  done <<EOF
$present_cloud
EOF
fi

# Strangers: a member of a priv group who is NOT on the allowlist. We never
# touch root (UID 0 is handled separately) and we skip the cloud-default desudo
# already captured above to avoid double-logging the same removal.
strangers=""
if [ "$allowlist_missing" -eq 0 ]; then
  for g in $AH_PRIV_GROUPS; do
    members=$(ah_group_members "$g")
    [ -n "$members" ] || continue
    while IFS= read -r u; do
      [ -n "$u" ] || continue
      [ "$u" = "root" ] && continue
      ah_in_allowlist "$u" && continue
      strangers="$strangers $u:$g"
    done <<EOF
$members
EOF
  done
fi

# Non-root UID-0 accounts (hard problem; reported, never auto-fixed).
uid0_extra=""
while IFS= read -r u; do
  [ -n "$u" ] || continue
  [ "$u" = "root" ] && continue
  uid0_extra="$uid0_extra $u"
done <<EOF
$(ah_uid0_accounts)
EOF

# sudoers.d blanket NOPASSWD: ALL files (reported, never auto-edited).
nopasswd_files=$(ah_nopasswd_all_files)

# ---------------------------------------------------------------------------
# Dry run: print the full plan, change nothing, exit 0.
# ---------------------------------------------------------------------------
if [ "$AH_DRY_RUN" -eq 1 ]; then
  info "dry-run: account-hygiene (no host changes)"
  cat <<EOF

PLAN
  allowlist         -> $ONIONARMOR_AH_ALLOWLIST$([ "$allowlist_missing" -eq 1 ] && echo "  (MISSING — allowlist enforcement SKIPPED)")
  safety latch      -> $([ "$AH_SAFETY_LATCH" -eq 1 ] && echo "at now + $AH_LATCH_MIN min (auto-restore membership/locks)" || echo "DISABLED (--no-safety-latch)")

CLOUD-INIT DEFAULTS
EOF
  if [ -n "$present_cloud" ]; then
    for u in $cloud_lock;   do printf '  lock        -> %s\n' "$u"; done
    for u in $cloud_desudo; do printf '  remove sudo -> %s\n' "$u"; done
    [ -z "$cloud_lock$cloud_desudo" ] && printf '  (all present cloud defaults already locked + out of sudo)\n'
  else
    printf '  (none of %s present)\n' "$ONIONARMOR_AH_CLOUD_DEFAULTS"
  fi

  printf '\nALLOWLIST ENFORCEMENT (sudo/wheel/admin)\n'
  if [ "$allowlist_missing" -eq 1 ]; then
    printf '  SKIPPED — create %s before applying.\n' "$ONIONARMOR_AH_ALLOWLIST"
  elif [ -n "$strangers" ]; then
    for pair in $strangers; do printf '  remove from %-6s -> %s\n' "${pair#*:}" "${pair%%:*}"; done
  else
    printf '  (every sudo/wheel/admin member is allowlisted)\n'
  fi

  printf '\nUID 0 ASSERTION\n'
  if [ -n "$uid0_extra" ]; then
    printf '  PROBLEM: non-root UID-0 account(s):%s (NOT auto-fixed — investigate)\n' "$uid0_extra"
  else
    printf '  (only root has UID 0)\n'
  fi

  printf '\nSUDOERS.D NOPASSWD:ALL\n'
  if [ -n "$nopasswd_files" ]; then
    printf '%s\n' "$nopasswd_files" | while IFS= read -r f; do
      [ -n "$f" ] && printf '  WARN: blanket NOPASSWD:ALL in %s (NOT auto-edited)\n' "$f"
    done
  else
    printf '  (no blanket NOPASSWD:ALL in %s)\n' "$ONIONARMOR_AH_SUDOERS_D"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Not a dry run. The allowlist must exist before we are willing to remove ANY
# priv-group member — otherwise we would have no notion of "who is allowed" and
# could strip every sudoer, locking the operator out.
# ---------------------------------------------------------------------------
if [ "$allowlist_missing" -eq 1 ]; then
  die "account-hygiene: allowlist $ONIONARMOR_AH_ALLOWLIST not found — create it (one operator username per line) before applying, or removing all sudoers could lock you out. (Preview safely with --dry-run.)"
fi

# ---------------------------------------------------------------------------
# Mandatory confirmation: a bare apply (no --dry-run, no --confirm) must NOT
# mutate. Require an explicit --confirm or an interactive yes.
# ---------------------------------------------------------------------------
if [ "$AH_CONFIRM" -ne 1 ]; then
  if ! oa_confirm "account-hygiene will lock/de-sudo accounts and remove non-allowlisted users from sudo/wheel/admin. Proceed?"; then
    die "account-hygiene: refusing to mutate without --confirm (or an interactive 'yes'). Preview with --dry-run."
  fi
fi

audit_log ah.apply.start "allowlist=$ONIONARMOR_AH_ALLOWLIST latch=$AH_SAFETY_LATCH cloud_lock=${cloud_lock:-none} cloud_desudo=${cloud_desudo:-none} strangers=${strangers:-none}"

mkdir -p "$ONIONARMOR_AH_STATE_DIR" || die "cannot create state dir $ONIONARMOR_AH_STATE_DIR"

# ---------------------------------------------------------------------------
# Snapshot + restore script. The restore script (a /bin/sh program) re-adds
# every user we are about to remove back to its group, and unlocks every account
# we are about to lock. It is BOTH the latch payload and the revert snapshot, so
# auto-revert and manual `revert.sh` undo exactly the same changes.
# ---------------------------------------------------------------------------
snapshot=$(ah_snapshot_path)
restore="$ONIONARMOR_AH_STATE_DIR/restore.sh"

{
  printf '#!/bin/sh\n'
  printf '# Managed by onionarmor (module: account-hygiene) — auto-restore of the\n'
  printf '# account/sudo state captured before apply. Re-adds removed users to their\n'
  printf '# groups and unlocks accounts this run locked. Safe to re-run.\n'
  printf 'GPASSWD=%s\n' "${ONIONARMOR_AH_GPASSWD}"
  printf 'USERMOD=%s\n' "${ONIONARMOR_AH_USERMOD}"
  # Re-add cloud defaults we are removing from sudo.
  for u in $cloud_desudo; do
    printf '"$GPASSWD" -a %s sudo >/dev/null 2>&1 || true\n' "$u"
  done
  # Re-add each stranger to the group we remove them from.
  for pair in $strangers; do
    printf '"$GPASSWD" -a %s %s >/dev/null 2>&1 || true\n' "${pair%%:*}" "${pair#*:}"
  done
  # Unlock each cloud default we are locking.
  for u in $cloud_lock; do
    printf '"$USERMOD" -U %s >/dev/null 2>&1 || true\n' "$u"
  done
  printf 'exit 0\n'
} > "$restore" || die "cannot write restore script $restore"
chmod +x "$restore" 2>/dev/null || true

# Persist the snapshot for revert.sh (the same data the restore script encodes).
{
  printf 'cloud_lock=%s\n'   "${cloud_lock# }"
  printf 'cloud_desudo=%s\n' "${cloud_desudo# }"
  printf 'strangers=%s\n'    "${strangers# }"
} > "$snapshot" || die "cannot write snapshot $snapshot"
audit_log ah.apply.snapshot "snapshot=$snapshot restore=$restore"

# ---------------------------------------------------------------------------
# Arm the 5-minute safety latch BEFORE mutating. If arming fails (atd down), we
# have changed nothing yet, so we die cleanly with no host changes.
# ---------------------------------------------------------------------------
latch_armed=0
if [ "$AH_SAFETY_LATCH" -eq 1 ]; then
  if oa_latch_arm "$AH_MODULE" "$restore" "$AH_LATCH_MIN"; then
    latch_armed=1
    info "armed safety latch (at job $OA_LATCH_JOBID): auto-restore in $AH_LATCH_MIN min"
  else
    audit_log ah.apply.fail "stage=latch-arm"
    die "account-hygiene: could not arm the safety latch (is atd running? 'apt install at && systemctl enable --now atd') — refusing to mutate accounts without an auto-restore. Use --no-safety-latch only with console access."
  fi
else
  warn "--no-safety-latch: no auto-restore scheduled — make sure you have console access in case this strips your own sudo."
fi

# ---------------------------------------------------------------------------
# 1. Lock + de-sudo cloud-init default accounts.
# ---------------------------------------------------------------------------
for u in $cloud_lock; do
  if "$ONIONARMOR_AH_USERMOD" -L "$u" >/dev/null 2>&1; then
    audit_log ah.apply.lock "user=$u"
    info "locked account: $u"
  else
    warn "could not lock account $u (usermod -L)"
  fi
done
for u in $cloud_desudo; do
  if "$ONIONARMOR_AH_GPASSWD" -d "$u" sudo >/dev/null 2>&1; then
    audit_log ah.apply.desudo "user=$u group=sudo reason=cloud-default"
    info "removed cloud-init default from sudo: $u"
  else
    warn "could not remove $u from sudo (gpasswd -d)"
  fi
done

# ---------------------------------------------------------------------------
# 2. Enforce the operator allowlist: remove each stranger from its priv group.
# ---------------------------------------------------------------------------
for pair in $strangers; do
  su=${pair%%:*}; sg=${pair#*:}
  if "$ONIONARMOR_AH_GPASSWD" -d "$su" "$sg" >/dev/null 2>&1; then
    audit_log ah.apply.desudo "user=$su group=$sg reason=not-allowlisted"
    info "removed non-allowlisted user from $sg: $su"
  else
    warn "could not remove $su from $sg (gpasswd -d)"
  fi
done

# ---------------------------------------------------------------------------
# 3. Assert only root is UID 0. We NEVER auto-fix this — a stray UID-0 account
#    could be the operator's own break-glass; deleting/renaming it blindly is
#    too dangerous. Warn loudly and audit so the operator investigates.
# ---------------------------------------------------------------------------
if [ -n "$uid0_extra" ]; then
  warn "non-root UID-0 account(s) detected:$uid0_extra — this is a serious problem. onionarmor will NOT fix it automatically; investigate (a backdoor or mistake)."
  audit_log ah.apply.uid0 "extra=$uid0_extra"
fi

# ---------------------------------------------------------------------------
# 4. Flag blanket NOPASSWD: ALL sudoers.d rules. NEVER auto-edited — editing
#    sudoers wrong can break sudo entirely; we only report.
# ---------------------------------------------------------------------------
if [ -n "$nopasswd_files" ]; then
  printf '%s\n' "$nopasswd_files" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    warn "blanket 'NOPASSWD: ALL' in $f — review/remove it by hand (onionarmor will NOT edit sudoers files)."
  done
  audit_log ah.apply.nopasswd "files=$(printf '%s' "$nopasswd_files" | tr '\n' ';')"
fi

audit_log ah.apply.done "latch_armed=$latch_armed jobid=${OA_LATCH_JOBID:-none}"

cat <<EOF

[account-hygiene] applied.
  allowlist : $ONIONARMOR_AH_ALLOWLIST
  locked    : $([ -n "${cloud_lock# }" ] && echo "${cloud_lock# }" || echo "(none)")
  de-sudoed : $([ -n "${cloud_desudo# }${strangers# }" ] && printf '%s %s' "${cloud_desudo# }" "$(for p in $strangers; do printf '%s ' "${p%%:*}"; done)" || echo "(none)")
EOF

if [ "$latch_armed" -eq 1 ]; then
  cat <<EOF

  *** ACCOUNT SAFETY LATCH ACTIVE — membership/locks auto-restore in $AH_LATCH_MIN minutes. ***
  Confirm you can still run 'sudo', THEN cancel the latch within $AH_LATCH_MIN min:

      atrm $OA_LATCH_JOBID
      # (or, generally:)  $(oa_latch_cancel_cmd "$AH_MODULE")

  If you do NOT cancel it, your prior account/sudo state is restored automatically.
EOF
fi

cat <<EOF

Check status any time:  onionarmor audit  --module account-hygiene
Undo the posture:       onionarmor revert --module account-hygiene
EOF
