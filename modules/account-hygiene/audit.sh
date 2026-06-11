#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the account-hygiene posture. Read-only.
# Exits non-zero if any check is red (shared UID-0 or blanket NOPASSWD: ALL).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

acct_parse_flags "$@"

info "account-hygiene audit"
printf '\n'

# --- 1. leftover cloud-init users with sudo --------------------------------
cloudinit=$(acct_cloudinit_sudo_users | sed '/^$/d' | sort -u || true)
if [ -n "$cloudinit" ]; then
  oa_status_check yellow "cloud-init sudo users" "still hold sudo: $(printf '%s' "$cloudinit" | tr '\n' ' ') (apply locks + de-sudoes these)"
else
  oa_status_check green "cloud-init sudo users" "no cloud-init account holds sudo"
fi

# --- 2. cloud-init accounts locked ----------------------------------------
unlocked=""
for u in $ONIONARMOR_ACCT_CLOUDINIT_USERS; do
  acct_user_exists "$u" || continue
  acct_user_locked "$u" || unlocked="$unlocked $u"
done
unlocked=$(printf '%s' "$unlocked" | sed 's/^ *//')
if [ -n "$unlocked" ]; then
  oa_status_check yellow "cloud-init accounts locked" "still unlocked: $unlocked"
else
  oa_status_check green "cloud-init accounts locked" "no unlocked cloud-init accounts"
fi

# --- 3. shared UID-0 accounts (RED) ---------------------------------------
uid0_extra=$(acct_uid0_accounts | grep -vx root || true)
if [ -n "$uid0_extra" ]; then
  oa_status_check red "single UID-0 (root)" "shared UID-0 account(s): $(printf '%s' "$uid0_extra" | tr '\n' ' ')"
else
  oa_status_check green "single UID-0 (root)" "root is the only UID-0 account"
fi

# --- 4. blanket NOPASSWD: ALL sudoers (RED) -------------------------------
nopasswd=$(acct_nopasswd_all_files || true)
if [ -n "$nopasswd" ]; then
  oa_status_check red "no blanket NOPASSWD" "NOPASSWD: ALL in: $(printf '%s' "$nopasswd" | tr '\n' ' ')"
else
  oa_status_check green "no blanket NOPASSWD" "no blanket NOPASSWD: ALL in $ONIONARMOR_ACCT_SUDOERS_D"
fi

# --- 5. sudo allowlist enforcement ----------------------------------------
allow=$(acct_read_allowlist)
if [ -z "$allow" ]; then
  oa_status_check yellow "sudo allowlist" "no allowlist at $ONIONARMOR_ACCT_ALLOWLIST (enforcement off)"
else
  violations=$(acct_allowlist_violations | sed '/^$/d' | sort -u || true)
  if [ -n "$violations" ]; then
    oa_status_check yellow "sudo allowlist" "off-allowlist sudo: $(printf '%s' "$violations" | tr '\n' ',' | sed 's/,$//')"
  else
    oa_status_check green "sudo allowlist" "every sudo-group member is on the allowlist"
  fi
fi

# --- 6. pending safety latch ----------------------------------------------
job=$(acct_latch_pending)
if [ -n "$job" ]; then
  oa_status_check yellow "safety latch" "at job $job still PENDING — confirm sudo then: atrm $job"
else
  oa_status_check green "safety latch" "no pending auto-restore job"
fi

oa_status_summary "shared UID-0 account or blanket NOPASSWD: ALL present — account posture is broken"
