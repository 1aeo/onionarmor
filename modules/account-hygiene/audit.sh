#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the account-hygiene posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) every present cloud-init default is locked AND out of sudo,
#   (b) every sudo/wheel/admin member is on the operator allowlist
#       (yellow, not red, if the allowlist file is missing — can't judge),
#   (c) only root has UID 0,
#   (d) no sudoers.d file carries a blanket NOPASSWD: ALL,
#   (e) a pending safety latch is yellow (the host may still auto-revert).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ah_parse_flags "$@"

info "account-hygiene audit"
printf '\n'

# --- (a) cloud-init defaults locked + out of sudo -------------------------
present_cloud=$(ah_present_cloud_defaults)
if [ -z "$present_cloud" ]; then
  oa_status_check green "cloud-init defaults" "none of the known defaults are present"
else
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    in_sudo=no; ah_in_group "$u" sudo && in_sudo=yes
    locked=no;  ah_account_locked "$u" && locked=yes
    if [ "$locked" = yes ] && [ "$in_sudo" = no ]; then
      oa_status_check green "cloud default: $u" "locked + out of sudo"
    else
      oa_status_check red "cloud default: $u" "locked=$locked in_sudo=$in_sudo — run: onionarmor apply --module account-hygiene"
    fi
  done <<EOF
$present_cloud
EOF
fi

# --- (b) every priv-group member is allowlisted ---------------------------
if ! ah_allowlist_exists; then
  oa_status_check yellow "sudo allowlist" "$ONIONARMOR_AH_ALLOWLIST missing — cannot verify priv-group membership (create it)"
else
  strangers=""
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
  if [ -z "$strangers" ]; then
    oa_status_check green "sudo allowlist" "every sudo/wheel/admin member is allowlisted"
  else
    for pair in $strangers; do
      oa_status_check red "priv-group stranger" "${pair%%:*} is in ${pair#*:} but not in $ONIONARMOR_AH_ALLOWLIST"
    done
  fi
fi

# --- (c) only root has UID 0 ----------------------------------------------
uid0_extra=""
while IFS= read -r u; do
  [ -n "$u" ] || continue
  [ "$u" = "root" ] && continue
  uid0_extra="$uid0_extra $u"
done <<EOF
$(ah_uid0_accounts)
EOF
if [ -z "$uid0_extra" ]; then
  oa_status_check green "UID 0 == root only" "only root has UID 0"
else
  oa_status_check red "UID 0 == root only" "non-root UID-0 account(s):$uid0_extra — investigate (possible backdoor)"
fi

# --- (d) no blanket NOPASSWD: ALL in sudoers.d ----------------------------
nopasswd_files=$(ah_nopasswd_all_files)
if [ -z "$nopasswd_files" ]; then
  oa_status_check green "sudoers.d NOPASSWD:ALL" "no blanket NOPASSWD:ALL in $ONIONARMOR_AH_SUDOERS_D"
else
  # Iterate without a pipe so oa_status_check's red verdict is set in THIS shell
  # (a `| while` subshell would lose the worst-severity update under set -e).
  while IFS= read -r f; do
    [ -n "$f" ] && oa_status_check red "sudoers.d NOPASSWD:ALL" "blanket NOPASSWD:ALL in $f — review/remove by hand"
  done <<EOF
$nopasswd_files
EOF
fi

# --- (e) pending safety latch ---------------------------------------------
if oa_latch_is_armed "$AH_MODULE"; then
  oa_status_check yellow "safety latch" "a safety latch is pending — the host may auto-restore account state. Cancel: $(oa_latch_cancel_cmd "$AH_MODULE")"
fi

oa_status_summary "one or more RED checks — account-hygiene posture has problems above"
