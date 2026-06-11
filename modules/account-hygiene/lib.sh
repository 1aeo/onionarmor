# shellcheck shell=bash
# SC2034: the ACCT_* flag defaults set here are consumed by the apply/audit/
# revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/account-hygiene/lib.sh — shared helpers for the account-hygiene
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses lib/common.sh for info/warn/
# die/audit_log and the oa_status_* reporter. EVERY external command and path is
# overridable via env so the bats suite drives the module against a sandbox with
# stub binaries (getent, gpasswd, usermod, passwd, userdel, at, ...), never
# touching the real host's accounts.
#
# WHAT THIS MODULE DOES
#   Cleans up the account attack surface left by cloud images: locks + de-sudoes
#   leftover cloud-init users (ubuntu/debian/ec2-user/...), enforces an operator-
#   supplied sudo allowlist, refuses shared UID-0 accounts, and flags blanket
#   NOPASSWD sudoers. Removing sudo can strand the operator, so — like
#   firewall-default-deny — apply schedules a 5-minute safety latch that restores
#   the prior group membership unless the operator cancels it.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_ACCT_GETENT:=getent}"
: "${ONIONARMOR_ACCT_GPASSWD:=gpasswd}"
: "${ONIONARMOR_ACCT_USERMOD:=usermod}"
: "${ONIONARMOR_ACCT_USERDEL:=userdel}"
: "${ONIONARMOR_ACCT_PASSWD:=passwd}"
: "${ONIONARMOR_ACCT_AT:=at}"
: "${ONIONARMOR_ACCT_ATQ:=atq}"
: "${ONIONARMOR_ACCT_ATRM:=atrm}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_ACCT_SUDOERS_D:=/etc/sudoers.d}"
: "${ONIONARMOR_ACCT_ALLOWLIST:=/etc/onionarmor/sudo-allowlist.conf}"
: "${ONIONARMOR_ACCT_STATE_DIR:=/var/lib/onionarmor/account-hygiene}"
: "${ONIONARMOR_ACCT_LATCH_STATE_NAME:=safety-latch.job}"
: "${ONIONARMOR_ACCT_SNAPSHOT_NAME:=group-snapshot}"
: "${ONIONARMOR_ACCT_RESTORE_NAME:=latch-restore.sh}"

# Cloud-image default accounts that should never retain sudo on a relay.
: "${ONIONARMOR_ACCT_CLOUDINIT_USERS:=ubuntu debian ec2-user centos fedora admin vagrant pi}"
# Groups that grant sudo across distros.
: "${ONIONARMOR_ACCT_SUDO_GROUPS:=sudo wheel admin}"

# --- flag defaults --------------------------------------------------------
acct_set_defaults() {
  ACCT_PURGE=0            # userdel -r leftover cloud-init users (default: just lock)
  ACCT_ENFORCE_ALLOWLIST=1
  ACCT_SAFETY_LATCH=1
  ACCT_LATCH_MIN=5
  ACCT_ASSUME_YES=0
  ACCT_DRY_RUN=0
  ACCT_VERIFY=1
}

acct_need_val() {
  [ "$2" -ge 2 ] || die "account-hygiene: $1 requires a value (try --help)"
}

acct_parse_flags() {
  acct_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge)              ACCT_PURGE=1; shift ;;
      --no-allowlist)       ACCT_ENFORCE_ALLOWLIST=0; shift ;;
      --safety-latch)       ACCT_SAFETY_LATCH=1; shift ;;
      --no-safety-latch)    ACCT_SAFETY_LATCH=0; shift ;;
      --latch-minutes)      acct_need_val "$1" "$#"; ACCT_LATCH_MIN=$2; shift 2 ;;
      --latch-minutes=*)    ACCT_LATCH_MIN=${1#--latch-minutes=}; shift ;;
      --yes|--assume-yes)   ACCT_ASSUME_YES=1; shift ;;
      --dry-run)            ACCT_DRY_RUN=1; shift ;;
      --verify)             ACCT_VERIFY=1; shift ;;
      --no-verify)          ACCT_VERIFY=0; shift ;;
      -h|--help)            acct_usage; exit 0 ;;
      *)                    die "account-hygiene: unknown option: $1 (try --help)" ;;
    esac
  done
  acct_validate_flags
}

acct_validate_flags() {
  case "$ACCT_LATCH_MIN" in (*[!0-9]*|"") die "account-hygiene: --latch-minutes must be numeric: $ACCT_LATCH_MIN" ;; esac
  [ "$ACCT_LATCH_MIN" -ge 1 ] || die "account-hygiene: --latch-minutes must be >= 1"
}

acct_usage() {
  cat <<'EOF'
onionarmor apply --module account-hygiene [options]   (also: audit, revert)

Tighten the account attack surface: lock + de-sudo leftover cloud-init users
(ubuntu/debian/ec2-user/centos/fedora/admin/vagrant/pi), enforce an operator
sudo allowlist, refuse shared UID-0 accounts, and flag blanket NOPASSWD sudoers.

SAFETY: removing a user's sudo can strand the operator, so apply schedules a
5-minute `at` job that restores the prior group membership unless you cancel it.
Confirm you still have sudo, THEN run the printed atrm command.

The sudo allowlist lives at /etc/onionarmor/sudo-allowlist.conf — one username
per line (comments with #). Any user in a sudo group NOT on the allowlist is
removed from that group. If the allowlist is missing or empty, allowlist
enforcement is SKIPPED (so a typo can't strip every admin).

OPTIONS
  --purge                 Also `userdel -r` the locked cloud-init users (default:
                          lock + de-sudo only).
  --no-allowlist          Do not enforce the sudo allowlist (cloud-init + UID-0
                          checks still run).
  --no-safety-latch       Skip the 5-minute auto-restore latch (console access!).
  --latch-minutes <n>     Latch delay in minutes (default: 5).
  --yes, --assume-yes     Do not prompt for confirmation.
  --dry-run               Print the plan. Changes nothing.
  --verify / --no-verify  Post-apply verification (default: verify).
  -h, --help              This help.
EOF
}

# --- paths ----------------------------------------------------------------
acct_latch_state_path() { printf '%s/%s\n' "$ONIONARMOR_ACCT_STATE_DIR" "$ONIONARMOR_ACCT_LATCH_STATE_NAME"; }
acct_snapshot_path()    { printf '%s/%s\n' "$ONIONARMOR_ACCT_STATE_DIR" "$ONIONARMOR_ACCT_SNAPSHOT_NAME"; }
acct_restore_path()     { printf '%s/%s\n' "$ONIONARMOR_ACCT_STATE_DIR" "$ONIONARMOR_ACCT_RESTORE_NAME"; }

# --- account queries ------------------------------------------------------
# acct_user_exists <user>: true if the account exists in passwd.
acct_user_exists() {
  "$ONIONARMOR_ACCT_GETENT" passwd "$1" >/dev/null 2>&1
}

# acct_group_members <group>: print the group's members, one per line.
acct_group_members() {
  "$ONIONARMOR_ACCT_GETENT" group "$1" 2>/dev/null \
    | awk -F: 'NF>=4 { n=split($4, m, ","); for (i=1;i<=n;i++) if (m[i] != "") print m[i] }' \
    | sed '/^$/d' | sort -u || true
}

# acct_user_in_group <user> <group>: true if user is a member of group.
acct_user_in_group() {
  acct_group_members "$2" | grep -qx "$1"
}

# acct_user_locked <user>: true if the account is locked (passwd -S => "user L").
acct_user_locked() {
  "$ONIONARMOR_ACCT_PASSWD" -S "$1" 2>/dev/null | awk '{print $2}' | grep -qE '^L'
}

# acct_uid0_accounts: print every account with UID 0 (should be only root).
acct_uid0_accounts() {
  "$ONIONARMOR_ACCT_GETENT" passwd 2>/dev/null | awk -F: '$3 == 0 { print $1 }' | sort -u || true
}

# acct_sudo_group_members: print "user group" for every (user,sudo-group) pair.
acct_sudo_group_members() {
  local g u
  for g in $ONIONARMOR_ACCT_SUDO_GROUPS; do
    while IFS= read -r u; do
      [ -n "$u" ] && printf '%s %s\n' "$u" "$g"
    done <<EOF
$(acct_group_members "$g")
EOF
  done
}

# acct_cloudinit_sudo_users: print cloud-init users that exist AND hold sudo.
acct_cloudinit_sudo_users() {
  local u g
  for u in $ONIONARMOR_ACCT_CLOUDINIT_USERS; do
    acct_user_exists "$u" || continue
    for g in $ONIONARMOR_ACCT_SUDO_GROUPS; do
      if acct_user_in_group "$u" "$g"; then printf '%s\n' "$u"; break; fi
    done
  done
}

# acct_read_allowlist: print allowlisted usernames (skip comments/blanks).
acct_read_allowlist() {
  [ -r "$ONIONARMOR_ACCT_ALLOWLIST" ] || return 0
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$ONIONARMOR_ACCT_ALLOWLIST" \
    | sed '/^$/d' | sort -u || true
}

# acct_allowlist_violations: print "user group" pairs for sudo-group members not
# on the allowlist. Empty when the allowlist is missing/empty (enforcement off).
acct_allowlist_violations() {
  local allow; allow=$(acct_read_allowlist)
  [ -n "$allow" ] || return 0
  local u g
  while IFS=' ' read -r u g; do
    [ -n "$u" ] || continue
    printf '%s\n' "$allow" | grep -qx "$u" || printf '%s %s\n' "$u" "$g"
  done <<EOF
$(acct_sudo_group_members)
EOF
}

# acct_nopasswd_all_files: print sudoers.d files granting blanket NOPASSWD: ALL.
acct_nopasswd_all_files() {
  [ -d "$ONIONARMOR_ACCT_SUDOERS_D" ] || return 0
  local f
  for f in "$ONIONARMOR_ACCT_SUDOERS_D"/*; do
    [ -f "$f" ] || continue
    grep -qE 'NOPASSWD:[[:space:]]*ALL' "$f" 2>/dev/null && printf '%s\n' "$f"
  done
  return 0
}

# acct_latch_pending: echo the pending safety-latch at-job id if still queued.
acct_latch_pending() {
  local f job
  f=$(acct_latch_state_path)
  [ -f "$f" ] || return 0
  job=$(cat "$f" 2>/dev/null)
  [ -n "$job" ] || return 0
  if "$ONIONARMOR_ACCT_ATQ" 2>/dev/null | awk '{print $1}' | grep -qx "$job"; then
    printf '%s\n' "$job"
  fi
}
