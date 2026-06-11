# shellcheck shell=bash
# SC2034: the AH_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/account-hygiene/lib.sh — shared helpers for the account-hygiene
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log and the shared lib/safety_latch.sh for the 5-min
# dead-man's-switch. EVERY external command and filesystem path is overridable
# via env (ONIONARMOR_AH_*) so the bats suite drives the module against a sandbox
# of stub getent/usermod/passwd/gpasswd + a fake group database, never touching
# the real host's accounts.
#
# WHAT THIS MODULE DOES
#   Tightens local account / sudo posture on a relay host (onionauditor category
#   `accounts`). Concretely it (1) locks + de-sudoes the cloud-init default
#   accounts, (2) enforces an operator sudo allowlist by removing strangers from
#   the sudo/wheel/admin groups, (3) asserts only `root` has UID 0, and (4) flags
#   any blanket `NOPASSWD: ALL` sudoers.d rule. Because a mis-applied account or
#   sudo change can lock the operator out, apply REQUIRES either --dry-run or
#   --confirm and arms a 5-minute safety latch that auto-restores membership.
#   This module is MEDIUM risk and RECOMMENDED-OFF by default.

# --- locate + source the shared common.sh + safety latch ------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"
# shellcheck source=../../lib/safety_latch.sh
. "$ONIONARMOR_PREFIX/lib/safety_latch.sh"

# The literal latch module name shared across apply/audit/revert.
AH_MODULE="account-hygiene"

# --- overridable external commands ----------------------------------------
# In tests these are stubs that read/mutate a fake group database file; in
# production they are the real account tools. NEVER call the real ones unstubbed.
: "${ONIONARMOR_AH_GETENT:=getent}"
: "${ONIONARMOR_AH_USERMOD:=usermod}"
: "${ONIONARMOR_AH_PASSWD:=passwd}"
: "${ONIONARMOR_AH_GPASSWD:=gpasswd}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_AH_ALLOWLIST:=/etc/onionarmor/sudo-allowlist.conf}"
: "${ONIONARMOR_AH_SUDOERS_D:=/etc/sudoers.d}"
: "${ONIONARMOR_AH_STATE_DIR:=/var/lib/onionarmor/account-hygiene}"

# --- policy: the cloud-init default accounts we lock + de-sudo ------------
# Space-separated; overridable so an operator can extend/trim the set. Only
# accounts that actually exist are ever acted on.
: "${ONIONARMOR_AH_CLOUD_DEFAULTS:=ubuntu debian ec2-user centos fedora admin vagrant pi}"

# --- the privileged groups whose membership we police ---------------------
# sudo (Debian/Ubuntu), wheel (RHEL-ish), admin (legacy Ubuntu).
AH_PRIV_GROUPS="sudo wheel admin"

# --- flag defaults --------------------------------------------------------
ah_set_defaults() {
  AH_DRY_RUN=0
  AH_CONFIRM=0
  AH_SAFETY_LATCH=1
  AH_CANCEL_LATCH=0
  AH_LATCH_MIN="${ONIONARMOR_LATCH_TIMEOUT_MIN:-5}"
}

# ah_need_val <flag> <argc>: guard a value-taking flag's `shift 2` so a trailing
# `--latch-minutes` with no argument fails loudly instead of mis-parsing.
ah_need_val() {
  [ "$2" -ge 2 ] || die "account-hygiene: $1 requires a value"
}

ah_parse_flags() {
  ah_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)             AH_DRY_RUN=1; shift ;;
      --confirm)             AH_CONFIRM=1; shift ;;
      --no-safety-latch)     AH_SAFETY_LATCH=0; shift ;;
      --cancel-safety-latch) AH_CANCEL_LATCH=1; shift ;;
      --latch-minutes)       ah_need_val "$1" "$#"; AH_LATCH_MIN="$2"; shift 2 ;;
      -h|--help)             ah_usage; exit 0 ;;
      *)                     die "account-hygiene: unknown option: $1 (try --help)" ;;
    esac
  done
  case "$AH_LATCH_MIN" in
    ''|*[!0-9]*) die "account-hygiene: --latch-minutes must be a positive integer: $AH_LATCH_MIN" ;;
  esac
}

ah_usage() {
  cat <<'EOF'
onionarmor apply --module account-hygiene [options]   (also: audit, revert)

Tighten local account / sudo posture: lock + de-sudo cloud-init default
accounts, enforce an operator sudo allowlist (sudo/wheel/admin), assert only
root has UID 0, and flag blanket NOPASSWD:ALL sudoers rules. MEDIUM risk;
recommended-off. A bare apply refuses to mutate — pass --dry-run to preview or
--confirm to proceed. A 5-minute safety latch auto-restores membership unless
you cancel it after verifying you can still sudo.

OPTIONS
  --dry-run              Print the full plan of every account/group change and
                         exit. Changes nothing. (Default-safe.)
  --confirm              Required to actually mutate accounts/groups.
  --no-safety-latch      Do NOT arm the 5-minute auto-restore latch (console
                         access strongly recommended).
  --cancel-safety-latch  Cancel a pending safety latch and exit.
  --latch-minutes <N>    Minutes before the latch auto-restores (default 5).
  -h, --help             This help.

The operator sudo allowlist is read from:
  /etc/onionarmor/sudo-allowlist.conf   (one username per line, '#' comments)
If it is absent, apply REFUSES to enforce the allowlist (removing every sudoer
with no allowlist would lock you out). Create it first.
EOF
}

# --- paths ----------------------------------------------------------------
# ah_snapshot_path -> the saved-state file revert restores from.
ah_snapshot_path() {
  printf '%s/snapshot\n' "$ONIONARMOR_AH_STATE_DIR"
}

# --- account / group reads (all via the overridable getent) ---------------
# ah_account_exists <user>: true if the account is present in the passwd db.
ah_account_exists() {
  "$ONIONARMOR_AH_GETENT" passwd "$1" >/dev/null 2>&1
}

# ah_group_members <group>: emit one member username per line (empty if the
# group is absent or has no members). Parses the 4th colon field of `getent
# group <g>` (group_name:passwd:gid:member,member,...).
ah_group_members() {
  "$ONIONARMOR_AH_GETENT" group "$1" 2>/dev/null \
    | awk -F: 'NR==1 { n=split($4, m, ","); for (i=1;i<=n;i++) if (m[i] != "") print m[i] }'
}

# ah_group_exists <group>: true if the group is present in the group db.
ah_group_exists() {
  "$ONIONARMOR_AH_GETENT" group "$1" >/dev/null 2>&1
}

# ah_in_group <user> <group>: true if <user> is a member of <group>.
ah_in_group() {
  ah_group_members "$2" | grep -qxF "$1"
}

# ah_uid0_accounts: emit every username whose UID is 0 (one per line). The
# passwd db is name:passwd:uid:gid:... so field 3 == 0.
ah_uid0_accounts() {
  "$ONIONARMOR_AH_GETENT" passwd 2>/dev/null \
    | awk -F: '$3 == 0 { print $1 }'
}

# ah_account_locked <user>: true if the account's password is locked. `passwd
# -S <u>` prints `<user> L ...` when locked, `<user> P ...`/`NP` otherwise.
ah_account_locked() {
  local st
  st=$("$ONIONARMOR_AH_PASSWD" -S "$1" 2>/dev/null | awk '{print $2}')
  [ "$st" = "L" ]
}

# --- allowlist reading ----------------------------------------------------
# ah_allowlist_exists: true if the operator allowlist file is present.
ah_allowlist_exists() {
  [ -f "$ONIONARMOR_AH_ALLOWLIST" ]
}

# ah_allowlist_members: emit each allowlisted username (one per line), stripping
# '#' comments, inline comments, and surrounding whitespace.
ah_allowlist_members() {
  [ -f "$ONIONARMOR_AH_ALLOWLIST" ] || return 0
  while IFS= read -r line; do
    line=${line%%#*}
    # trim leading/trailing whitespace via word-splitting on a single token
    set -- $line
    [ "$#" -ge 1 ] || continue
    printf '%s\n' "$1"
  done < "$ONIONARMOR_AH_ALLOWLIST"
}

# ah_in_allowlist <user>: true if <user> is on the operator allowlist.
ah_in_allowlist() {
  ah_allowlist_members | grep -qxF "$1"
}

# --- sudoers.d scanning ---------------------------------------------------
# ah_nopasswd_all_files: emit each sudoers.d file path that contains a blanket
# `NOPASSWD: ALL` directive (one per line). Read-only. We match a line that
# grants ALL commands with NOPASSWD (ignoring leading whitespace + comments).
ah_nopasswd_all_files() {
  [ -d "$ONIONARMOR_AH_SUDOERS_D" ] || return 0
  local f
  for f in "$ONIONARMOR_AH_SUDOERS_D"/*; do
    [ -f "$f" ] || continue
    # A real blanket grant: "... NOPASSWD: ALL" not inside a comment.
    if grep -E '^[^#]*NOPASSWD:[[:space:]]*ALL' "$f" >/dev/null 2>&1; then
      printf '%s\n' "$f"
    fi
  done
  return 0
}

# --- cloud-default helpers ------------------------------------------------
# ah_present_cloud_defaults: emit each cloud-init default account that actually
# exists on this host (one per line).
ah_present_cloud_defaults() {
  local u
  for u in $ONIONARMOR_AH_CLOUD_DEFAULTS; do
    if ah_account_exists "$u"; then printf '%s\n' "$u"; fi
  done
  return 0
}
