# shellcheck shell=bash
# lib/common.sh — shared helpers (paths, logging, audit, errors).
#
# Sourced by lib/* and bin/onionarmor. All filesystem paths are env-var
# overridable so tests can run without touching /etc or /var/log.

# ---------------------------------------------------------------------------
# Path configuration. Defaults are production paths; tests override via env.
# ---------------------------------------------------------------------------
: "${ONIONARMOR_ROLES_DIR:=$ONIONARMOR_PREFIX/roles}"
: "${ONIONARMOR_MODULES_DIR:=$ONIONARMOR_PREFIX/modules}"
: "${ONIONARMOR_ETC_DIR:=/etc/onionarmor}"
: "${ONIONARMOR_SYSCTL_DIR:=/etc/sysctl.d}"
: "${ONIONARMOR_AUDIT_LOG:=/var/log/onionarmor/audit.log}"
: "${ONIONARMOR_SYSCTL_CMD:=sysctl}"
: "${ONIONARMOR_GRUB_FILE:=/etc/default/grub}"
: "${ONIONARMOR_UPDATE_GRUB_CMD:=update-grub}"
: "${ONIONARMOR_OPERATOR:=${SUDO_USER:-${USER:-unknown}}}"

# ---------------------------------------------------------------------------
# Output helpers. Errors go to stderr; everything else to stdout. Colour only
# if stderr is a tty.
# ---------------------------------------------------------------------------
if [ -t 2 ]; then
  _OA_C_RED=$'\033[31m'; _OA_C_YEL=$'\033[33m'; _OA_C_OFF=$'\033[0m'
else
  _OA_C_RED=""; _OA_C_YEL=""; _OA_C_OFF=""
fi

die()  { printf '%sonionarmor: error:%s %s\n' "$_OA_C_RED" "$_OA_C_OFF" "$*" >&2; exit 1; }
warn() { printf '%sonionarmor: warn:%s %s\n'  "$_OA_C_YEL" "$_OA_C_OFF" "$*" >&2; }
info() { printf 'onionarmor: %s\n' "$*"; }

# Tabular layout for `diff` + `apply --dry-run` sysctl rows. Columns:
#   KEY (40w) CURRENT (10w) TARGET (10w) STATUS (free)
# Centralised so widening one column doesn't require touching 7 printf sites.
_OA_FMT_SYSCTL_ROW='%-40s %-10s %-10s %s\n'
_OA_DASH_SYSCTL_ROW='----------------------------------------'
_OA_DASH_SYSCTL_COL='----------'

oa_utc_ts() { date -u +%Y%m%dT%H%M%SZ; }
oa_utc_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
# Audit log. Tab-separated for cheap awk parsing. Each apply / rollback /
# apply-lockdown writes a .start, zero or more .change, and a .done line.
# ---------------------------------------------------------------------------
audit_log() {
  # audit_log <action> <details...>
  local action=$1; shift
  local line
  line="$(oa_utc_iso)"$'\t'"$ONIONARMOR_OPERATOR"$'\t'"$action"$'\t'"$*"
  local dir
  dir=$(dirname "$ONIONARMOR_AUDIT_LOG")
  mkdir -p "$dir" 2>/dev/null || die "cannot create audit dir: $dir"
  printf '%s\n' "$line" >> "$ONIONARMOR_AUDIT_LOG" \
    || die "cannot write audit log: $ONIONARMOR_AUDIT_LOG"
}

# audit_fail_die  <fail-action> <details> <die-msg>
# audit_fail_warn <fail-action> <details> <warn-msg>
#
# Collapses the recurring `|| { audit_log X.fail "stage=Y"; die/warn "Z"; }`
# pattern at apply/rollback/lockdown fail sites. Use as:
#   <command> || audit_fail_die  apply.fail "stage=write" "failed to write …"
#   <command> || audit_fail_warn rollback.fail "stage=reload" "sysctl reload …"
audit_fail_die()  { audit_log "$1" "$2"; die  "$3"; }
audit_fail_warn() { audit_log "$1" "$2"; warn "$3"; }

# ---------------------------------------------------------------------------
# Confirmation prompt. Reads from stdin; returns 0 on yes/y, nonzero otherwise.
# Tests override via $ONIONARMOR_AUTO_CONFIRM=yes.
# ---------------------------------------------------------------------------
oa_confirm() {
  # oa_confirm <prompt>
  if [ "${ONIONARMOR_AUTO_CONFIRM:-}" = "yes" ]; then return 0; fi
  if [ "${ONIONARMOR_AUTO_CONFIRM:-}" = "no" ]; then return 1; fi
  local reply
  printf '%s [yes/NO] ' "$1" >&2
  read -r reply || return 1
  case "$reply" in yes|YES|y|Y) return 0 ;; *) return 1 ;; esac
}

# require_role <subcommand-name>: every command that takes --role gates on a
# non-empty role + the role file existing. Sources lib/role.sh's `role_validate`.
require_role() {
  [ -n "${_oa_role:-}" ] || die "$1: --role <name> required"
  role_validate "$_oa_role"
}
