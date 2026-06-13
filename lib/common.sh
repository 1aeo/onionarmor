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
  _OA_C_RED=$'\033[31m'; _OA_C_GRN=$'\033[32m'; _OA_C_YEL=$'\033[33m'; _OA_C_OFF=$'\033[0m'
else
  _OA_C_RED=""; _OA_C_GRN=""; _OA_C_YEL=""; _OA_C_OFF=""
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
# Dry-run preview helpers. A module action invoked with --dry-run must print
# the exact host changes it WOULD make and then exit WITHOUT touching the host
# (no file writes, no sysctl/systemctl, not even an audit-log line). These give
# every module's apply/revert preview one shared banner + "would:" line format
# so the operator sees a consistent, greppable plan.
#
#   oa_dryrun_header <module> <action>   banner: "dry-run: <module> <action> — no host changes"
#   oa_would <text...>                   one planned action: "  would: <text>"
# ---------------------------------------------------------------------------
oa_dryrun_header() {
  info "dry-run: $1 $2 — no host changes (preview only; nothing below is executed)"
  printf '\nPLAN\n'
}
oa_would() { printf '  would: %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Module audit status reporting. Every module's audit.sh reports a series of
# green/yellow/red checks then a verdict; this is the shared machinery so the
# three modules don't each carry an identical reporter + summary block.
#
#   oa_status_check <green|yellow|red> <label> <detail>   per check line
#   oa_status_summary <red-message>                        verdict line + exit
#
# Worst severity wins: green/yellow exit 0, any red exits 1. _oa_status_worst is
# reset on each source of common.sh, i.e. once per audit run.
# ---------------------------------------------------------------------------
_oa_status_worst=0   # 0 green, 1 yellow, 2 red

oa_status_check() {
  local mark col
  case "$1" in
    green)  mark="[ ok ]"; col=$_OA_C_GRN ;;
    yellow) mark="[warn]"; col=$_OA_C_YEL; [ "$_oa_status_worst" -lt 1 ] && _oa_status_worst=1 ;;
    red)    mark="[FAIL]"; col=$_OA_C_RED; _oa_status_worst=2 ;;
  esac
  printf '%s%s%s %-26s %s\n' "$col" "$mark" "$_OA_C_OFF" "$2" "$3"
}

oa_status_summary() {
  printf '\n'
  case "$_oa_status_worst" in
    0) info "audit: all green"; exit 0 ;;
    1) info "audit: green/yellow — no failures, see warnings above"; exit 0 ;;
    *) warn "audit: $1"; exit 1 ;;
  esac
}

# oa_write_if_changed <path> <content>: atomically write <content> to <path>
# only when it differs from the current file (idempotent). Returns 0 when the
# file was (re)written, 1 when it was already byte-identical, so callers branch
# to log "wrote" vs "already current". Dies on a write/rename failure. MUST be
# used as an `if` condition — a bare call returning 1 would trip `set -e`.
oa_write_if_changed() {
  local path=$1 content=$2 tmp
  [ -f "$path" ] && [ "$(cat "$path")" = "$content" ] && return 1
  tmp="$path.tmp.$$"
  printf '%s\n' "$content" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$path" || { rm -f "$tmp"; die "cannot move $tmp -> $path"; }
  return 0
}

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
