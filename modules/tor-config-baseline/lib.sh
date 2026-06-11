# shellcheck shell=bash
# SC2034: the TCB_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/tor-config-baseline/lib.sh — shared helpers for the tor-config-baseline
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log and the shared lib/safety_latch.sh dead-man's
# switch. EVERY external command and filesystem path is overridable via env so
# the bats suite drives the whole module against a sandbox torrc tree with stub
# systemctl/at/atrm binaries, never touching the real tor.
#
# WHAT THIS MODULE DOES
#   Enforces a conservative "config baseline" on every tor instance's torrc:
#   offline master key + short signing-key lifetime, loopback-only Metrics/Control
#   ports (preserving any operator-chosen localhost binding), cookie auth for an
#   unauthenticated ControlPort, and disabling the optional statistics that a
#   relay would otherwise publish. It NEVER touches the operator's identity / exit
#   / family / socks lines. Maps to the onionauditor `tor-config` category.

# --- locate + source the shared common.sh + safety latch ------------------
# apply/audit/revert are exec'd by bin/onionarmor with ONIONARMOR_PREFIX set,
# but they can also be run directly (e.g. from tests) — fall back to deriving
# the prefix from this file's location.
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"
# shellcheck source=../../lib/safety_latch.sh
. "$ONIONARMOR_PREFIX/lib/safety_latch.sh"

# The module-name literal used for latch state + audit-log lines.
TCB_MODULE="tor-config-baseline"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_TCB_SYSTEMCTL:=systemctl}"

# --- overridable torrc discovery (mirrors kernel-reserved-ports) ----------
: "${ONIONARMOR_TCB_INSTANCES_DIR:=/etc/tor/instances}"
: "${ONIONARMOR_TCB_TORRC:=/etc/tor/torrc}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_TCB_STATE_DIR:=/var/lib/onionarmor/tor-config-baseline}"

# --- the enforced "key value" settings this module manages ----------------
# One `key value` per line. Order is stable so the rendered plan is
# deterministic. Overridable as a whole for tests / future tuning, but these are
# the published baseline values, not a per-run knob.
: "${TCB_ENFORCED:=OfflineMasterKey 1
SigningKeyLifetime 60 days
DirReqStatistics 0
ConnDirectionStatistics 0
ExtraInfoStatistics 0}"

# The loopback "auto" listeners we add when none is present. Handled specially
# (preserve any existing localhost binding) rather than as plain enforced keys.
: "${ONIONARMOR_TCB_METRICSPORT:=127.0.0.1:auto}"
: "${ONIONARMOR_TCB_CONTROLPORT:=127.0.0.1:auto}"
: "${ONIONARMOR_TCB_COOKIE_AUTHFILE:=/var/run/tor/control.authcookie}"

# --- flag defaults --------------------------------------------------------
tcb_set_defaults() {
  TCB_DRY_RUN=0
  TCB_CONFIRM_OMK=0
  TCB_SAFETY_LATCH=1
  TCB_CANCEL_LATCH=0
  TCB_LATCH_MIN=$ONIONARMOR_LATCH_TIMEOUT_MIN
}

# tcb_need_val <flag> <count>: die unless a value-taking flag was given an
# argument. Guards `shift 2` from a "shift count out of range" on a trailing
# valueless flag, routing the error through our die message.
tcb_need_val() {
  [ "$2" -ge 2 ] || die "tor-config-baseline: $1 requires a value (try --help)"
}

tcb_parse_flags() {
  tcb_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)                    TCB_DRY_RUN=1; shift ;;
      --confirm-offline-master-key) TCB_CONFIRM_OMK=1; shift ;;
      --safety-latch)               TCB_SAFETY_LATCH=1; shift ;;
      --no-safety-latch)            TCB_SAFETY_LATCH=0; shift ;;
      --cancel-safety-latch)        TCB_CANCEL_LATCH=1; shift ;;
      --latch-minutes)              tcb_need_val "$1" "$#"; TCB_LATCH_MIN=$2; shift 2 ;;
      --latch-minutes=*)            TCB_LATCH_MIN=${1#--latch-minutes=}; shift ;;
      -h|--help)                    tcb_usage; exit 0 ;;
      *)                            die "tor-config-baseline: unknown option: $1 (try --help)" ;;
    esac
  done
  case "$TCB_LATCH_MIN" in (*[!0-9]*|"") die "tor-config-baseline: --latch-minutes must be a positive integer: $TCB_LATCH_MIN" ;; esac
  [ "$TCB_LATCH_MIN" -ge 1 ] || die "tor-config-baseline: --latch-minutes must be >= 1"
}

tcb_usage() {
  cat <<'EOF'
onionarmor apply --module tor-config-baseline [options]   (also: audit, revert)

Enforce a conservative config baseline on every tor instance's torrc: offline
master key, 60-day signing-key lifetime, loopback-only Metrics/Control ports,
cookie auth for an unauthenticated ControlPort, and disabled relay statistics.
Edits each torrc in place (backing it up first) and reloads the instance. Never
touches ContactInfo / MyFamily / FamilyId / ExitRelay / SocksPort lines. MEDIUM
risk; recommended-OFF.

Enforced settings:
  OfflineMasterKey 1          SigningKeyLifetime 60 days
  MetricsPort 127.0.0.1:auto  ControlPort 127.0.0.1:auto  (preserve existing localhost)
  CookieAuthentication 1      (only if ControlPort set with no auth)
  DirReqStatistics 0          ConnDirectionStatistics 0   ExtraInfoStatistics 0

OPTIONS
  --dry-run                       Print a per-instance plan of what would change.
                                  Changes nothing. Exits 0.
  --confirm-offline-master-key    REQUIRED to mutate (outside --dry-run). Setting
                                  OfflineMasterKey has real operational
                                  consequences (the signing key must be rotated
                                  and the master key taken offline), so apply
                                  refuses without this flag.
  --no-safety-latch               Skip the 5-minute auto-revert latch (a broken
                                  torrc edit can lock you out of the control port
                                  or fail the reload — console access required).
  --cancel-safety-latch           Cancel a pending auto-revert latch and exit.
  --latch-minutes <N>             Auto-revert delay in minutes (default 5).
  -h, --help                      This help.
EOF
}

# --- paths ----------------------------------------------------------------
# tcb_backup_dir -> the directory holding per-instance torrc backups.
tcb_backup_dir() {
  printf '%s/backups\n' "$ONIONARMOR_TCB_STATE_DIR"
}

# tcb_restore_script_path -> the rendered restore script the latch fires.
tcb_restore_script_path() {
  printf '%s/restore.sh\n' "$ONIONARMOR_TCB_STATE_DIR"
}

# --- torrc discovery ------------------------------------------------------
# tcb_instances: print "<inst-name>\t<torrc-path>" for every discovered instance
# torrc, one per line, in a stable order. Instance dirs under the instances dir
# give their dir name as <inst-name>; a single top-level torrc is labelled
# "default".
tcb_instances() {
  local d f name
  d=$ONIONARMOR_TCB_INSTANCES_DIR
  if [ -d "$d" ]; then
    for f in "$d"/*/torrc; do
      [ -e "$f" ] || continue
      name=$(basename "$(dirname "$f")")
      printf '%s\t%s\n' "$name" "$f"
    done
  fi
  [ -f "$ONIONARMOR_TCB_TORRC" ] && printf 'default\t%s\n' "$ONIONARMOR_TCB_TORRC"
  return 0
}

# tcb_instance_count: number of discovered instance torrc files.
tcb_instance_count() {
  tcb_instances | grep -c . || true
}

# --- torrc inspection -----------------------------------------------------
# tcb_directive_lines <file> <directive>: print every non-comment line in <file>
# whose first token is <directive> (case-sensitive, tor directives are too).
tcb_directive_lines() {
  awk -v key="$2" '
    { line = $0; sub(/#.*/, "", line)
      n = split(line, F, /[ \t]+/)
      d = F[1]; if (d == "" && n >= 2) d = F[2]
      if (d == key) print $0 }
  ' "$1"
}

# tcb_has_localhost_listener <file> <directive>: true if <directive> has a value
# bound to a loopback address (127.x / ::1 / [::1]) OR a bare port (tor binds
# those on 127.0.0.1). Used to PRESERVE an operator's existing localhost binding.
tcb_has_localhost_listener() {
  tcb_directive_lines "$1" "$2" | awk '
    { line = $0; sub(/#.*/, "", line)
      n = split(line, F, /[ \t]+/)
      spec = F[2]; if (F[1] == "" && n >= 3) spec = F[3]
      if (spec == "") next
      if (spec ~ /^127\./)        { found = 1; exit }
      if (spec ~ /^\[?::1\]?:/)   { found = 1; exit }
      if (spec ~ /^[0-9]+$/)      { found = 1; exit }   # bare port -> 127.0.0.1
      if (spec == "auto")         { found = 1; exit }   # "auto" -> 127.0.0.1
    }
    END { exit (found ? 0 : 1) }
  '
}

# tcb_has_directive <file> <directive>: true if <directive> appears at all.
tcb_has_directive() {
  [ -n "$(tcb_directive_lines "$1" "$2")" ]
}

# tcb_setting_ok <file> <key> <val>: true if <key> is present with EXACTLY the
# enforced <val> (whitespace-normalised). Used by audit + idempotency checks for
# the plain enforced `key value` settings.
tcb_setting_ok() {
  local file=$1 key=$2 val=$3 line cur
  line=$(tcb_directive_lines "$file" "$key" | tail -1)
  [ -n "$line" ] || return 1
  cur=$(printf '%s' "$line" | awk '{ $1=""; sub(/^ +/, ""); sub(/#.*/, ""); sub(/ +$/, ""); print }')
  [ "$(printf '%s' "$cur" | awk '{$1=$1;print}')" = "$val" ]
}

# tcb_controlport_unauthed <file>: true if a ControlPort is set WITHOUT any auth
# (no CookieAuthentication and no HashedControlPassword present).
tcb_controlport_unauthed() {
  local file=$1
  tcb_has_directive "$file" ControlPort || return 1
  tcb_has_directive "$file" CookieAuthentication && return 1
  tcb_has_directive "$file" HashedControlPassword && return 1
  return 0
}

# --- the rewriter ---------------------------------------------------------
# tcb_plan_changes <file>: print a human-readable, one-per-line plan of the edits
# this module WOULD make to <file> (used by --dry-run and to decide if anything
# changes). Empty output => already compliant.
tcb_plan_changes() {
  local file=$1 key val

  # Plain enforced settings.
  printf '%s\n' "$TCB_ENFORCED" | while read -r key val; do
    [ -n "$key" ] || continue
    if tcb_setting_ok "$file" "$key" "$val"; then
      continue
    elif tcb_has_directive "$file" "$key"; then
      printf 'set   %s -> %s\n' "$key" "$val"
    else
      printf 'add   %s %s\n' "$key" "$val"
    fi
  done

  # MetricsPort / ControlPort: only add if no localhost listener already present.
  if ! tcb_has_localhost_listener "$file" MetricsPort; then
    printf 'add   MetricsPort %s\n' "$ONIONARMOR_TCB_METRICSPORT"
  fi
  if ! tcb_has_localhost_listener "$file" ControlPort; then
    printf 'add   ControlPort %s\n' "$ONIONARMOR_TCB_CONTROLPORT"
  fi

  # Cookie auth for an unauthenticated ControlPort.
  if tcb_controlport_unauthed "$file"; then
    printf 'add   CookieAuthentication 1\n'
    printf 'add   CookieAuthFile %s\n' "$ONIONARMOR_TCB_COOKIE_AUTHFILE"
  fi
}

# tcb_rewrite <src> <dst>: write a baseline-compliant copy of torrc <src> to
# <dst>. Plain enforced keys are corrected in place (first occurrence rewritten,
# later duplicates dropped) or appended; the special Metrics/Control/Cookie
# directives are appended only when absent (preserving existing localhost
# bindings). PRESERVED operator lines pass through verbatim. Portable awk + temp
# file; the caller does the mv.
tcb_rewrite() {
  local src=$1 dst=$2
  local add_metrics=0 add_control=0 add_cookie=0
  tcb_has_localhost_listener "$src" MetricsPort || add_metrics=1
  tcb_has_localhost_listener "$src" ControlPort || add_control=1
  tcb_controlport_unauthed "$src" && add_cookie=1

  # Pass the (multi-line) enforced settings through the environment rather than
  # `-v`: BSD awk rejects an embedded newline in a -v assignment.
  TCB_ENFORCED_ENV="$TCB_ENFORCED" awk \
    -v add_metrics="$add_metrics" -v metricsval="$ONIONARMOR_TCB_METRICSPORT" \
    -v add_control="$add_control" -v controlval="$ONIONARMOR_TCB_CONTROLPORT" \
    -v add_cookie="$add_cookie" -v cookiefile="$ONIONARMOR_TCB_COOKIE_AUTHFILE" '
    BEGIN {
      enforced = ENVIRON["TCB_ENFORCED_ENV"]
      ne = split(enforced, lines, "\n")
      for (i = 1; i <= ne; i++) {
        n = split(lines[i], parts, /[ \t]+/)
        if (n < 2) continue
        k = parts[1]
        v = parts[2]; for (j = 3; j <= n; j++) v = v " " parts[j]
        ekey[k] = v
      }
    }
    {
      raw = $0
      line = raw; sub(/#.*/, "", line)
      n = split(line, F, /[ \t]+/)
      d = F[1]; if (d == "" && n >= 2) d = F[2]
      if (d != "" && (d in ekey)) {
        if (!seen[d]) {            # rewrite first occurrence to the enforced value
          printf "%s %s\n", d, ekey[d]
          seen[d] = 1
        }
        next                       # drop later duplicates of an enforced key
      }
      print raw                     # preserved line (ContactInfo/MyFamily/...) verbatim
    }
    END {
      added = 0
      for (k in ekey) { if (!seen[k]) need[k] = 1 }
      # Emit any enforced keys that were absent, in the original enforced order.
      ne2 = split(enforced, lines2, "\n")
      for (i = 1; i <= ne2; i++) {
        split(lines2[i], p2, /[ \t]+/)
        k = p2[1]
        if (k != "" && (k in need)) {
          if (!added) { print ""; print "# Added by onionarmor (module: tor-config-baseline)"; added = 1 }
          printf "%s %s\n", k, ekey[k]
        }
      }
      if (add_metrics == "1") { if (!added) { print ""; print "# Added by onionarmor (module: tor-config-baseline)"; added = 1 }; printf "MetricsPort %s\n", metricsval }
      if (add_control == "1") { if (!added) { print ""; print "# Added by onionarmor (module: tor-config-baseline)"; added = 1 }; printf "ControlPort %s\n", controlval }
      if (add_cookie  == "1") {
        if (!added) { print ""; print "# Added by onionarmor (module: tor-config-baseline)"; added = 1 }
        print "CookieAuthentication 1"
        printf "CookieAuthFile %s\n", cookiefile
      }
    }
  ' "$src" > "$dst"
}

# tcb_reload_instance <inst>: reload one tor instance via systemctl (no-op under
# ONIONARMOR_SKIP_RELOAD=yes). Returns the systemctl exit status.
tcb_reload_instance() {
  local inst=$1
  if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
    info "ONIONARMOR_SKIP_RELOAD=yes — skipping reload of tor@$inst"
    return 0
  fi
  "$ONIONARMOR_TCB_SYSTEMCTL" reload "tor@$inst"
}
