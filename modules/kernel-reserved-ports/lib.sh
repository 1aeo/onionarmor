# shellcheck shell=bash
# SC2034: the colour vars + KRP_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/kernel-reserved-ports/lib.sh — shared helpers for the
# kernel-reserved-ports module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log, and the existing ONIONARMOR_SYSCTL_DIR /
# ONIONARMOR_SYSCTL_CMD knobs so the module's drop-in lives alongside the
# role-based managed files. EVERY external command and filesystem path is
# overridable via env so the bats suite drives the whole module against a
# sandbox with stub binaries, never touching the real host.
#
# WHAT THIS MODULE DOES
#   Linux picks the source port of an outbound connection from the ephemeral
#   range net.ipv4.ip_local_port_range (default ~32768-60999). On a dense relay
#   host, a tor MetricsPort/ControlPort bound on loopback inside that range can
#   collide with an ephemeral source port the kernel hands to *another* tor
#   instance's outbound socket — the listener then fails to bind. This module
#   removes the relay's loopback service ports from the ephemeral pool via
#   net.ipv4.ip_local_reserved_ports, written as a sysctl.d drop-in.

# --- locate + source the shared common.sh ---------------------------------
# apply/audit/revert are exec'd by bin/onionarmor with ONIONARMOR_PREFIX set,
# but they can also be run directly (e.g. from tests) — fall back to deriving
# the prefix from this file's location.
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- the sysctl key this module manages -----------------------------------
KRP_SYSCTL_KEY="net.ipv4.ip_local_reserved_ports"

# --- overridable external commands ----------------------------------------
# Reuse the same sysctl command knob as the role-based path.
: "${ONIONARMOR_SYSCTL_CMD:=sysctl}"

# --- overridable filesystem paths -----------------------------------------
# Drop-in lives in the same dir as the role-based managed files.
: "${ONIONARMOR_KRP_DROPIN_NAME:=99-onionarmor-reserved-ports.conf}"
: "${ONIONARMOR_KRP_STATE_DIR:=/var/lib/onionarmor/kernel-reserved-ports}"
: "${ONIONARMOR_KRP_PROC_FILE:=/proc/sys/net/ipv4/ip_local_reserved_ports}"

# --- torrc sources for --auto detection -----------------------------------
: "${ONIONARMOR_KRP_TOR_INSTANCES_DIR:=/etc/tor/instances}"
: "${ONIONARMOR_KRP_TOR_RUN_DIR:=/run/tor-instances}"
: "${ONIONARMOR_KRP_TORRC_ALL:=/etc/tor/torrc.all}"
: "${ONIONARMOR_KRP_TORRC:=/etc/tor/torrc}"

# Tor directives that open a (potentially loopback) listener.
KRP_TOR_DIRECTIVES="MetricsPort ControlPort SocksPort DNSPort TransPort HTTPTunnelPort"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_KRP_GREEN=$'\033[32m'; OA_KRP_YEL=$'\033[33m'; OA_KRP_RED=$'\033[31m'; OA_KRP_OFF=$'\033[0m'
else
  OA_KRP_GREEN=""; OA_KRP_YEL=""; OA_KRP_RED=""; OA_KRP_OFF=""
fi

# --- flag defaults --------------------------------------------------------
krp_set_defaults() {
  KRP_AUTO=0
  KRP_RANGES=""          # accumulated manual ranges, comma-joined "a-b,c-d"
  KRP_AUTO_BUFFER=0
  KRP_LISTEN_IP=""       # empty => all loopback
  KRP_DRY_RUN=0
  KRP_VERIFY=1
  KRP_CLUSTER_GAP=256    # ports within this gap fold into one compact range
  KRP_MIN_PORT=1024      # ignore well-known ports below this
  # "Explicitly set on the CLI" markers for the persisted detection filters, so
  # krp_load_apply_filters can tell `--min-port 1024` (an explicit default) from
  # "not passed at all" — a value-vs-default check cannot.
  KRP_LISTEN_IP_SET=0
  KRP_MIN_PORT_SET=0
  KRP_AUTO_BUFFER_SET=0
}

# krp_need_val <flag> <count>: die unless a value-taking flag was given an
# argument. Guards `shift 2` from "shift count out of range" on a trailing
# valueless flag (e.g. `--auto-buffer` at the end of the args), routing the
# error through our own die message instead of the shell builtin's.
krp_need_val() {
  [ "$2" -ge 2 ] || die "kernel-reserved-ports: $1 requires a value (try --help)"
}

# krp_parse_flags <args...>: populate KRP_* from the command line. Shared by all
# three actions (revert ignores the ones that don't apply to it).
krp_parse_flags() {
  krp_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --auto)              KRP_AUTO=1; shift ;;
      --reserved-range)    krp_need_val "$1" "$#"; krp_add_range "$2"; shift 2 ;;
      --reserved-range=*)  krp_add_range "${1#--reserved-range=}"; shift ;;
      --auto-buffer)       krp_need_val "$1" "$#"; KRP_AUTO_BUFFER=$2; KRP_AUTO_BUFFER_SET=1; shift 2 ;;
      --auto-buffer=*)     KRP_AUTO_BUFFER=${1#--auto-buffer=}; KRP_AUTO_BUFFER_SET=1; shift ;;
      --listen-ip)         krp_need_val "$1" "$#"; KRP_LISTEN_IP=$2; KRP_LISTEN_IP_SET=1; shift 2 ;;
      --listen-ip=*)       KRP_LISTEN_IP=${1#--listen-ip=}; KRP_LISTEN_IP_SET=1; shift ;;
      --cluster-gap)       krp_need_val "$1" "$#"; KRP_CLUSTER_GAP=$2; shift 2 ;;
      --cluster-gap=*)     KRP_CLUSTER_GAP=${1#--cluster-gap=}; shift ;;
      --min-port)          krp_need_val "$1" "$#"; KRP_MIN_PORT=$2; KRP_MIN_PORT_SET=1; shift 2 ;;
      --min-port=*)        KRP_MIN_PORT=${1#--min-port=}; KRP_MIN_PORT_SET=1; shift ;;
      --dry-run)           KRP_DRY_RUN=1; shift ;;
      --verify)            KRP_VERIFY=1; shift ;;
      --no-verify)         KRP_VERIFY=0; shift ;;
      -h|--help)           krp_usage; exit 0 ;;
      *)                   die "kernel-reserved-ports: unknown option: $1 (try --help)" ;;
    esac
  done
  krp_validate_flags
}

# krp_add_range <token>: append one or more comma-separated ranges to KRP_RANGES.
krp_add_range() {
  local tok=$1
  [ -n "$tok" ] || die "kernel-reserved-ports: --reserved-range needs a value (e.g. 48001-48249)"
  if [ -z "$KRP_RANGES" ]; then KRP_RANGES="$tok"; else KRP_RANGES="$KRP_RANGES,$tok"; fi
}

krp_validate_flags() {
  case "$KRP_AUTO_BUFFER" in (*[!0-9]*|"") die "kernel-reserved-ports: --auto-buffer must be a non-negative integer: $KRP_AUTO_BUFFER" ;; esac
  case "$KRP_CLUSTER_GAP" in (*[!0-9]*|"") die "kernel-reserved-ports: --cluster-gap must be a non-negative integer: $KRP_CLUSTER_GAP" ;; esac
  case "$KRP_MIN_PORT"     in (*[!0-9]*|"") die "kernel-reserved-ports: --min-port must be a non-negative integer: $KRP_MIN_PORT" ;; esac

  # Validate every manual range: a-b, 1<=a<=b<=65535.
  if [ -n "$KRP_RANGES" ]; then
    local r lo hi IFS=,
    # shellcheck disable=SC2086  # intentional comma-split of the ranges list
    for r in $KRP_RANGES; do
      [ -n "$r" ] || continue
      case "$r" in
        *-*) : ;;
        *)   die "kernel-reserved-ports: malformed --reserved-range '$r' — expected <start>-<end>" ;;
      esac
      lo=${r%-*}; hi=${r#*-}
      case "$lo$hi" in (*[!0-9]*|"") die "kernel-reserved-ports: non-numeric --reserved-range '$r'" ;; esac
      [ "$lo" -ge 1 ] && [ "$hi" -le 65535 ] \
        || die "kernel-reserved-ports: range '$r' out of bounds (1-65535)"
      [ "$lo" -le "$hi" ] \
        || die "kernel-reserved-ports: range '$r' has start > end"
    done
  fi
}

krp_usage() {
  cat <<'EOF'
onionarmor apply --module kernel-reserved-ports [options]   (also: audit, revert)

Reserve the relay's loopback service ports (MetricsPort/ControlPort/...) from the
kernel ephemeral source-port pool (net.ipv4.ip_local_reserved_ports), so an
outbound connection can never steal a port a tor instance needs to bind to.

OPTIONS
  --auto                 Auto-detect loopback tor ports from torrc files and
                         reserve the compact range(s) covering them. (headline)
  --reserved-range <r>   Reserve an explicit <start>-<end> range. Repeatable;
                         comma-separated lists accepted (48001-48249,29000-29299).
  --auto-buffer <N>      Widen each auto-detected range by N ports on each side
                         (headroom for fleet growth; default 0).
  --listen-ip <ip>       Restrict --auto to ports bound to this IP
                         (default: all loopback — 127.0.0.0/8 and ::1).
  --cluster-gap <N>      Auto-detect: fold ports within N of each other into one
                         range (default 256). Bands farther apart stay separate.
  --min-port <N>         Ignore detected ports below N (default 1024, well-known).
  --dry-run              Print the would-be drop-in + planned sysctl call, plus
                         before/after sysctl values. Changes nothing.
  --verify / --no-verify Post-apply verification (default: verify).
  -h, --help             This help.

At least one of --auto / --reserved-range is required for apply.
EOF
}

# --- paths ----------------------------------------------------------------
# krp_dropin_path -> the managed sysctl.d drop-in path.
krp_dropin_path() {
  printf '%s/%s\n' "$ONIONARMOR_SYSCTL_DIR" "$ONIONARMOR_KRP_DROPIN_NAME"
}

# krp_backup_path -> the revert backup path.
krp_backup_path() {
  printf '%s/backup.conf\n' "$ONIONARMOR_KRP_STATE_DIR"
}

# krp_filters_path -> the apply-time filter parameters state file.
krp_filters_path() {
  printf '%s/apply-filters.conf\n' "$ONIONARMOR_KRP_STATE_DIR"
}

# --- torrc discovery ------------------------------------------------------
# krp_torrc_sources: print every candidate torrc file path that exists, one per
# line, in a stable order.
krp_torrc_sources() {
  local d f
  d=$ONIONARMOR_KRP_TOR_INSTANCES_DIR
  if [ -d "$d" ]; then
    for f in "$d"/*/torrc; do [ -e "$f" ] && printf '%s\n' "$f"; done
  fi
  d=$ONIONARMOR_KRP_TOR_RUN_DIR
  if [ -d "$d" ]; then
    for f in "$d"/*.defaults; do [ -e "$f" ] && printf '%s\n' "$f"; done
  fi
  [ -f "$ONIONARMOR_KRP_TORRC_ALL" ] && printf '%s\n' "$ONIONARMOR_KRP_TORRC_ALL"
  [ -f "$ONIONARMOR_KRP_TORRC" ]     && printf '%s\n' "$ONIONARMOR_KRP_TORRC"
  return 0
}

# krp_parse_ports_file <file>: emit the loopback (or --listen-ip-matching) tor
# ports declared in <file>, one per line. Handles `ip:port`, `[ipv6]:port`, and
# bare `port` (which tor binds on 127.0.0.1).
krp_parse_ports_file() {
  local f=$1
  awk -v keys="$KRP_TOR_DIRECTIVES" -v listen="$KRP_LISTEN_IP" -v minport="$KRP_MIN_PORT" '
    BEGIN { n = split(keys, K, " "); for (i = 1; i <= n; i++) iskey[K[i]] = 1 }
    {
      line = $0
      sub(/#.*/, "", line)                 # strip trailing comments
      nf = split(line, F, /[ \t]+/)
      if (nf < 2) next
      # F[1] may be empty if the line had leading whitespace; find the directive.
      d = F[1]; spec = F[2]
      if (d == "" && nf >= 3) { d = F[2]; spec = F[3] }
      if (!(d in iskey)) next

      ip = ""; port = ""
      if (spec ~ /^\[.*\]:[0-9]+$/) {        # [ipv6]:port
        ip = spec; sub(/\]:[0-9]+$/, "", ip); sub(/^\[/, "", ip)
        port = spec; sub(/^.*\]:/, "", port)
      } else if (spec ~ /^[0-9.]+:[0-9]+$/) { # ipv4:port
        ip = spec; sub(/:[0-9]+$/, "", ip)
        port = spec; sub(/^.*:/, "", port)
      } else if (spec ~ /^[0-9]+$/) {         # bare port -> tor default loopback
        ip = "127.0.0.1"; port = spec
      } else {
        next                                  # unix:/path, "auto", etc.
      }

      if (port + 0 < minport) next
      isloop = (ip ~ /^127\./ || ip == "::1")
      if (listen != "") {
        if (ip != listen) next
      } else {
        if (!isloop) next
      }
      print port + 0
    }
  ' "$f"
}

# krp_detect_ports: print every discovered loopback tor port (one per line,
# unsorted, possibly with duplicates).
krp_detect_ports() {
  local f
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    krp_parse_ports_file "$f"
  done < <(krp_torrc_sources)
}

# --- range maths ----------------------------------------------------------
# krp_compact_ports <gap>: read ports (one per line) on stdin, emit "lo hi"
# range pairs, folding ports within <gap> of the running max into one range.
krp_compact_ports() {
  local gap=$1
  sort -n -u | awk -v gap="$gap" '
    NR == 1 { lo = $1; hi = $1; next }
    { if ($1 - hi <= gap) { hi = $1 } else { print lo, hi; lo = $1; hi = $1 } }
    END { if (NR > 0) print lo, hi }
  '
}

# krp_buffer_ranges <buf>: read "lo hi" pairs, widen each by <buf> on both sides,
# clamped to [1, 65535].
krp_buffer_ranges() {
  local buf=$1
  awk -v b="$buf" '{ lo = $1 - b; hi = $2 + b; if (lo < 1) lo = 1; if (hi > 65535) hi = 65535; print lo, hi }'
}

# krp_normalize_ranges: read "lo hi" pairs, emit a sorted, merged set (ranges
# that overlap or touch fold together).
krp_normalize_ranges() {
  sort -n -k1,1 -k2,2n | awk '
    NR == 1 { lo = $1; hi = $2; next }
    { if ($1 <= hi + 1) { if ($2 > hi) hi = $2 } else { print lo, hi; lo = $1; hi = $2 } }
    END { if (NR > 0) print lo, hi }
  '
}

# krp_manual_ranges_as_pairs: emit the manual KRP_RANGES as "lo hi" pairs.
krp_manual_ranges_as_pairs() {
  [ -n "$KRP_RANGES" ] || return 0
  local r lo hi IFS=,
  # shellcheck disable=SC2086  # intentional comma-split of the ranges list
  for r in $KRP_RANGES; do
    [ -n "$r" ] || continue
    lo=${r%-*}; hi=${r#*-}
    printf '%s %s\n' "$lo" "$hi"
  done
}

# krp_pairs_to_csv: read "lo hi" pairs, print one comma-joined "lo-hi,..." line.
krp_pairs_to_csv() {
  awk '{ printf "%s%d-%d", sep, $1, $2; sep = "," } END { if (NR > 0) printf "\n" }'
}

# krp_compute_ranges: the canonical reservation string for the current flags
# (auto-detected + buffered ranges unioned with the manual ranges, normalized).
# Prints empty when there is nothing to reserve.
krp_compute_ranges() {
  {
    if [ "$KRP_AUTO" -eq 1 ]; then
      krp_detect_ports | krp_compact_ports "$KRP_CLUSTER_GAP" | krp_buffer_ranges "$KRP_AUTO_BUFFER"
    fi
    krp_manual_ranges_as_pairs
  } | krp_normalize_ranges | krp_pairs_to_csv
}

# krp_csv_to_pairs <csv>: split a "lo-hi,lo-hi" reservation string to "lo hi"
# pairs (one per line). Empty input -> no output.
krp_csv_to_pairs() {
  [ -n "$1" ] || return 0
  # NB: trailing newline is required — `while read` drops a final line that has
  # none, which would silently empty a single-range reservation.
  printf '%s\n' "$1" | tr ',' '\n' | while IFS= read -r r; do
    [ -n "$r" ] || continue
    printf '%s %s\n' "${r%-*}" "${r#*-}"
  done
}

# krp_canon <csv>: canonical (sorted, merged) form of a reservation string, so
# the kernel's own re-ordering of ip_local_reserved_ports compares equal to ours.
krp_canon() {
  krp_csv_to_pairs "$1" | krp_normalize_ranges | krp_pairs_to_csv
}

# krp_uncovered_ports <csv>: read ports on stdin, print those NOT inside any
# range of the reservation <csv>.
krp_uncovered_ports() {
  awk -v csv="$1" '
    BEGIN {
      nr = split(csv, parts, ",")
      for (i = 1; i <= nr; i++) { split(parts[i], ab, "-"); lo[i] = ab[1] + 0; hi[i] = ab[2] + 0 }
    }
    {
      p = $1 + 0; cov = 0
      for (i = 1; i <= nr; i++) { if (p >= lo[i] && p <= hi[i]) { cov = 1; break } }
      if (!cov) print p
    }
  '
}

# --- drop-in render -------------------------------------------------------
# krp_dropin_value: the reservation string currently in the drop-in (empty if
# the file is absent or has no managed key).
krp_dropin_value() {
  local f; f=$(krp_dropin_path)
  [ -f "$f" ] || return 0
  sed -n "s/^[[:space:]]*$(printf '%s' "$KRP_SYSCTL_KEY" | sed 's/\./\\./g')[[:space:]]*=[[:space:]]*//p" "$f" | tail -1
}

# krp_render_dropin <csv>: emit the managed sysctl.d drop-in to stdout.
krp_render_dropin() {
  local ranges=$1
  printf '# Managed by onionarmor (module: kernel-reserved-ports) — do not edit by hand.\n'
  printf '# Removes the relay'\''s loopback service ports from the kernel ephemeral\n'
  printf '# source-port pool so an outbound connection can never steal a port a tor\n'
  printf '# instance needs to bind. See: onionarmor list-modules / the module README.\n'
  printf '# Revert with: onionarmor revert --module kernel-reserved-ports\n'
  printf '%s = %s\n' "$KRP_SYSCTL_KEY" "$ranges"
}

# krp_sysctl_runtime: the live value of the managed key (empty if unreadable).
krp_sysctl_runtime() {
  "$ONIONARMOR_SYSCTL_CMD" -n "$KRP_SYSCTL_KEY" 2>/dev/null || printf ''
}

# krp_save_apply_filters: persist the current filter parameters (listen-ip,
# min-port, auto-buffer) to the state file so audit --auto can reproduce the
# same port-detection query that apply used.
krp_save_apply_filters() {
  local filters_file; filters_file=$(krp_filters_path)
  mkdir -p "$ONIONARMOR_KRP_STATE_DIR" || die "cannot create $ONIONARMOR_KRP_STATE_DIR"
  cat > "$filters_file" <<EOF
# Managed by onionarmor (module: kernel-reserved-ports) — do not edit by hand.
# The filter parameters from the most recent 'apply --auto' invocation,
# persisted so 'audit --auto' can check coverage using the same detection scope.
KRP_LISTEN_IP=$KRP_LISTEN_IP
KRP_MIN_PORT=$KRP_MIN_PORT
KRP_AUTO_BUFFER=$KRP_AUTO_BUFFER
EOF
}

# krp_load_apply_filters: if the state file exists and the current invocation
# is in --auto mode, load the persisted filters for any parameters that are
# still at their default values. CLI overrides take precedence.
# This ensures audit --auto uses the same detection scope as the last apply.
krp_load_apply_filters() {
  local filters_file; filters_file=$(krp_filters_path)
  [ -f "$filters_file" ] || return 0
  [ "$KRP_AUTO" -eq 1 ] || return 0

  # Read saved values from the file. Initialize to defaults in case the file
  # doesn't contain all keys (forward compat with older state files).
  local saved_listen_ip="" saved_min_port=1024 saved_auto_buffer=0
  while IFS='=' read -r key val; do
    case "$key" in
      KRP_LISTEN_IP) saved_listen_ip=$val ;;
      KRP_MIN_PORT) saved_min_port=$val ;;
      KRP_AUTO_BUFFER) saved_auto_buffer=$val ;;
    esac
  done < <(grep '^KRP_' "$filters_file")

  # Apply saved values only for filters the user did NOT pass on this command's
  # CLI (tracked by krp_parse_flags markers). A value-vs-default check would be
  # wrong: `audit --auto --min-port 1024` explicitly asks for 1024 and must not
  # be overwritten by a persisted non-default. Use if/fi (not `cond && assign`):
  # a trailing `&&` that evaluates false would make this function return
  # non-zero and, as a bare call under `set -e` in audit.sh, abort the audit.
  # `return 0` is belt and suspenders for the same reason.
  if [ "$KRP_LISTEN_IP_SET" -eq 0 ]; then KRP_LISTEN_IP=$saved_listen_ip; fi
  if [ "$KRP_MIN_PORT_SET" -eq 0 ]; then KRP_MIN_PORT=$saved_min_port; fi
  if [ "$KRP_AUTO_BUFFER_SET" -eq 0 ]; then KRP_AUTO_BUFFER=$saved_auto_buffer; fi
  return 0
}
