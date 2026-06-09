# shellcheck shell=bash
# SC2034: the colour vars + CHR_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/chrony-pinning/lib.sh — shared helpers for the chrony-pinning module's
# apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite can drive the whole module against a
# sandbox with stub binaries, never touching the real host.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_CHR_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_CHR_APT:=apt-get}"
: "${ONIONARMOR_CHR_CHRONYC:=chronyc}"
: "${ONIONARMOR_CHR_CHRONYD:=chronyd}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_CHR_SOURCES_DIR:=/etc/chrony/sources.d}"
: "${ONIONARMOR_CHR_CONF_DIR:=/etc/chrony/conf.d}"
: "${ONIONARMOR_CHR_MAIN_CONF:=/etc/chrony/chrony.conf}"
: "${ONIONARMOR_CHR_SOURCES_NAME:=onionarmor-stratum1.sources}"
: "${ONIONARMOR_CHR_CONF_NAME:=onionarmor-stratum1.conf}"
: "${ONIONARMOR_CHR_STATE_DIR:=/var/lib/onionarmor/chrony-pinning}"

: "${ONIONARMOR_CHR_SERVICE:=chrony.service}"
: "${ONIONARMOR_CHR_TIMESYNCD:=systemd-timesyncd.service}"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_CHR_GREEN=$'\033[32m'; OA_CHR_YEL=$'\033[33m'; OA_CHR_RED=$'\033[31m'; OA_CHR_OFF=$'\033[0m'
else
  OA_CHR_GREEN=""; OA_CHR_YEL=""; OA_CHR_RED=""; OA_CHR_OFF=""
fi

# The pinned source set — geographic + operator diversity so no single national
# time authority (or its compromise) can steer the relay's clock alone.
# 4 stratum-1 (US x2, EU, APAC) + 2 stratum-2 pool-member fallbacks. Overridable.
: "${ONIONARMOR_CHR_STRATUM1:=time-a-g.nist.gov|NIST (US)
tick.usno.navy.mil|USNO (US)
ptbtime1.ptb.de|PTB (EU/DE)
ntp.nict.jp|NICT (APAC/JP)}"
: "${ONIONARMOR_CHR_STRATUM2:=2.pool.ntp.org|pool fallback
3.pool.ntp.org|pool fallback}"
# Last-resort pool, used only when the pinned sources are unreachable.
: "${ONIONARMOR_CHR_POOL:=pool.ntp.org}"

# --- flag defaults --------------------------------------------------------
chr_set_defaults() {
  CHR_MASK_TIMESYNCD=1
  CHR_MAKESTEP="1.0 3"
  CHR_LEAPSECTZ="right/UTC"
  CHR_OFFSET_MS=50          # audit: max acceptable |offset| in milliseconds
  CHR_DRY_RUN=0
  CHR_VERIFY=1
}

chr_parse_flags() {
  chr_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --mask-timesyncd)     CHR_MASK_TIMESYNCD=1; shift ;;
      --no-mask-timesyncd)  CHR_MASK_TIMESYNCD=0; shift ;;
      --makestep)           CHR_MAKESTEP=${2:-}; shift 2 ;;
      --makestep=*)         CHR_MAKESTEP=${1#--makestep=}; shift ;;
      --leapsectz)          CHR_LEAPSECTZ=${2:-}; shift 2 ;;
      --leapsectz=*)        CHR_LEAPSECTZ=${1#--leapsectz=}; shift ;;
      --offset-ms)          CHR_OFFSET_MS=${2:-}; shift 2 ;;
      --offset-ms=*)        CHR_OFFSET_MS=${1#--offset-ms=}; shift ;;
      --dry-run)            CHR_DRY_RUN=1; shift ;;
      --verify)             CHR_VERIFY=1; shift ;;
      --no-verify)          CHR_VERIFY=0; shift ;;
      -h|--help)            chr_usage; exit 0 ;;
      *)                    die "chrony-pinning: unknown option: $1 (try --help)" ;;
    esac
  done
  case "$CHR_OFFSET_MS" in (*[!0-9]*|"") die "chrony-pinning: --offset-ms must be numeric: $CHR_OFFSET_MS" ;; esac
}

chr_usage() {
  cat <<'EOF'
onionarmor apply --module chrony-pinning [options]   (also: audit, revert)

Pin the relay's clock to a geographically + operationally diverse set of
stratum-1 NTP sources via chrony (NIST + USNO + PTB + NICT), with stratum-2 and
pool.ntp.org fallbacks, and mask systemd-timesyncd so only chrony disciplines
the clock. Accurate, hard-to-steer time is a Tor-consensus and TLS-validity
dependency.

OPTIONS
  --no-mask-timesyncd   Leave systemd-timesyncd alone (default: mask it).
  --makestep <v>        chrony makestep value (default: "1.0 3").
  --leapsectz <tz>      Leap-second source timezone (default: right/UTC).
  --offset-ms <n>       audit: max acceptable |offset| in ms (default: 50).
  --dry-run             Print the plan + rendered config, change nothing.
  --verify / --no-verify  Post-apply verification (default: verify).
  -h, --help            This help.
EOF
}

chr_sources_path() { printf '%s/%s\n' "$ONIONARMOR_CHR_SOURCES_DIR" "$ONIONARMOR_CHR_SOURCES_NAME"; }
chr_conf_path()    { printf '%s/%s\n' "$ONIONARMOR_CHR_CONF_DIR" "$ONIONARMOR_CHR_CONF_NAME"; }
chr_mainconf_backup() { printf '%s/chrony.conf.orig\n' "$ONIONARMOR_CHR_STATE_DIR"; }
chr_state_file()   { printf '%s/state\n' "$ONIONARMOR_CHR_STATE_DIR"; }

# chr_write_state: persist the current flag state so audit can read it back.
chr_write_state() {
  local state=$(chr_state_file)
  mkdir -p "$ONIONARMOR_CHR_STATE_DIR" || return 1
  printf 'CHR_MASK_TIMESYNCD=%s\n' "$CHR_MASK_TIMESYNCD" > "$state" || return 1
}

# chr_read_state: if a state file exists, source it to override flag defaults.
chr_read_state() {
  local state=$(chr_state_file)
  # shellcheck disable=SC1090
  [ -f "$state" ] && . "$state" || true
}

# chr_render_sources: emit the managed .sources file (server/pool lines only).
chr_render_sources() {
  printf '# Managed by onionarmor (module: chrony-pinning) — do not edit by hand.\n'
  printf '# Revert with: onionarmor revert --module chrony-pinning\n'
  printf '#\n'
  printf '# 4 diverse stratum-1 sources (geographic + operator diversity).\n'
  local host label
  while IFS='|' read -r host label; do
    [ -n "$host" ] || continue
    printf 'server %-22s iburst   # %s\n' "$host" "$label"
  done <<EOF
$ONIONARMOR_CHR_STRATUM1
EOF
  printf '#\n# 2 stratum-2 fallbacks (pool members).\n'
  while IFS='|' read -r host label; do
    [ -n "$host" ] || continue
    printf 'server %-22s iburst   # %s\n' "$host" "$label"
  done <<EOF
$ONIONARMOR_CHR_STRATUM2
EOF
  printf '#\n'
  printf '# Last-resort pool: chrony prefers the lower-stratum pinned sources, so\n'
  printf '# these only contribute when the pinned servers are unreachable.\n'
  printf 'pool %s iburst maxsources 3\n' "$ONIONARMOR_CHR_POOL"
}

# chr_render_conf: emit the managed conf.d directives.
chr_render_conf() {
  printf '# Managed by onionarmor (module: chrony-pinning) — do not edit by hand.\n'
  printf '# Revert with: onionarmor revert --module chrony-pinning\n'
  printf 'makestep %s\n' "$CHR_MAKESTEP"
  printf 'rtcsync\n'
  printf 'leapsectz %s\n' "$CHR_LEAPSECTZ"
}

# chr_chrony_installed: true if chrony's daemon or client is on PATH.
chr_chrony_installed() {
  command -v "$ONIONARMOR_CHR_CHRONYD" >/dev/null 2>&1 \
    || command -v "$ONIONARMOR_CHR_CHRONYC" >/dev/null 2>&1
}

# chr_main_reads <keyword> <dir>: true if the main chrony.conf already pulls in
# <dir> via a sourcedir/confdir/include line for <keyword>.
chr_main_reads() {
  local keyword=$1 dir=$2
  [ -f "$ONIONARMOR_CHR_MAIN_CONF" ] || return 1
  grep -E "^[[:space:]]*${keyword}[[:space:]]+" "$ONIONARMOR_CHR_MAIN_CONF" 2>/dev/null | grep -qF "$dir"
}

# chr_count_reachable_stratum1 <chronyc-sources-output>: count sources that are
# stratum 1, reachable (reach != 0) and not in the '?' (unreachable) state.
chr_count_reachable_stratum1() {
  printf '%s\n' "$1" | awk '
    # data rows start with a 2-char mode+state token like "^*", "^?", "^+".
    # mode char: = # ^ ; state char: - * + ? x ~ (note: - and ^ placed so they
    # are literals, not a range / negation, inside the bracket expressions).
    $1 ~ /^[=#^][-*+?x~]$/ {
      state = substr($1, 2, 1)
      stratum = $3
      reach = $5
      if (stratum == 1 && state != "?" && reach + 0 > 0) n++
    }
    END { print n + 0 }'
}

# chr_offset_seconds <chronyc-tracking-output>: echo the absolute "Last offset"
# in seconds (e.g. 0.000012), or empty if not found.
chr_offset_seconds() {
  printf '%s\n' "$1" | awk '
    /^Last offset/ {
      v = $4              # e.g. +0.000012345 (field after the colon+":")
      if (v == ":") v = $5
      gsub(/[+]/, "", v)
      sub(/^-/, "", v)
      print v
      exit
    }'
}
