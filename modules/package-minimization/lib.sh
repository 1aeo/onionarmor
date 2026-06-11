# shellcheck shell=bash
# SC2034: the PKG_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/package-minimization/lib.sh — shared helpers for the
# package-minimization module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log/oa_status_* and lib/role.sh for host_role_read.
# EVERY external command and filesystem path is overridable via env so the bats
# suite drives the module against a sandbox with stub dpkg-query/apt-get, never
# touching the real host (it must NEVER run a real apt/dpkg unstubbed).
#
# WHAT THIS MODULE DOES
#   Removes a fixed set of build/debug/network-analysis tools that have no place
#   on a hardened Tor relay — compilers, debuggers, packet sniffers, tracers.
#   Each expands the local attack surface and aids post-exploitation (compile a
#   rootkit in place, sniff traffic, trace a running tor). This module is LOW
#   risk but RECOMMENDED-OFF by default: removal is destructive and requires the
#   operator's explicit `--confirm`. It maps to the onionauditor
#   `package-hygiene` category. A `build-host` role legitimately needs these
#   toolchains, so the module SKIPS removal entirely on that role.

# --- locate + source the shared common.sh + role.sh -----------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"
# shellcheck source=../../lib/role.sh
. "$ONIONARMOR_PREFIX/lib/role.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_PKG_DPKG_QUERY:=dpkg-query}"
: "${ONIONARMOR_PKG_APT:=apt-get}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_PKG_STATE_DIR:=/var/lib/onionarmor/package-minimization}"

# --- overridable policy knobs ---------------------------------------------
# The role on which removal is skipped (a build host needs toolchains).
: "${ONIONARMOR_PKG_SKIP_ROLE:=build-host}"
# The set of packages this module removes. Space/newline separated; overridable
# so the bats suite can shrink it and so operators can extend it. Kept as the
# published default policy, not a per-run flag.
: "${ONIONARMOR_PKG_REMOVE_LIST:=gcc g++ make cmake build-essential tcpdump nc netcat-openbsd netcat-traditional strace ltrace gdb python3-dev}"

# --- "critical" debug tools: their presence is RED in audit ---------------
# The rest are merely YELLOW. These are the ones most directly useful to an
# attacker who already has a shell (compile, debug a live tor, sniff, trace).
PKG_CRIT_TOOLS="gcc gdb tcpdump strace"

# --- flag defaults --------------------------------------------------------
pkg_set_defaults() {
  PKG_DRY_RUN=0
  PKG_CONFIRM=0
}

# pkg_need_val <flag> <count>: die unless a value-taking flag was given an
# argument, guarding `shift 2` from a silent "shift count out of range" abort on
# a trailing valueless flag. Mirrors kh_need_val / dns_need_val. (No value-taking
# flags ship today, but the helper is defined per the module contract.)
pkg_need_val() {
  [ "$2" -ge 2 ] || die "package-minimization: $1 requires a value (try --help)"
}

# pkg_parse_flags <args...>: populate PKG_* from the command line. Shared by all
# three actions (audit/revert ignore the ones that don't apply to them).
pkg_parse_flags() {
  pkg_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)  PKG_DRY_RUN=1; shift ;;
      --confirm)  PKG_CONFIRM=1; shift ;;
      -h|--help)  pkg_usage; exit 0 ;;
      *)          die "package-minimization: unknown option: $1 (try --help)" ;;
    esac
  done
}

pkg_usage() {
  cat <<'EOF'
onionarmor apply --module package-minimization [options]   (also: audit, revert)

Remove build/debug/network-analysis tools that have no place on a hardened Tor
relay (compilers, debuggers, packet sniffers, tracers). They expand the local
attack surface and aid post-exploitation. LOW risk but RECOMMENDED-OFF by
default: removal is destructive and is REFUSED unless --confirm is passed.

Removable packages (override with ONIONARMOR_PKG_REMOVE_LIST):
  gcc g++ make cmake build-essential tcpdump nc netcat-openbsd
  netcat-traditional strace ltrace gdb python3-dev

Only packages that are actually installed are touched. On a host whose role
(/etc/onionarmor/role.conf) is 'build-host', removal is SKIPPED entirely.

OPTIONS
  --dry-run   List which removable packages are present and the disk space that
              would be reclaimed. Changes nothing. Exits 0.
  --confirm   Actually purge the present removable packages (apt-get purge -y).
              Without this (and without --dry-run) apply REFUSES to remove
              anything, so packages can never be stripped silently.
  -h, --help  This help.
EOF
}

# --- paths ----------------------------------------------------------------
# pkg_state_file -> the record of what this module removed (for revert).
pkg_state_file() {
  printf '%s/removed.list\n' "$ONIONARMOR_PKG_STATE_DIR"
}

# --- package queries (read-only; all via the overridable dpkg-query) ------
# pkg_remove_list: emit the configured removable packages, one per line. Folds
# any whitespace (spaces or newlines in the override) into single tokens.
pkg_remove_list() {
  printf '%s\n' "$ONIONARMOR_PKG_REMOVE_LIST" | tr ' \t' '\n\n' | while read -r p; do
    [ -n "$p" ] && printf '%s\n' "$p"
  done
}

# pkg_is_installed <pkg>: true iff dpkg-query reports the package state as
# 'installed'. Read-only.
pkg_is_installed() {
  local st
  st=$("$ONIONARMOR_PKG_DPKG_QUERY" -W -f '${db:Status-Status}' "$1" 2>/dev/null || printf '')
  [ "$st" = "installed" ]
}

# pkg_present_list: emit the subset of the removable list that is currently
# installed, one per line. The ONLY packages this module ever acts on.
pkg_present_list() {
  pkg_remove_list | while read -r p; do
    [ -n "$p" ] || continue
    if pkg_is_installed "$p"; then printf '%s\n' "$p"; fi
  done
}

# pkg_installed_size_kib <pkg>: the package's installed size in KiB (0 if the
# query yields nothing or a non-numeric value). dpkg's Installed-Size is KiB.
pkg_installed_size_kib() {
  local s
  s=$("$ONIONARMOR_PKG_DPKG_QUERY" -W -f '${Installed-Size}' "$1" 2>/dev/null || printf '')
  case "$s" in
    ''|*[!0-9]*) printf '0' ;;
    *)           printf '%s' "$s" ;;
  esac
}

# pkg_reclaim_kib <pkg-list-on-stdin>: sum installed sizes (KiB) of the packages
# read from stdin, one per line.
pkg_reclaim_kib() {
  local total=0 p sz
  while read -r p; do
    [ -n "$p" ] || continue
    sz=$(pkg_installed_size_kib "$p")
    total=$((total + sz))
  done
  printf '%s\n' "$total"
}

# pkg_human_kib <kib>: render a KiB count as a rough human string (KiB/MiB).
pkg_human_kib() {
  local k=$1
  if [ "$k" -ge 1024 ]; then
    printf '%s MiB (%s KiB)\n' "$((k / 1024))" "$k"
  else
    printf '%s KiB\n' "$k"
  fi
}

# pkg_is_crit <pkg>: true iff <pkg> is one of the "critical" debug tools whose
# presence makes audit RED rather than YELLOW.
pkg_is_crit() {
  case " $PKG_CRIT_TOOLS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# pkg_skip_role: the host's declared role if it equals ONIONARMOR_PKG_SKIP_ROLE,
# else empty. Used to short-circuit removal on a build host.
pkg_skip_role() {
  local role
  role=$(host_role_read)
  if [ -n "$role" ] && [ "$role" = "$ONIONARMOR_PKG_SKIP_ROLE" ]; then
    printf '%s' "$role"
  fi
}
