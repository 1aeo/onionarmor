# shellcheck shell=bash
# SC2034: the PM_* flag defaults + status colour vars set here are consumed by
# the apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/package-minimization/lib.sh — shared helpers for the
# package-minimization module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log/oa_status_*/oa_confirm. EVERY external command and
# filesystem path is overridable via env so the bats suite can drive the whole
# module against a sandbox with stub binaries (dpkg-query, apt-get), never
# touching the real host.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_PM_DPKG_QUERY:=dpkg-query}"
: "${ONIONARMOR_PM_APT:=apt-get}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_PM_ROLE_FILE:=/etc/onionarmor/role.conf}"
: "${ONIONARMOR_PM_STATE_DIR:=/var/lib/onionarmor/package-minimization}"
: "${ONIONARMOR_PM_REMOVED_NAME:=removed.list}"

# Target package set: build toolchain + debug tooling that a production relay
# does not need at runtime. Overridable so tests can shrink it. Reinstallable on
# demand, so removal is reversible.
: "${ONIONARMOR_PM_PACKAGES:=gcc g++ make cmake build-essential tcpdump nc netcat-openbsd netcat-traditional strace ltrace gdb python3-dev}"

# Default Installed-Size (KiB) assumed for a package reinstalled on revert, when
# we only know its name from the removed.list (apt has no size before install).
: "${ONIONARMOR_PM_DEFAULT_SIZE:=1024}"

# Roles that legitimately need a toolchain and must be SKIPPED (no removal).
: "${ONIONARMOR_PM_SKIP_ROLES:=build-host ci}"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_PM_GREEN=$'\033[32m'; OA_PM_YEL=$'\033[33m'; OA_PM_RED=$'\033[31m'; OA_PM_OFF=$'\033[0m'
else
  OA_PM_GREEN=""; OA_PM_YEL=""; OA_PM_RED=""; OA_PM_OFF=""
fi

# --- flag defaults --------------------------------------------------------
pm_set_defaults() {
  PM_DRY_RUN=0
  PM_VERIFY=1
  PM_ASSUME_YES=0
}

pm_parse_flags() {
  pm_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)            PM_DRY_RUN=1; shift ;;
      --yes|--assume-yes)   PM_ASSUME_YES=1; shift ;;
      --verify)             PM_VERIFY=1; shift ;;
      --no-verify)          PM_VERIFY=0; shift ;;
      -h|--help)            pm_usage; exit 0 ;;
      *)                    die "package-minimization: unknown option: $1 (try --help)" ;;
    esac
  done
}

pm_usage() {
  cat <<'EOF'
onionarmor apply --module package-minimization [options]   (also: audit, revert)

Remove the build toolchain + debug tooling (gcc/g++/make/cmake/build-essential,
tcpdump/nc/netcat, strace/ltrace/gdb, python3-dev) from a production relay. This
shrinks the attack surface: an attacker who lands a shell finds no compiler or
debugger to stage further tooling. Fully reversible — `revert` reinstalls the
exact set that was removed via apt.

Skipped automatically on hosts whose role is build-host or ci (they legitimately
need a toolchain). The detected role is printed in the output.

OPTIONS
  --yes, --assume-yes     Skip the interactive confirmation prompt.
  --dry-run               Print the removable packages + reclaimable size. Changes nothing.
  --verify / --no-verify  Post-apply: re-query each package is gone (default: verify).
  -h, --help              This help.
EOF
}

pm_removed_path() { printf '%s/%s\n' "$ONIONARMOR_PM_STATE_DIR" "$ONIONARMOR_PM_REMOVED_NAME"; }

# pm_role: echo the host role read from ONIONARMOR_PM_ROLE_FILE (a `role=<name>`
# line), or empty if the file is absent/unreadable or has no role line.
pm_role() {
  local f=$ONIONARMOR_PM_ROLE_FILE
  [ -r "$f" ] || return 0
  awk -F= '
    /^[[:space:]]*#/ { next }
    $1 ~ /^[[:space:]]*role[[:space:]]*$/ {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
      print $2; exit
    }
  ' "$f"
}

# pm_role_is_skip <role>: true if the role legitimately needs a toolchain and
# this module must SKIP (no removal). Empty/unset/other roles => not skip.
pm_role_is_skip() {
  local role=$1 r
  [ -n "$role" ] || return 1
  for r in $ONIONARMOR_PM_SKIP_ROLES; do
    [ "$role" = "$r" ] && return 0
  done
  return 1
}

# pm_pkg_installed <pkg>: true if dpkg reports "install ok installed".
pm_pkg_installed() {
  "$ONIONARMOR_PM_DPKG_QUERY" -W -f '${Status}' "$1" 2>/dev/null \
    | grep -q 'install ok installed'
}

# pm_pkg_size <pkg>: echo the Installed-Size in KiB (or 0 if unknown).
pm_pkg_size() {
  local sz
  sz=$("$ONIONARMOR_PM_DPKG_QUERY" -W -f '${Installed-Size}' "$1" 2>/dev/null || true)
  case "$sz" in (*[!0-9]*|"") sz=0 ;; esac
  printf '%s\n' "$sz"
}

# pm_human_kib <kib>: render a KiB integer as a human-friendly size.
pm_human_kib() {
  local kib=$1
  case "$kib" in (*[!0-9]*|"") kib=0 ;; esac
  if [ "$kib" -ge 1048576 ]; then
    awk -v k="$kib" 'BEGIN { printf "%.1f GiB\n", k/1048576 }'
  elif [ "$kib" -ge 1024 ]; then
    awk -v k="$kib" 'BEGIN { printf "%.1f MiB\n", k/1024 }'
  else
    printf '%s KiB\n' "$kib"
  fi
}

# pm_installed_targets: print "<pkg> <sizeKiB>" for each TARGET package that is
# currently installed, one per line.
pm_installed_targets() {
  local pkg
  for pkg in $ONIONARMOR_PM_PACKAGES; do
    if pm_pkg_installed "$pkg"; then
      printf '%s %s\n' "$pkg" "$(pm_pkg_size "$pkg")"
    fi
  done
}
