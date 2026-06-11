# shellcheck shell=bash
# SC2034: the MAC_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/mac-profile-install/lib.sh — shared helpers for the
# mac-profile-install module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log/oa_status_*. EVERY external command and filesystem
# path is overridable via env so the bats suite can drive the whole module
# against a sandbox with stub binaries, never touching the real host (it must
# NEVER run a real apt/dnf/aa-enforce/setenforce/aa-status/sestatus).
#
# WHAT THIS MODULE DOES
#   Installs and enforces a Mandatory Access Control (MAC) layer for tor,
#   matching the host's distro family:
#     Debian / Ubuntu          -> AppArmor (install + enforce the tor profile)
#     RHEL / CentOS / Fedora /  -> SELinux  (install + SELINUX=enforcing +
#       Rocky / Alma                          setenforce 1)
#   Maps to the onionauditor `apparmor-selinux` category. LOW risk, but
#   recommended-OFF: enforcing a MAC layer can constrain a misconfigured tor, so
#   the operator opts in deliberately. No safety latch (it cannot lock the
#   operator out of the box — at worst it confines tor, which audit surfaces).

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

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_MAC_APT:=apt-get}"           # Debian/Ubuntu package manager
: "${ONIONARMOR_MAC_DNF:=dnf}"               # RHEL-family package manager
: "${ONIONARMOR_MAC_AA_ENFORCE:=aa-enforce}" # put an AppArmor profile in enforce
: "${ONIONARMOR_MAC_AA_COMPLAIN:=aa-complain}" # put a profile in complain mode
: "${ONIONARMOR_MAC_AA_STATUS:=aa-status}"   # report AppArmor state (audit)
: "${ONIONARMOR_MAC_SETENFORCE:=setenforce}" # flip the running SELinux mode
: "${ONIONARMOR_MAC_SESTATUS:=sestatus}"     # report SELinux state (audit)

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_MAC_OS_RELEASE:=/etc/os-release}"
: "${ONIONARMOR_MAC_APPARMOR_PROFILE:=/etc/apparmor.d/usr.bin.tor}"
: "${ONIONARMOR_MAC_SELINUX_CONFIG:=/etc/selinux/config}"

# --- status colours (green/yellow/red) ------------------------------------
# (lib/common.sh keeps its palette private; mirror the other modules.)
if [ -t 2 ]; then
  OA_MAC_GREEN=$'\033[32m'; OA_MAC_YEL=$'\033[33m'; OA_MAC_RED=$'\033[31m'; OA_MAC_OFF=$'\033[0m'
else
  OA_MAC_GREEN=""; OA_MAC_YEL=""; OA_MAC_RED=""; OA_MAC_OFF=""
fi

# --- flag defaults --------------------------------------------------------
mac_set_defaults() {
  MAC_DISTRO=""      # detected family: "debian" | "rhel" (empty -> autodetect)
  MAC_DRY_RUN=0
}

# mac_need_val <flag> <count>: die unless a value-taking flag was given an
# argument, guarding `shift 2` from a silent "shift count out of range" abort on
# a trailing valueless flag. Mirrors dns_need_val / bgp_need_val.
mac_need_val() {
  [ "$2" -ge 2 ] || die "mac-profile-install: $1 requires a value (try --help)"
}

# mac_parse_flags <args...>: populate MAC_* from the command line. Shared by all
# three actions (audit/revert ignore the ones that don't apply to them).
mac_parse_flags() {
  mac_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --distro)    mac_need_val "$1" "$#"; MAC_DISTRO=$2; shift 2 ;;
      --distro=*)  MAC_DISTRO=${1#--distro=}; shift ;;
      --dry-run)   MAC_DRY_RUN=1; shift ;;
      -h|--help)   mac_usage; exit 0 ;;
      *)           die "mac-profile-install: unknown option: $1 (try --help)" ;;
    esac
  done
  mac_resolve_distro
}

mac_usage() {
  cat <<'EOF'
onionarmor apply --module mac-profile-install [options]   (also: audit, revert)

Install and enforce a Mandatory Access Control (MAC) layer for tor, matched to
the host's distro family. LOW risk; recommended-OFF (opt in deliberately).

  Debian / Ubuntu          -> AppArmor: install apparmor + apparmor-utils, then
                              aa-enforce the tor profile (usr.bin.tor) if present.
  RHEL / CentOS / Fedora /  -> SELinux:  install policycoreutils +
    Rocky / Alma               selinux-policy-targeted, set SELINUX=enforcing in
                               the config, and `setenforce 1`.

OPTIONS
  --distro <debian|rhel>  Force the family instead of autodetecting from
                          /etc/os-release (useful for testing / cross-distro).
  --dry-run               Print the plan (detected distro, packages, profile /
                          enforce actions). Changes nothing.
  -h, --help              This help.
EOF
}

# --- distro detection -----------------------------------------------------
# mac_os_release_field <KEY>: echo the unquoted value of KEY= in os-release.
mac_os_release_field() {
  [ -r "$ONIONARMOR_MAC_OS_RELEASE" ] || return 0
  awk -F= -v k="$1" '
    $1 == k {
      v = $2
      gsub(/^"|"$/, "", v)
      print v
      exit
    }' "$ONIONARMOR_MAC_OS_RELEASE"
}

# mac_resolve_distro: fill MAC_DISTRO from /etc/os-release unless the operator
# pinned it with --distro. Classifies the ID / ID_LIKE into the two MAC families
# this module supports. Normalises to "debian" | "rhel"; dies on anything else
# so we never run the wrong package manager.
mac_resolve_distro() {
  if [ -z "$MAC_DISTRO" ]; then
    local id like
    id=$(mac_os_release_field ID)
    like=$(mac_os_release_field ID_LIKE)
    MAC_DISTRO=$(mac_classify_family "$id" "$like")
  fi
  case "$MAC_DISTRO" in
    debian|rhel) : ;;
    *) die "mac-profile-install: unsupported/undetected distro '${MAC_DISTRO:-?}' — pass --distro debian|rhel" ;;
  esac
}

# mac_classify_family <id> <id_like>: map an os-release ID / ID_LIKE pair to a
# MAC family. Debian/Ubuntu -> debian (AppArmor); the RHEL family -> rhel
# (SELinux). Empty when neither matches (the caller then dies with guidance).
mac_classify_family() {
  local id=$1 like=$2 token
  for token in $id $like; do
    case "$token" in
      debian|ubuntu)
        printf 'debian\n'; return 0 ;;
      rhel|centos|fedora|rocky|almalinux|alma)
        printf 'rhel\n'; return 0 ;;
    esac
  done
  printf '\n'
}

# --- AppArmor helpers -----------------------------------------------------
# mac_apparmor_profile_present: 0 if the tor AppArmor profile file exists.
mac_apparmor_profile_present() {
  [ -e "$ONIONARMOR_MAC_APPARMOR_PROFILE" ]
}

# mac_apparmor_tor_state: classify the running tor profile state from aa-status
# output. Echoes one of: enforce | complain | absent | unknown.
#   enforce  -> profile is loaded in enforce mode (green)
#   complain -> profile is loaded in complain mode (yellow)
#   absent   -> aa-status ran but no tor profile is loaded (red)
#   unknown  -> aa-status unavailable / unreadable (red, with guidance)
mac_apparmor_tor_state() {
  local out
  out=$("$ONIONARMOR_MAC_AA_STATUS" 2>/dev/null) || { printf 'unknown\n'; return 0; }
  # aa-status groups profiles under "enforce mode:" / "complain mode:" headers;
  # classify tor by the section it sits under (enforce wins over complain).
  if mac_aa_section_has "$out" 'enforce' 'tor'; then printf 'enforce\n'; return 0; fi
  if mac_aa_section_has "$out" 'complain' 'tor'; then printf 'complain\n'; return 0; fi
  printf 'absent\n'
}

# mac_aa_section_has <aa-status-output> <enforce|complain> <needle>: 0 if a
# profile line matching <needle> appears under the "<mode> mode:" section of
# aa-status output. bash 3.2 safe (awk state machine, no assoc arrays).
mac_aa_section_has() {
  printf '%s\n' "$1" | awk -v want="$2" -v needle="$3" '
    # aa-status prints a header line "N profiles are in enforce mode." then the
    # indented profile paths until the next such header. Track which section the
    # current profile lines belong to. (No colon in the header — match the words.)
    /profiles are in enforce mode/  { sec = "enforce";  next }
    /profiles are in complain mode/ { sec = "complain"; next }
    sec == want && index($0, needle) > 0 { found = 1 }
    END { exit found ? 0 : 1 }
  '
}

# --- SELinux helpers ------------------------------------------------------
# mac_selinux_runtime_mode: the live SELinux mode via sestatus, one of
# enforcing | permissive | disabled | unknown.
mac_selinux_runtime_mode() {
  local out mode
  out=$("$ONIONARMOR_MAC_SESTATUS" 2>/dev/null) || { printf 'unknown\n'; return 0; }
  mode=$(printf '%s\n' "$out" | awk -F: '/Current mode/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}')
  case "$mode" in
    enforcing|permissive) printf '%s\n' "$mode" ;;
    *)
      # No "Current mode" line (mode disabled) — fall back to the status line.
      if printf '%s\n' "$out" | grep -qiE 'SELinux status:[[:space:]]*disabled'; then
        printf 'disabled\n'
      else
        printf 'unknown\n'
      fi
      ;;
  esac
}

# mac_selinux_config_mode: the SELINUX= value persisted in the config file, or
# empty when the file/line is absent.
mac_selinux_config_mode() {
  [ -r "$ONIONARMOR_MAC_SELINUX_CONFIG" ] || { printf '\n'; return 0; }
  awk -F= '/^[[:space:]]*SELINUX[[:space:]]*=/{gsub(/[ \t]/,"",$2); print $2; exit}' \
    "$ONIONARMOR_MAC_SELINUX_CONFIG"
}

# mac_selinux_write_mode <enforcing|permissive>: rewrite the SELINUX= line in the
# config to <mode>, portably (awk rewrite + mv). Creates the line if the config
# exists without one. Idempotent at the caller (compare first). Dies on failure.
mac_selinux_write_mode() {
  local mode=$1 cfg=$ONIONARMOR_MAC_SELINUX_CONFIG tmp
  [ -f "$cfg" ] || die "mac-profile-install: SELinux config not found: $cfg (is selinux-policy installed?)"
  tmp="$cfg.tmp.$$"
  awk -v mode="$mode" '
    /^[[:space:]]*SELINUX[[:space:]]*=/ { print "SELINUX=" mode; seen = 1; next }
    { print }
    END { if (!seen) print "SELINUX=" mode }
  ' "$cfg" > "$tmp" || { rm -f "$tmp"; die "cannot rewrite $cfg"; }
  mv "$tmp" "$cfg" || { rm -f "$tmp"; die "cannot move $tmp -> $cfg"; }
}
