# shellcheck shell=bash
# SC2034: the colour vars + UU_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/unattended-upgrades/lib.sh — shared helpers for the
# unattended-upgrades module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite can drive the whole module against a
# sandbox with stub binaries, never touching the real host.

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
: "${ONIONARMOR_UU_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_UU_APT:=apt-get}"
: "${ONIONARMOR_UU_DPKG_QUERY:=dpkg-query}"
: "${ONIONARMOR_UU_APT_MARK:=apt-mark}"
: "${ONIONARMOR_UU_LSB_RELEASE:=lsb_release}"
: "${ONIONARMOR_UU_SHA256:=sha256sum}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_UU_APT_CONFD:=/etc/apt/apt.conf.d}"
: "${ONIONARMOR_UU_50_NAME:=50unattended-upgrades}"
: "${ONIONARMOR_UU_20_NAME:=20auto-upgrades}"
: "${ONIONARMOR_UU_LOG:=/var/log/unattended-upgrades/unattended-upgrades.log}"
: "${ONIONARMOR_UU_STATE_DIR:=/var/lib/onionarmor/unattended-upgrades}"
: "${ONIONARMOR_UU_OS_RELEASE:=/etc/os-release}"

# The systemd unit that actually runs the upgrades.
: "${ONIONARMOR_UU_SERVICE:=unattended-upgrades.service}"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_UU_GREEN=$'\033[32m'; OA_UU_YEL=$'\033[33m'; OA_UU_RED=$'\033[31m'; OA_UU_OFF=$'\033[0m'
else
  OA_UU_GREEN=""; OA_UU_YEL=""; OA_UU_RED=""; OA_UU_OFF=""
fi

# --- flag defaults --------------------------------------------------------
uu_set_defaults() {
  UU_DISTRO=""          # autodetected when empty (Debian / Ubuntu)
  UU_CODENAME=""        # autodetected when empty (bookworm / noble / ...)
  UU_REBOOT=1           # auto-reboot when an upgrade sets /run/reboot-required
  UU_REBOOT_TIME="03:00"
  UU_REBOOT_WITH_USERS=1  # headless fleet: reboot even if a session is open
  UU_DRY_RUN=0
}

# uu_parse_flags <args...>: populate UU_* from the command line. Shared by all
# three actions (audit/revert ignore the ones that don't apply to them).
uu_parse_flags() {
  uu_set_defaults
  uu_load_flags  # restore apply-time flags (if saved); CLI overrides below
  while [ $# -gt 0 ]; do
    case "$1" in
      --distro)              UU_DISTRO=${2:-}; shift 2 ;;
      --distro=*)            UU_DISTRO=${1#--distro=}; shift ;;
      --codename)            UU_CODENAME=${2:-}; shift 2 ;;
      --codename=*)          UU_CODENAME=${1#--codename=}; shift ;;
      --reboot)              UU_REBOOT=1; shift ;;
      --no-reboot)           UU_REBOOT=0; shift ;;
      --reboot-time)         UU_REBOOT_TIME=${2:-}; shift 2 ;;
      --reboot-time=*)       UU_REBOOT_TIME=${1#--reboot-time=}; shift ;;
      --reboot-with-users)   UU_REBOOT_WITH_USERS=1; shift ;;
      --no-reboot-with-users) UU_REBOOT_WITH_USERS=0; shift ;;
      --dry-run)             UU_DRY_RUN=1; shift ;;
      -h|--help)             uu_usage; exit 0 ;;
      *)                     die "unattended-upgrades: unknown option: $1 (try --help)" ;;
    esac
  done
  uu_resolve_distro
  uu_validate_flags
}

uu_validate_flags() {
  case "$UU_REBOOT_TIME" in
    [0-2][0-9]:[0-5][0-9]) : ;;
    *) die "unattended-upgrades: --reboot-time must be HH:MM (24h): $UU_REBOOT_TIME" ;;
  esac
}

# uu_resolve_distro: fill UU_DISTRO / UU_CODENAME from lsb_release (preferred)
# or /etc/os-release, unless the operator pinned them. UU_DISTRO is normalised
# to the apt origin id ("Debian" / "Ubuntu").
uu_resolve_distro() {
  if [ -z "$UU_DISTRO" ]; then
    UU_DISTRO=$("$ONIONARMOR_UU_LSB_RELEASE" -is 2>/dev/null || true)
  fi
  if [ -z "$UU_CODENAME" ]; then
    UU_CODENAME=$("$ONIONARMOR_UU_LSB_RELEASE" -cs 2>/dev/null || true)
  fi
  # Fall back to /etc/os-release when lsb_release is absent.
  if { [ -z "$UU_DISTRO" ] || [ -z "$UU_CODENAME" ]; } && [ -r "$ONIONARMOR_UU_OS_RELEASE" ]; then
    local id codename
    id=$(uu_os_release_field ID)
    codename=$(uu_os_release_field VERSION_CODENAME)
    [ -z "$UU_DISTRO" ] && [ -n "$id" ] && UU_DISTRO=$id
    [ -z "$UU_CODENAME" ] && [ -n "$codename" ] && UU_CODENAME=$codename
  fi
  # Normalise to the apt origin label capitalisation.
  case "$UU_DISTRO" in
    debian|Debian) UU_DISTRO="Debian" ;;
    ubuntu|Ubuntu) UU_DISTRO="Ubuntu" ;;
  esac
}

# uu_os_release_field <KEY>: echo the unquoted value of KEY= in os-release.
uu_os_release_field() {
  [ -r "$ONIONARMOR_UU_OS_RELEASE" ] || return 0
  awk -F= -v k="$1" '
    $1 == k {
      v = $2
      gsub(/^"|"$/, "", v)
      print v
      exit
    }' "$ONIONARMOR_UU_OS_RELEASE"
}

uu_usage() {
  cat <<'EOF'
onionarmor apply --module unattended-upgrades [options]   (also: audit, revert)

Turn on Debian/Ubuntu unattended security upgrades under the 1aeo fleet posture:
security-only origins, daily update + upgrade, and an automatic reboot at 03:00
ONLY when an upgrade flags one as required (kernel / libc).

OPTIONS (every fleet default is overridable)
  --distro <Debian|Ubuntu>   Override autodetected distribution.
  --codename <name>          Override autodetected release codename.
  --reboot / --no-reboot     Auto-reboot when /run/reboot-required appears (default: reboot).
  --reboot-time <HH:MM>      When to take the reboot (default: 03:00).
  --reboot-with-users        Reboot even with a logged-in session (default; headless fleet).
  --no-reboot-with-users     Defer the reboot while a user session is open.
  --dry-run                  Print the plan + rendered config, change nothing.
  -h, --help                 This help.
EOF
}

# uu_50_path / uu_20_path -> managed apt.conf.d file paths.
uu_50_path() { printf '%s/%s\n' "$ONIONARMOR_UU_APT_CONFD" "$ONIONARMOR_UU_50_NAME"; }
uu_20_path() { printf '%s/%s\n' "$ONIONARMOR_UU_APT_CONFD" "$ONIONARMOR_UU_20_NAME"; }

# uu_backup_path <basename> -> the state-dir backup path for a managed file.
uu_backup_path() { printf '%s/%s.orig\n' "$ONIONARMOR_UU_STATE_DIR" "$1"; }

# uu_flags_state_path -> the state file that records apply-time flags.
uu_flags_state_path() { printf '%s/apply-flags.state\n' "$ONIONARMOR_UU_STATE_DIR"; }

# uu_save_flags: persist the current UU_* flags to the state file so audit can
# re-render the posture with the same flags apply used.
uu_save_flags() {
  local state_file
  state_file=$(uu_flags_state_path)
  mkdir -p "$ONIONARMOR_UU_STATE_DIR" || return 1
  cat > "$state_file" <<EOF
UU_DISTRO=$UU_DISTRO
UU_CODENAME=$UU_CODENAME
UU_REBOOT=$UU_REBOOT
UU_REBOOT_TIME=$UU_REBOOT_TIME
UU_REBOOT_WITH_USERS=$UU_REBOOT_WITH_USERS
EOF
}

# uu_load_flags: source the apply-time flags from the state file (if present).
# Call after uu_set_defaults so defaults are in place for first-run audit.
uu_load_flags() {
  local state_file
  state_file=$(uu_flags_state_path)
  [ -f "$state_file" ] && . "$state_file" || true
}

# uu_origins_block: emit the Origins-Pattern entries for the resolved distro,
# one indented quoted line each. Security archives only — never -updates.
uu_origins_block() {
  case "$UU_DISTRO" in
    Debian)
      printf '        "origin=Debian,codename=${distro_codename},label=Debian-Security";\n'
      printf '        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";\n'
      ;;
    Ubuntu)
      printf '        "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";\n'
      printf '        "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";\n'
      printf '        "origin=UbuntuESM,archive=${distro_codename}-infra-security";\n'
      ;;
    *)
      die "unattended-upgrades: unsupported/undetected distro '${UU_DISTRO:-?}' — pass --distro Debian|Ubuntu"
      ;;
  esac
}

# uu_render_50: emit the managed 50unattended-upgrades to stdout.
uu_render_50() {
  local with_users reboot
  [ "$UU_REBOOT_WITH_USERS" -eq 1 ] && with_users="true" || with_users="false"
  [ "$UU_REBOOT" -eq 1 ] && reboot="true" || reboot="false"
  cat <<EOF
// Managed by onionarmor (module: unattended-upgrades) — do not edit by hand.
// Revert with: onionarmor revert --module unattended-upgrades
//
// Security archives only: the fleet pulls feature pockets deliberately,
// but security fixes must land unattended.
Unattended-Upgrade::Origins-Pattern {
$(uu_origins_block)
};

// Never auto-upgrade these (operator-pinned packages go here).
Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";

// Reboot ONLY when an upgrade sets /run/reboot-required (kernel / libc).
Unattended-Upgrade::Automatic-Reboot "$reboot";
Unattended-Upgrade::Automatic-Reboot-WithUsers "$with_users";
Unattended-Upgrade::Automatic-Reboot-Time "$UU_REBOOT_TIME";

Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::Mail "";
EOF
}

# uu_render_20: emit the managed 20auto-upgrades (the apt periodic schedule).
uu_render_20() {
  cat <<'EOF'
// Managed by onionarmor (module: unattended-upgrades) — do not edit by hand.
// Revert with: onionarmor revert --module unattended-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
}

# uu_checksum <path> -> a short checksum string for reporting, or "n/a".
uu_checksum() {
  local p=$1
  [ -f "$p" ] || { printf 'n/a\n'; return 0; }
  "$ONIONARMOR_UU_SHA256" "$p" 2>/dev/null | awk '{print substr($1,1,16)}' \
    || printf 'n/a\n'
}

# uu_pkg_installed <pkg> -> true if dpkg reports the package installed.
uu_pkg_installed() {
  local st
  st=$("$ONIONARMOR_UU_DPKG_QUERY" -W -f='${Status}' "$1" 2>/dev/null || true)
  case "$st" in *"install ok installed"*) return 0 ;; *) return 1 ;; esac
}

# uu_holds: print any apt holds (apt-mark showhold), one package per line.
uu_holds() {
  "$ONIONARMOR_UU_APT_MARK" showhold 2>/dev/null || true
}

# uu_last_run: echo the most recent log timestamp line from the
# unattended-upgrades log, or empty if none.
uu_last_run() {
  [ -f "$ONIONARMOR_UU_LOG" ] || return 0
  # Lines start with an ISO-ish "YYYY-MM-DD HH:MM:SS,mmm ..." stamp.
  grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$ONIONARMOR_UU_LOG" 2>/dev/null \
    | tail -1
}
