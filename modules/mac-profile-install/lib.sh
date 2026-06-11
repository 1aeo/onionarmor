# shellcheck shell=bash
# SC2034: the MAC_* flag defaults + colour vars set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/mac-profile-install/lib.sh — shared helpers for the
# mac-profile-install module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite can drive the whole module against a
# sandbox with stub binaries (aa-status, aa-enforce, sestatus, setenforce, ...),
# never touching the real host.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- distro detection source ----------------------------------------------
: "${ONIONARMOR_MAC_OS_RELEASE:=/etc/os-release}"

# --- overridable package managers -----------------------------------------
: "${ONIONARMOR_MAC_APT:=apt-get}"
: "${ONIONARMOR_MAC_DNF:=dnf}"

# --- overridable AppArmor tools + paths ------------------------------------
: "${ONIONARMOR_MAC_AA_STATUS:=aa-status}"
: "${ONIONARMOR_MAC_AA_ENFORCE:=aa-enforce}"
: "${ONIONARMOR_MAC_AA_DISABLE:=aa-disable}"
: "${ONIONARMOR_MAC_APPARMOR_D:=/etc/apparmor.d}"
# The tor profile filename under the apparmor.d directory.
: "${ONIONARMOR_MAC_TOR_PROFILE_NAME:=usr.bin.tor}"

# --- overridable SELinux tools + paths -------------------------------------
: "${ONIONARMOR_MAC_SESTATUS:=sestatus}"
: "${ONIONARMOR_MAC_SELINUX_CONFIG:=/etc/selinux/config}"
: "${ONIONARMOR_MAC_SETENFORCE:=setenforce}"

# --- GRUB (reuse the shared knob) + module state ---------------------------
# ONIONARMOR_GRUB_FILE defaults to /etc/default/grub in lib/common.sh.
: "${ONIONARMOR_MAC_STATE_DIR:=/var/lib/onionarmor/mac-profile-install}"
: "${ONIONARMOR_MAC_STATE_NAME:=applied.state}"
: "${ONIONARMOR_MAC_GRUB_BACKUP_NAME:=grub.backup}"

# Kernel cmdline tokens AppArmor needs to be active at boot.
: "${ONIONARMOR_MAC_GRUB_TOKENS:=apparmor=1 security=apparmor}"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_MAC_GREEN=$'\033[32m'; OA_MAC_YEL=$'\033[33m'; OA_MAC_RED=$'\033[31m'; OA_MAC_OFF=$'\033[0m'
else
  OA_MAC_GREEN=""; OA_MAC_YEL=""; OA_MAC_RED=""; OA_MAC_OFF=""
fi

# --- flag defaults --------------------------------------------------------
mac_set_defaults() {
  MAC_DRY_RUN=0
  MAC_VERIFY=1
}

mac_parse_flags() {
  mac_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)     MAC_DRY_RUN=1; shift ;;
      --verify)      MAC_VERIFY=1; shift ;;
      --no-verify)   MAC_VERIFY=0; shift ;;
      -h|--help)     mac_usage; exit 0 ;;
      *)             die "mac-profile-install: unknown option: $1 (try --help)" ;;
    esac
  done
}

mac_usage() {
  cat <<'EOF'
onionarmor apply --module mac-profile-install [options]   (also: audit, revert)

Install + enforce a Mandatory Access Control LSM appropriate to the distro:
AppArmor on Debian/Ubuntu, SELinux on RHEL/CentOS/Fedora. On AppArmor it also
sets the kernel cmdline (apparmor=1 security=apparmor) and puts the tor profile
(usr.bin.tor) into enforce mode; on SELinux it sets SELINUX=enforcing. Kernel
cmdline / enforcing changes can need a reboot or relabel — this module prints a
REBOOT REQUIRED notice and NEVER reboots or relabels automatically.

The failure mode of this module is "permissive, not broken": if a step cannot
complete, the host keeps running — it is just not yet under mandatory access
control. revert leaves the LSM installed and only relaxes the tor profile /
enforcing mode.

OPTIONS
  --dry-run               Print the plan. Changes nothing.
  --verify / --no-verify  Post-apply verification (default: verify).
  -h, --help              This help.
EOF
}

# --- state paths ----------------------------------------------------------
mac_state_path()       { printf '%s/%s\n' "$ONIONARMOR_MAC_STATE_DIR" "$ONIONARMOR_MAC_STATE_NAME"; }
mac_grub_backup_path() { printf '%s/%s\n' "$ONIONARMOR_MAC_STATE_DIR" "$ONIONARMOR_MAC_GRUB_BACKUP_NAME"; }
mac_tor_profile_path() { printf '%s/%s\n' "$ONIONARMOR_MAC_APPARMOR_D" "$ONIONARMOR_MAC_TOR_PROFILE_NAME"; }

# mac_detect_lsm: echo "apparmor" for Debian/Ubuntu, "selinux" for
# RHEL/CentOS/Fedora, based on ID / ID_LIKE in os-release. Dies if it can't tell.
mac_detect_lsm() {
  local id="" id_like="" line key val
  if [ -r "$ONIONARMOR_MAC_OS_RELEASE" ]; then
    while IFS= read -r line; do
      case "$line" in
        ID=*)      key=ID;      val=${line#ID=} ;;
        ID_LIKE=*) key=ID_LIKE; val=${line#ID_LIKE=} ;;
        *)         continue ;;
      esac
      # Strip surrounding quotes.
      val=${val#\"}; val=${val%\"}
      val=${val#\'}; val=${val%\'}
      case "$key" in
        ID)      id=$val ;;
        ID_LIKE) id_like=$val ;;
      esac
    done < "$ONIONARMOR_MAC_OS_RELEASE"
  fi

  local haystack=" $id $id_like "
  case "$haystack" in
    *" debian "*|*" ubuntu "*) printf 'apparmor\n'; return 0 ;;
  esac
  case "$haystack" in
    *" rhel "*|*" fedora "*|*" centos "*) printf 'selinux\n'; return 0 ;;
  esac
  die "mac-profile-install: cannot determine distro family from $ONIONARMOR_MAC_OS_RELEASE (ID='$id' ID_LIKE='$id_like') — expected debian/ubuntu (AppArmor) or rhel/fedora/centos (SELinux)"
}

# mac_skip_reload: true when ONIONARMOR_SKIP_RELOAD=yes (plan only; do not invoke
# apt/dnf/aa-enforce/setenforce — symmetric across apply + revert).
mac_skip_reload() { [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; }

# --- AppArmor helpers ------------------------------------------------------

# mac_aa_installed: true if the aa-status tool is available.
mac_aa_installed() { command -v "$ONIONARMOR_MAC_AA_STATUS" >/dev/null 2>&1; }

# mac_aa_tor_profile_exists: true if a tor AppArmor profile is present on disk.
mac_aa_tor_profile_exists() { [ -f "$(mac_tor_profile_path)" ]; }

# mac_aa_tor_mode: echo the tor profile's mode as reported by aa-status —
# "enforce", "complain", or "" if not loaded. aa-status output groups profiles
# under "N profiles are in enforce mode." / "... complain mode." headers, then
# lists each profile indented; we attribute each listed profile to the mode of
# the most recent header.
mac_aa_tor_mode() {
  mac_aa_installed || return 0
  "$ONIONARMOR_MAC_AA_STATUS" 2>/dev/null | awk -v prof="$ONIONARMOR_MAC_TOR_PROFILE_NAME" '
    /enforce mode/  { mode = "enforce"; next }
    /complain mode/ { mode = "complain"; next }
    /mode/          { mode = "" }
    {
      line = $0
      gsub(/^[[:space:]]+/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      if (line == prof || line == "/usr/bin/tor") { print mode; found = 1 }
    }
    END { if (!found) exit 0 }
  ' | tail -1
}

# mac_aa_active: true if aa-status reports the module is loaded/active. aa-status
# exits 0 when AppArmor is enabled.
mac_aa_active() {
  mac_aa_installed || return 1
  "$ONIONARMOR_MAC_AA_STATUS" >/dev/null 2>&1
}

# --- SELinux helpers -------------------------------------------------------

# mac_se_installed: true if the sestatus tool is available.
mac_se_installed() { command -v "$ONIONARMOR_MAC_SESTATUS" >/dev/null 2>&1; }

# mac_se_current_mode: echo the live mode from sestatus ("enforcing",
# "permissive", "disabled") or "" if sestatus is missing/unparsable.
mac_se_current_mode() {
  mac_se_installed || return 0
  "$ONIONARMOR_MAC_SESTATUS" 2>/dev/null \
    | awk -F: 'tolower($1) ~ /current mode/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2 }' \
    | tail -1
}

# mac_se_config_mode: echo the SELINUX= value from the selinux config, or "".
mac_se_config_mode() {
  [ -r "$ONIONARMOR_MAC_SELINUX_CONFIG" ] || return 0
  awk -F= '/^[[:space:]]*SELINUX=/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2 }' \
    "$ONIONARMOR_MAC_SELINUX_CONFIG" | tail -1
}

# mac_grub_has_tokens: true if every token in ONIONARMOR_MAC_GRUB_TOKENS already
# appears in the GRUB_CMDLINE_LINUX_DEFAULT line of the grub file.
mac_grub_has_tokens() {
  [ -r "$ONIONARMOR_GRUB_FILE" ] || return 1
  local cmdline tok
  # Extract the quoted value WITHOUT splitting on '=' (the tokens contain '='),
  # then drop the surrounding quotes so the LAST token (which abuts the closing
  # quote) still matches the space-padded test below.
  cmdline=$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT[[:space:]]*=//p' "$ONIONARMOR_GRUB_FILE" | tr -d '"')
  for tok in $ONIONARMOR_MAC_GRUB_TOKENS; do
    case " $cmdline " in *" $tok "*) : ;; *) return 1 ;; esac
  done
  return 0
}
