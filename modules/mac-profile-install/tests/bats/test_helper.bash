# Test helper for the mac-profile-install module bats suite.
#
# Builds a throwaway sandbox that NEVER touches the real host:
#   * a fake /etc/os-release (Debian or RHEL, controllable per test),
#   * stub apt-get / dnf that only record their `install` calls to a log,
#   * stub aa-enforce / aa-complain that flip a controllable AppArmor state file,
#   * a stub aa-status that renders that state in real aa-status section layout,
#   * stub setenforce / sestatus over a controllable SELinux runtime-mode file,
#   * a sandbox /etc/selinux/config and a sandbox apparmor profile path.
# All ONIONARMOR_MAC_* are overridden into the sandbox. mktemp -d (not
# $BATS_TEST_TMPDIR) for ubuntu-22.04's older bats.

setup() {
  MOD_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export MOD_ROOT
  REPO_ROOT="$(cd "$MOD_ROOT/../.." && pwd)"
  export REPO_ROOT
  export ONIONARMOR_PREFIX="$REPO_ROOT"

  APPLY="$MOD_ROOT/apply.sh"
  AUDIT="$MOD_ROOT/audit.sh"
  REVERT="$MOD_ROOT/revert.sh"
  export APPLY AUDIT REVERT

  SB="$(mktemp -d)"
  export SB
  STUB="$SB/stubs"
  export STUB
  mkdir -p "$STUB" "$SB/etc/selinux"

  # --- sandbox paths the module reads/writes ---
  export ONIONARMOR_MAC_OS_RELEASE="$SB/etc/os-release"
  export ONIONARMOR_MAC_APPARMOR_PROFILE="$SB/etc/apparmor.d/usr.bin.tor"
  export ONIONARMOR_MAC_SELINUX_CONFIG="$SB/etc/selinux/config"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"

  # --- controllable stub state files ---
  export INSTALL_LOG="$SB/install.log"; : > "$INSTALL_LOG"
  export ACTION_LOG="$SB/action.log";   : > "$ACTION_LOG"
  # AppArmor: tor profile state, one of enforce|complain|absent (default absent).
  export AA_TOR_STATE="$SB/aa-tor-state"; printf 'absent\n' > "$AA_TOR_STATE"
  # SELinux running mode, one of enforcing|permissive|disabled (default disabled).
  export SE_RUNMODE="$SB/se-runmode"; printf 'disabled\n' > "$SE_RUNMODE"

  _build_stubs
  export ONIONARMOR_MAC_APT="$STUB/apt-get"
  export ONIONARMOR_MAC_DNF="$STUB/dnf"
  export ONIONARMOR_MAC_AA_ENFORCE="$STUB/aa-enforce"
  export ONIONARMOR_MAC_AA_COMPLAIN="$STUB/aa-complain"
  export ONIONARMOR_MAC_AA_STATUS="$STUB/aa-status"
  export ONIONARMOR_MAC_SETENFORCE="$STUB/setenforce"
  export ONIONARMOR_MAC_SESTATUS="$STUB/sestatus"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# --- os-release fixtures --------------------------------------------------
seed_os_release_debian() {
  cat > "$ONIONARMOR_MAC_OS_RELEASE" <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
ID=debian
VERSION_CODENAME=bookworm
EOF
}

seed_os_release_ubuntu() {
  cat > "$ONIONARMOR_MAC_OS_RELEASE" <<'EOF'
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=noble
EOF
}

seed_os_release_rhel() {
  cat > "$ONIONARMOR_MAC_OS_RELEASE" <<'EOF'
NAME="Rocky Linux"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
EOF
}

# --- selinux config fixtures ----------------------------------------------
# seed_selinux_config <enforcing|permissive|disabled> : write a stock config.
seed_selinux_config() {
  cat > "$ONIONARMOR_MAC_SELINUX_CONFIG" <<EOF
# This file controls the state of SELinux on the system.
SELINUX=$1
SELINUXTYPE=targeted
EOF
}

# --- AppArmor profile + state knobs ---------------------------------------
seed_apparmor_profile() {
  mkdir -p "$(dirname "$ONIONARMOR_MAC_APPARMOR_PROFILE")"
  printf '# stub tor apparmor profile\n/usr/bin/tor {\n}\n' > "$ONIONARMOR_MAC_APPARMOR_PROFILE"
}
set_aa_tor_state() { printf '%s\n' "$1" > "$AA_TOR_STATE"; }
set_se_runmode()   { printf '%s\n' "$1" > "$SE_RUNMODE"; }

# config_selinux_mode : read back the persisted SELINUX= value from the sandbox.
config_selinux_mode() {
  awk -F= '/^[[:space:]]*SELINUX[[:space:]]*=/{gsub(/[ \t]/,"",$2);print $2;exit}' \
    "$ONIONARMOR_MAC_SELINUX_CONFIG"
}

_build_stubs() {
  # apt-get / dnf: record an "install ..." line; succeed.
  for pm in apt-get dnf; do
    cat > "$STUB/$pm" <<EOF
#!/bin/sh
if [ "\$1" = install ]; then printf '$pm %s\\n' "\$*" >> "\$INSTALL_LOG"; fi
exit 0
EOF
  done

  # aa-enforce <profile>: record + flip the tor state to enforce.
  cat > "$STUB/aa-enforce" <<'EOF'
#!/bin/sh
printf 'aa-enforce %s\n' "$*" >> "$ACTION_LOG"
printf 'enforce\n' > "$AA_TOR_STATE"
exit 0
EOF

  # aa-complain <profile>: record + flip the tor state to complain.
  cat > "$STUB/aa-complain" <<'EOF'
#!/bin/sh
printf 'aa-complain %s\n' "$*" >> "$ACTION_LOG"
printf 'complain\n' > "$AA_TOR_STATE"
exit 0
EOF

  # aa-status: render real aa-status section layout from $AA_TOR_STATE.
  cat > "$STUB/aa-status" <<'EOF'
#!/bin/sh
st=$(cat "$AA_TOR_STATE" 2>/dev/null || echo absent)
echo "apparmor module is loaded."
case "$st" in
  enforce)
    echo "2 profiles are in enforce mode."
    echo "   /usr/bin/man"
    echo "   /usr/bin/tor"
    echo "0 profiles are in complain mode."
    ;;
  complain)
    echo "1 profiles are in enforce mode."
    echo "   /usr/bin/man"
    echo "1 profiles are in complain mode."
    echo "   /usr/bin/tor"
    ;;
  *)
    echo "1 profiles are in enforce mode."
    echo "   /usr/bin/man"
    echo "0 profiles are in complain mode."
    ;;
esac
exit 0
EOF

  # setenforce <0|1>: record + flip the running SELinux mode.
  cat > "$STUB/setenforce" <<'EOF'
#!/bin/sh
printf 'setenforce %s\n' "$*" >> "$ACTION_LOG"
case "$1" in
  1) printf 'enforcing\n'  > "$SE_RUNMODE" ;;
  0) printf 'permissive\n' > "$SE_RUNMODE" ;;
esac
exit 0
EOF

  # sestatus: render the running mode from $SE_RUNMODE.
  cat > "$STUB/sestatus" <<'EOF'
#!/bin/sh
mode=$(cat "$SE_RUNMODE" 2>/dev/null || echo disabled)
if [ "$mode" = disabled ]; then
  echo "SELinux status:                 disabled"
  exit 0
fi
echo "SELinux status:                 enabled"
echo "SELinuxfs mount:                /sys/fs/selinux"
echo "Current mode:                   $mode"
echo "Policy from config file:        targeted"
exit 0
EOF

  chmod +x "$STUB"/*
}
