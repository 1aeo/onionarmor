# Test helper for the mac-profile-install module bats suite.
#
# Builds a throwaway sandbox with stub LSM tooling that reads/writes fake state
# files, so the suite drives the whole module offline and never touches the real
# host (no real apt/dnf/aa-*/setenforce):
#   aa-status   reports AppArmor "active" + the tor profile's mode from a sandbox
#               state file ($AA_PROFILE_STATE).
#   aa-enforce  flips that file to "enforce"; aa-disable flips it to "disabled".
#   apt-get     records the install into a log (no real package install).
#   sestatus    reports the current SELinux mode from $SE_MODE_STATE.
#   setenforce  flips $SE_MODE_STATE; dnf records the install into a log.
# We use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the older bats
# packaged on ubuntu-22.04.

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
  mkdir -p "$STUB"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_MAC_STATE_DIR="$SB/var/lib/onionarmor/mac-profile-install"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"

  export ONIONARMOR_MAC_OS_RELEASE="$SB/etc/os-release"
  export ONIONARMOR_GRUB_FILE="$SB/etc/default/grub"
  export ONIONARMOR_MAC_SELINUX_CONFIG="$SB/etc/selinux/config"
  export ONIONARMOR_MAC_APPARMOR_D="$SB/etc/apparmor.d"

  mkdir -p "$ONIONARMOR_MAC_APPARMOR_D" \
           "$(dirname "$ONIONARMOR_MAC_OS_RELEASE")" \
           "$(dirname "$ONIONARMOR_GRUB_FILE")" \
           "$(dirname "$ONIONARMOR_MAC_SELINUX_CONFIG")"

  # --- fake state files driven by the stubs ---
  export AA_PROFILE_STATE="$SB/aa-profile.state"   # enforce|complain|disabled|absent
  export SE_MODE_STATE="$SB/se-mode.state"         # enforcing|permissive|disabled
  export APT_LOG="$SB/apt.log"
  export DNF_LOG="$SB/dnf.log"
  : > "$APT_LOG"
  : > "$DNF_LOG"

  # Default fixtures: a default grub line and a permissive SELinux config so the
  # awk edits have something to rewrite.
  printf 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n' > "$ONIONARMOR_GRUB_FILE"
  printf 'SELINUX=permissive\nSELINUXTYPE=targeted\n' > "$ONIONARMOR_MAC_SELINUX_CONFIG"

  _build_stubs

  # Point the module's command knobs at the stubs.
  export ONIONARMOR_MAC_AA_STATUS="$STUB/aa-status"
  export ONIONARMOR_MAC_AA_ENFORCE="$STUB/aa-enforce"
  export ONIONARMOR_MAC_AA_DISABLE="$STUB/aa-disable"
  export ONIONARMOR_MAC_APT="$STUB/apt-get"
  export ONIONARMOR_MAC_SESTATUS="$STUB/sestatus"
  export ONIONARMOR_MAC_SETENFORCE="$STUB/setenforce"
  export ONIONARMOR_MAC_DNF="$STUB/dnf"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# set_debian: write a Debian/Ubuntu os-release fixture (=> AppArmor branch).
set_debian() {
  cat > "$ONIONARMOR_MAC_OS_RELEASE" <<'EOF'
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
EOF
}

# set_rhel: write a RHEL/CentOS/Fedora os-release fixture (=> SELinux branch).
set_rhel() {
  cat > "$ONIONARMOR_MAC_OS_RELEASE" <<'EOF'
ID=rocky
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
EOF
}

# seed_tor_profile [mode]: create the tor AppArmor profile file on disk and set
# its initial mode (default "complain"). Mode is "absent" => no file.
seed_tor_profile() {
  local mode="${1:-complain}"
  if [ "$mode" = "absent" ]; then
    rm -f "$ONIONARMOR_MAC_APPARMOR_D/usr.bin.tor"
    printf 'absent\n' > "$AA_PROFILE_STATE"
    return 0
  fi
  printf '# tor apparmor profile (test fixture)\n' > "$ONIONARMOR_MAC_APPARMOR_D/usr.bin.tor"
  printf '%s\n' "$mode" > "$AA_PROFILE_STATE"
}

# seed_selinux_mode <enforcing|permissive|disabled>: live mode for sestatus.
seed_selinux_mode() {
  printf '%s\n' "$1" > "$SE_MODE_STATE"
}

_build_stubs() {
  # aa-status: report AppArmor enabled, and (if loaded) the tor profile under the
  # matching "N profiles are in <mode> mode." header. Mode read from
  # $AA_PROFILE_STATE; "absent"/missing => tor profile not loaded.
  cat > "$STUB/aa-status" <<'EOF'
#!/bin/sh
STATE="${AA_PROFILE_STATE:-/dev/null}"
mode=absent
[ -f "$STATE" ] && mode=$(cat "$STATE" 2>/dev/null)
echo "apparmor module is loaded."
case "$mode" in
  enforce)
    echo "1 profiles are in enforce mode."
    echo "   usr.bin.tor"
    echo "0 profiles are in complain mode."
    ;;
  complain)
    echo "0 profiles are in enforce mode."
    echo "1 profiles are in complain mode."
    echo "   usr.bin.tor"
    ;;
  *)
    echo "0 profiles are in enforce mode."
    echo "0 profiles are in complain mode."
    ;;
esac
exit 0
EOF

  # aa-enforce <profile>: flip the tor profile state to enforce.
  cat > "$STUB/aa-enforce" <<'EOF'
#!/bin/sh
STATE="${AA_PROFILE_STATE:?}"
printf 'enforce\n' > "$STATE"
echo "Setting $1 to enforce mode."
exit 0
EOF

  # aa-disable <profile>: flip the tor profile state to disabled.
  cat > "$STUB/aa-disable" <<'EOF'
#!/bin/sh
STATE="${AA_PROFILE_STATE:?}"
printf 'disabled\n' > "$STATE"
echo "Disabling $1."
exit 0
EOF

  # apt-get: record the install args; do not install anything.
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${APT_LOG:-/dev/null}"
exit 0
EOF

  # sestatus: report the current SELinux mode from $SE_MODE_STATE (default
  # permissive).
  cat > "$STUB/sestatus" <<'EOF'
#!/bin/sh
STATE="${SE_MODE_STATE:-/dev/null}"
mode=permissive
[ -f "$STATE" ] && mode=$(cat "$STATE" 2>/dev/null)
echo "SELinux status:                 enabled"
echo "Current mode:                   $mode"
exit 0
EOF

  # setenforce <0|1|Enforcing|Permissive>: flip $SE_MODE_STATE.
  cat > "$STUB/setenforce" <<'EOF'
#!/bin/sh
STATE="${SE_MODE_STATE:?}"
case "$1" in
  1|Enforcing|enforcing)   printf 'enforcing\n'  > "$STATE" ;;
  0|Permissive|permissive) printf 'permissive\n' > "$STATE" ;;
esac
exit 0
EOF

  # dnf: record the install args; do not install anything.
  cat > "$STUB/dnf" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${DNF_LOG:-/dev/null}"
exit 0
EOF

  chmod +x "$STUB"/*
}
