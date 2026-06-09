# Test helper for the unattended-upgrades module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (systemctl, apt-get, dpkg-query, apt-mark, lsb_release,
# sha256sum) so the suite is fully offline and never changes the real host. We
# use mktemp -d (not $BATS_TEST_TMPDIR) for compatibility with the older bats
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
  export STUB_STATE="$SB/systemctl-state"
  mkdir -p "$STUB" "$STUB_STATE/active" "$STUB_STATE/enabled" "$SB/pkgs"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_UU_APT_CONFD="$SB/etc/apt/apt.conf.d"
  export ONIONARMOR_UU_LOG="$SB/var/log/unattended-upgrades/unattended-upgrades.log"
  export ONIONARMOR_UU_STATE_DIR="$SB/var/lib/onionarmor/unattended-upgrades"
  export ONIONARMOR_UU_OS_RELEASE="$SB/etc/os-release"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_UU_APT_CONFD" "$(dirname "$ONIONARMOR_UU_OS_RELEASE")"

  # A realistic Debian bookworm os-release fallback (lsb_release stub overrides).
  printf 'ID=debian\nVERSION_CODENAME=bookworm\n' > "$ONIONARMOR_UU_OS_RELEASE"

  # Apt holds (apt-mark showhold) — empty by default.
  export FAKE_HOLDS="$SB/holds"
  : > "$FAKE_HOLDS"

  _build_stubs

  export ONIONARMOR_UU_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_UU_APT="$STUB/apt-get"
  export ONIONARMOR_UU_DPKG_QUERY="$STUB/dpkg-query"
  export ONIONARMOR_UU_APT_MARK="$STUB/apt-mark"
  export ONIONARMOR_UU_LSB_RELEASE="$STUB/lsb_release"
  export ONIONARMOR_UU_SHA256="$STUB/sha256sum"

  # Default distro reported by the lsb_release stub.
  export FAKE_DISTRO="Debian"
  export FAKE_CODENAME="bookworm"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# Mark a package as already installed (so apply skips the apt install path).
mark_installed() { : > "$SB/pkgs/$1"; }

_build_stubs() {
  # systemctl: stateful per-unit active/enabled under $STUB_STATE; logs verbs.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
S="${STUB_STATE:?}"; mkdir -p "$S/active" "$S/enabled"
verb=$1; shift
now=0; unit=""
for a in "$@"; do
  case "$a" in
    --now) now=1 ;;
    -*) ;;
    *) [ -z "$unit" ] && unit="$a" ;;
  esac
done
printf '%s %s now=%s\n' "$verb" "$unit" "$now" >> "$S/systemctl.log"
# Failure injection: FAKE_SYSTEMCTL_FAIL holds space-separated verbs that should
# return nonzero (as real systemctl does on a refused mask/restart/etc.).
case " ${FAKE_SYSTEMCTL_FAIL:-} " in
  *" $verb "*) echo "systemctl: $verb $unit failed (injected)" >&2; exit 1 ;;
esac
af="$S/active/$unit"; ef="$S/enabled/$unit"
case "$verb" in
  is-active)  cat "$af" 2>/dev/null || echo inactive ;;
  is-enabled) cat "$ef" 2>/dev/null || echo disabled ;;
  mask)       echo masked > "$ef";   [ "$now" = 1 ] && echo inactive > "$af" ;;
  unmask)     echo disabled > "$ef" ;;
  disable)    echo disabled > "$ef"; [ "$now" = 1 ] && echo inactive > "$af" ;;
  enable)     echo enabled > "$ef";  [ "$now" = 1 ] && echo active > "$af" ;;
  start)      echo active > "$af" ;;
  stop)       echo inactive > "$af" ;;
  restart|reload) echo active > "$af" ;;
esac
exit 0
EOF

  # apt-get: log, and on `install` create installed-package markers so a
  # following dpkg-query reports them present (models a successful install).
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
echo "$*" >> "${STUB:?}/apt-get.log"
sub=$1; shift 2>/dev/null || true
if [ "$sub" = "install" ]; then
  for a in "$@"; do
    case "$a" in -*) ;; *) : > "${SB:?}/pkgs/$a" ;; esac
  done
fi
exit 0
EOF

  # dpkg-query -W -f='${Status}' PKG: marker file => installed.
  cat > "$STUB/dpkg-query" <<'EOF'
#!/bin/sh
pkg=""
for a in "$@"; do
  case "$a" in -*|"-W"|"-f="*) ;; *) pkg="$a" ;; esac
done
if [ -n "$pkg" ] && [ -e "${SB:?}/pkgs/$pkg" ]; then
  printf 'install ok installed'
  exit 0
fi
printf 'unknown ok not-installed'
exit 1
EOF

  # apt-mark showhold: emit the contents of $FAKE_HOLDS.
  cat > "$STUB/apt-mark" <<'EOF'
#!/bin/sh
[ "$1" = "showhold" ] && cat "${FAKE_HOLDS:?}" 2>/dev/null
exit 0
EOF

  # lsb_release -is / -cs: report the FAKE_DISTRO / FAKE_CODENAME env values.
  cat > "$STUB/lsb_release" <<'EOF'
#!/bin/sh
case "$1" in
  -is) echo "${FAKE_DISTRO:-Debian}" ;;
  -cs) echo "${FAKE_CODENAME:-bookworm}" ;;
  *) exit 1 ;;
esac
exit 0
EOF

  # sha256sum: deterministic fake digest (cksum-derived) so audit can report it
  # without depending on a real sha256sum (absent on some dev machines).
  cat > "$STUB/sha256sum" <<'EOF'
#!/bin/sh
f=$1
if [ -f "$f" ]; then
  h=$(cksum "$f" | awk '{print $1}')
  printf '%016x  %s\n' "$h" "$f"
  exit 0
fi
exit 1
EOF

  chmod +x "$STUB"/*
}
