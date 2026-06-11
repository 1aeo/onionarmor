# Test helper for the package-minimization module bats suite.
#
# Builds a throwaway sandbox: stub `dpkg-query` and `apt-get` that read/write a
# fake installed-package DB file (lines of "pkg<TAB>sizeKiB"), plus a sandbox
# role.conf. Fully offline; never touches the real host (no real apt/dpkg). We
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
  mkdir -p "$STUB"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_PM_STATE_DIR="$SB/var/lib/onionarmor/package-minimization"
  export ONIONARMOR_PM_ROLE_FILE="$SB/etc/onionarmor/role.conf"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  # Tests run non-interactively: auto-confirm yes unless a test overrides it.
  export ONIONARMOR_AUTO_CONFIRM=yes

  # Shrink the target set to a handful of packages the stub DB can model.
  export ONIONARMOR_PM_PACKAGES="gcc make gdb tcpdump strace"

  mkdir -p "$(dirname "$ONIONARMOR_PM_ROLE_FILE")"

  # Fake installed-package DB: one "pkg<TAB>sizeKiB" line per installed package.
  export PM_DB="$SB/dpkg-db"
  : > "$PM_DB"
  # Default size apt assigns to a freshly (re)installed package.
  export PM_DEFAULT_INSTALL_SIZE=2048

  _build_stubs
  export ONIONARMOR_PM_DPKG_QUERY="$STUB/dpkg-query"
  export ONIONARMOR_PM_APT="$STUB/apt-get"

  # Log of apt invocations, for assertions.
  export PM_APT_LOG="$SB/apt.log"
  : > "$PM_APT_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_pkg <name> <sizeKiB> : mark a package installed in the fake DB.
seed_pkg() {
  local name="$1" size="$2"
  # Remove any existing entry first, then append.
  if [ -f "$PM_DB" ]; then
    grep -v "^$name	" "$PM_DB" > "$PM_DB.tmp" 2>/dev/null || true
    mv "$PM_DB.tmp" "$PM_DB"
  fi
  printf '%s\t%s\n' "$name" "$size" >> "$PM_DB"
}

# set_role <role> : write a role=<role> line into the sandbox role.conf.
set_role() {
  printf 'role=%s\n' "$1" > "$ONIONARMOR_PM_ROLE_FILE"
}

# pkg_installed <name> : succeed iff the package is present in the fake DB.
pkg_installed() {
  grep -q "^$1	" "$PM_DB" 2>/dev/null
}

_build_stubs() {
  # dpkg-query stub: read the fake DB.
  #   dpkg-query -W -f '${Status}' pkg         -> "install ok installed" iff present
  #   dpkg-query -W -f '${Installed-Size}' pkg -> the size (KiB) iff present
  # Exits nonzero (like the real tool) for an unknown package.
  cat > "$STUB/dpkg-query" <<'EOF'
#!/bin/sh
DB="${PM_DB:?}"
fmt=""
pkg=""
while [ $# -gt 0 ]; do
  case "$1" in
    -W) shift ;;
    -f) fmt=$2; shift 2 ;;
    -f*) fmt=${1#-f}; shift ;;
    *) pkg=$1; shift ;;
  esac
done
line=$(grep "^$pkg	" "$DB" 2>/dev/null | head -1)
if [ -z "$line" ]; then
  # Unknown package: dpkg-query prints an error to stderr and exits nonzero.
  echo "dpkg-query: no packages found matching $pkg" >&2
  exit 1
fi
size=$(printf '%s' "$line" | cut -f2)
case "$fmt" in
  *'${Status}'*)         printf 'install ok installed' ;;
  *'${Installed-Size}'*) printf '%s' "$size" ;;
  *)                     printf '%s' "$size" ;;
esac
exit 0
EOF

  # apt-get stub: mutate the fake DB.
  #   apt-get remove -y  pkg...  -> delete those entries
  #   apt-get install -y pkg...  -> add those entries (default install size)
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
DB="${PM_DB:?}"
LOG="${PM_APT_LOG:-/dev/null}"
DEF="${PM_DEFAULT_INSTALL_SIZE:-1024}"
printf '%s\n' "$*" >> "$LOG"
op=$1; shift
# drop a leading -y if present
[ "$1" = "-y" ] && shift
case "$op" in
  remove)
    for p in "$@"; do
      grep -v "^$p	" "$DB" > "$DB.tmp" 2>/dev/null || true
      mv "$DB.tmp" "$DB"
    done
    ;;
  install)
    for p in "$@"; do
      grep -v "^$p	" "$DB" > "$DB.tmp" 2>/dev/null || true
      mv "$DB.tmp" "$DB"
      printf '%s\t%s\n' "$p" "$DEF" >> "$DB"
    done
    ;;
esac
exit 0
EOF

  chmod +x "$STUB"/*
}
