# Test helper for the package-minimization module bats suite.
#
# Builds a throwaway sandbox with:
#   - a stub `dpkg-query` that reports a controllable installed set + installed
#     sizes (KiB) through env vars (PKG_INSTALLED, PKG_SIZE_<pkg>),
#   - a stub `apt-get` that records its purge/install args to a log instead of
#     touching the host,
#   - a sandboxed ONIONARMOR_ETC_DIR holding role.conf,
#   - a sandboxed state dir + audit log.
# Fully offline; never runs real apt/dpkg. mktemp -d (not $BATS_TEST_TMPDIR) for
# ubuntu-22.04's older bats.

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
  export ONIONARMOR_ETC_DIR="$SB/etc/onionarmor"
  export ONIONARMOR_PKG_STATE_DIR="$SB/var/lib/onionarmor/package-minimization"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_ETC_DIR"

  # Never block on an interactive confirm prompt; tests opt in explicitly.
  export ONIONARMOR_AUTO_CONFIRM="no"

  # The fake "installed" set + per-package sizes (KiB) the dpkg stub reports.
  # Tests mutate these before invoking the module.
  export PKG_INSTALLED=""
  export PKG_DB="$SB/dpkg-db"
  : > "$PKG_DB"

  _build_stubs
  export ONIONARMOR_PKG_DPKG_QUERY="$STUB/dpkg-query"
  export ONIONARMOR_PKG_APT="$STUB/apt-get"
  export STUB_APT_LOG="$SB/apt.log"
  : > "$STUB_APT_LOG"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# install_pkg <pkg> [size-kib] : mark a package installed in the fake dpkg db.
install_pkg() {
  local p=$1 sz=${2:-100}
  printf '%s %s\n' "$p" "$sz" >> "$PKG_DB"
}

# set_role <role> : write /etc/onionarmor/role.conf in the sandbox.
set_role() {
  printf 'role=%s\n' "$1" > "$ONIONARMOR_ETC_DIR/role.conf"
}

# apt_purged <pkg> : true iff the apt stub recorded a purge of <pkg>.
apt_purged() {
  grep -q "purge .*\b$1\b" "$STUB_APT_LOG"
}

_build_stubs() {
  # dpkg-query stub: emulates the two queries the module uses against PKG_DB,
  # a flat "name size" file. Unknown packages exit non-zero (not installed).
  cat > "$STUB/dpkg-query" <<'EOF'
#!/bin/sh
DB="${PKG_DB:?}"
# Parse: dpkg-query -W -f '<fmt>' <pkg>
fmt=""; pkg=""
while [ $# -gt 0 ]; do
  case "$1" in
    -W) shift ;;
    -f) fmt=$2; shift 2 ;;
    -f*) fmt=${1#-f}; shift ;;
    *) pkg=$1; shift ;;
  esac
done
line=$(grep "^$pkg " "$DB" 2>/dev/null | tail -1)
if [ -z "$line" ]; then
  # Mimic dpkg-query: error to stderr, non-zero, no stdout.
  echo "dpkg-query: no packages found matching $pkg" >&2
  exit 1
fi
size=$(printf '%s' "$line" | awk '{print $2}')
case "$fmt" in
  *Status-Status*) printf 'installed' ;;
  *Installed-Size*) printf '%s' "$size" ;;
  *) printf '%s' "$size" ;;
esac
exit 0
EOF

  # apt-get stub: log the invocation; on `purge`, also remove the named packages
  # from the fake dpkg db so a follow-up query reports them gone (idempotency).
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
LOG="${STUB_APT_LOG:-/dev/null}"
DB="${PKG_DB:-/dev/null}"
printf '%s\n' "$*" >> "$LOG"
if [ "$1" = "purge" ]; then
  shift
  for a in "$@"; do
    case "$a" in -*) continue ;; esac
    tmp="$DB.tmp.$$"
    grep -v "^$a " "$DB" 2>/dev/null > "$tmp" || :
    mv "$tmp" "$DB"
  done
fi
exit "${STUB_APT_RC:-0}"
EOF
  chmod +x "$STUB"/*
}
