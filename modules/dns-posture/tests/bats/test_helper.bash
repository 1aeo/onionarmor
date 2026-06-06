# Test helper for the dns-posture module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (systemctl, unbound-checkconf, unbound-control, dig, getent,
# chattr, install, stat, pkill, apt-get) so the suite is fully offline and
# never changes the real host. We use mktemp -d (not $BATS_TEST_TMPDIR) for
# compatibility with the older bats packaged on ubuntu-22.04.

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
  mkdir -p "$STUB" "$STUB_STATE/active" "$STUB_STATE/enabled"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_DNS_UNBOUND_CONFD="$SB/etc/unbound/unbound.conf.d"
  export ONIONARMOR_DNS_ANCHOR_FILE="$SB/var/lib/unbound/root.key"
  export ONIONARMOR_DNS_ANCHOR_SOURCE="$SB/usr/share/dns/root.key"
  export ONIONARMOR_DNS_RESOLV_CONF="$SB/etc/resolv.conf"
  export ONIONARMOR_DNS_STATE_DIR="$SB/var/lib/onionarmor/dns-posture"
  export ONIONARMOR_DNS_TLS_CERT_BUNDLE="$SB/etc/ssl/certs/ca-certificates.crt"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$ONIONARMOR_DNS_UNBOUND_CONFD" \
           "$(dirname "$ONIONARMOR_DNS_ANCHOR_SOURCE")" \
           "$(dirname "$ONIONARMOR_DNS_RESOLV_CONF")" \
           "$(dirname "$ONIONARMOR_DNS_TLS_CERT_BUNDLE")"

  # A realistic starting point: a systemd-resolved stub resolv.conf + a distro
  # root.key source for anchor bootstrap.
  printf 'nameserver 127.0.0.53\noptions edns0\n' > "$ONIONARMOR_DNS_RESOLV_CONF"
  printf '. IN DS 20326 8 2 deadbeef\n' > "$ONIONARMOR_DNS_ANCHOR_SOURCE"
  : > "$ONIONARMOR_DNS_TLS_CERT_BUNDLE"

  _build_stubs

  # Point every overridable command at its stub (absolute paths so
  # `command -v` succeeds without PATH juggling).
  export ONIONARMOR_DNS_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_DNS_UNBOUND_CHECKCONF="$STUB/unbound-checkconf"
  export ONIONARMOR_DNS_UNBOUND_CONTROL="$STUB/unbound-control"
  export ONIONARMOR_DNS_DIG="$STUB/dig"
  export ONIONARMOR_DNS_GETENT="$STUB/getent"
  export ONIONARMOR_DNS_CHATTR="$STUB/chattr"
  export ONIONARMOR_DNS_INSTALL="$STUB/install"
  export ONIONARMOR_DNS_STAT="$STUB/stat"
  export ONIONARMOR_DNS_PKILL="$STUB/pkill"
  export ONIONARMOR_DNS_APT="$STUB/apt-get"

  # Default service state: unbound + systemd-resolved both running/enabled.
  printf 'active\n'  > "$STUB_STATE/active/unbound"
  printf 'enabled\n' > "$STUB_STATE/enabled/unbound"
  printf 'active\n'  > "$STUB_STATE/active/systemd-resolved"
  printf 'enabled\n' > "$STUB_STATE/enabled/systemd-resolved"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# Seed a conf.d file declaring a DNSSEC trust anchor (models Debian's stock
# root-auto-trust-anchor-file.conf, or an accidental duplicate).
seed_anchor_conf() {
  local name="$1"
  {
    printf 'server:\n'
    printf '    auto-trust-anchor-file: "%s"\n' "$ONIONARMOR_DNS_ANCHOR_FILE"
  } > "$ONIONARMOR_DNS_UNBOUND_CONFD/$name"
}

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

  # unbound-checkconf: fail if >1 auto-trust-anchor-file across conf.d, or if
  # any conf contains the literal SYNTAX-ERROR marker. Models the real tool's
  # rejection of the duplicate-anchor config.
  cat > "$STUB/unbound-checkconf" <<'EOF'
#!/bin/sh
d="${ONIONARMOR_DNS_UNBOUND_CONFD:?}"
n=$(grep -rhE '^[[:space:]]*auto-trust-anchor-file[[:space:]]*:' "$d" 2>/dev/null | wc -l | tr -d ' ')
if [ "$n" -gt 1 ]; then
  echo "[unbound-checkconf] error: duplicate auto-trust-anchor-file ($n)" >&2
  exit 1
fi
if grep -rqE 'SYNTAX-ERROR' "$d" 2>/dev/null; then
  echo "[unbound-checkconf] syntax error" >&2
  exit 1
fi
exit 0
EOF

  # unbound-control: list_forwards reflects the managed snippet's forward-addr.
  cat > "$STUB/unbound-control" <<'EOF'
#!/bin/sh
snip="${ONIONARMOR_DNS_UNBOUND_CONFD:?}/${ONIONARMOR_DNS_SNIPPET_NAME:-99-onionarmor-dns-posture.conf}"
case "$1" in
  list_forwards)
    addrs=$(grep -E '^[[:space:]]*forward-addr:' "$snip" 2>/dev/null | sed 's/.*forward-addr:[[:space:]]*//')
    [ -n "$addrs" ] || exit 0
    printf '. IN forward'
    for a in $addrs; do printf ' %s' "$a"; done
    printf '\n'
    ;;
  *) : ;;
esac
exit 0
EOF

  # dig: emit a header; ad flag controlled by $FAKE_DIG_AD (default 1).
  cat > "$STUB/dig" <<'EOF'
#!/bin/sh
if [ "${FAKE_DIG_AD:-1}" = "1" ]; then
  echo ';; flags: qr rd ra ad; QUERY: 1, ANSWER: 1'
else
  echo ';; flags: qr rd ra; QUERY: 1, ANSWER: 1'
fi
echo 'cloudflare.com.		300	IN	A	104.16.132.229'
exit 0
EOF

  # getent: exit code from $FAKE_GETENT_RC (default 0 = found).
  cat > "$STUB/getent" <<'EOF'
#!/bin/sh
echo '104.16.132.229  cloudflare.com'
exit "${FAKE_GETENT_RC:-0}"
EOF

  # chattr: record invocation, no-op.
  cat > "$STUB/chattr" <<'EOF'
#!/bin/sh
echo "$*" >> "${STUB:?}/chattr.log"
exit 0
EOF

  # install: emulate `install -o U -g G -m MODE SRC DST` -> cp + owner sidecar.
  cat > "$STUB/install" <<'EOF'
#!/bin/sh
src=""; dst=""; owner="root:group"; u=""; g=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) u="$2"; shift 2 ;;
    -g) g="$2"; shift 2 ;;
    -m) shift 2 ;;
    -*) shift ;;
    *) if [ -z "$src" ]; then src="$1"; elif [ -z "$dst" ]; then dst="$1"; fi; shift ;;
  esac
done
[ -n "$u" ] && [ -n "$g" ] && owner="$u:$g"
cp "$src" "$dst" || exit 1
printf '%s' "$owner" > "$dst.fakeowner"
exit 0
EOF

  # stat: `stat -c '%U:%G' PATH` -> owner sidecar if present, else root:root.
  cat > "$STUB/stat" <<'EOF'
#!/bin/sh
path=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) shift 2 ;;
    -*) shift ;;
    *) path="$1"; shift ;;
  esac
done
if [ -f "$path.fakeowner" ]; then cat "$path.fakeowner"; else echo "root:root"; fi
exit 0
EOF

  cat > "$STUB/pkill" <<'EOF'
#!/bin/sh
exit 0
EOF
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
echo "$*" >> "${STUB:?}/apt-get.log"
exit 0
EOF

  chmod +x "$STUB"/*
}
