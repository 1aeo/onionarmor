# Test helper for the bgp-hardening module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (vtysh, nft, systemctl, ss, apt-get) plus sandbox FRR
# config files (daemons, frr.conf). Fully offline; never touches the real host.
# Uses mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04 bats compatibility.

setup() {
  MOD_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export MOD_ROOT
  REPO_ROOT="$(cd "$MOD_ROOT/../.." && pwd)"
  export REPO_ROOT
  export ONIONARMOR_PREFIX="$REPO_ROOT"

  APPLY="$MOD_ROOT/apply.sh"; AUDIT="$MOD_ROOT/audit.sh"; REVERT="$MOD_ROOT/revert.sh"
  export APPLY AUDIT REVERT

  SB="$(mktemp -d)"; export SB
  STUB="$SB/stubs"; export STUB
  export STUB_STATE="$SB/systemctl-state"
  mkdir -p "$STUB" "$STUB_STATE/active" "$STUB_STATE/enabled" "$SB/bin"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_BGP_DAEMONS="$SB/etc/frr/daemons"
  export ONIONARMOR_BGP_FRR_CONF="$SB/etc/frr/frr.conf"
  export ONIONARMOR_BGP_STATE_DIR="$SB/var/lib/onionarmor/bgp-hardening"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$(dirname "$ONIONARMOR_BGP_DAEMONS")"

  # --- stub state + logs ---
  export NFT_STORE="$SB/nft-store"           # holds the managed table fragment
  export STUB_VTYSH_LOG="$SB/vtysh.log"
  export STUB_NFT_LOG="$SB/nft.log"
  export STUB_APT_LOG="$SB/apt.log"
  : > "$STUB_VTYSH_LOG"; : > "$STUB_NFT_LOG"; : > "$STUB_APT_LOG"
  export FAKE_FRR_VERSION="10.3.0"           # current (>= min 10.2, not flagged)

  _build_stubs
  export ONIONARMOR_BGP_VTYSH="$STUB/vtysh"
  export ONIONARMOR_BGP_NFT="$STUB/nft"
  export ONIONARMOR_BGP_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_BGP_SS="$STUB/ss"
  export ONIONARMOR_BGP_APT="$STUB/apt-get"
  # Absolute path that does not exist until apt "installs" it, so command -v is
  # deterministic and never finds a real system routinator.
  export ONIONARMOR_BGP_ROUTINATOR="$SB/bin/routinator"

  # Default service state: frr running; routinator absent.
  printf 'active\n'   > "$STUB_STATE/active/frr"
  printf 'enabled\n'  > "$STUB_STATE/enabled/frr"
  printf 'inactive\n' > "$STUB_STATE/active/routinator"
  printf 'disabled\n' > "$STUB_STATE/enabled/routinator"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then chmod -R u+rwx "$SB" 2>/dev/null || true; rm -rf "$SB"; fi
}

# seed_frr <router-id> <peer-ip> [more peers...] : write a realistic frr.conf
# (router-id + a neighbor remote-as line per peer) and a wildcard daemons file.
seed_frr() {
  local rid="$1"; shift
  mkdir -p "$(dirname "$ONIONARMOR_BGP_FRR_CONF")"
  {
    printf 'frr version 10.3\n'
    printf 'router bgp 65010\n'
    printf ' bgp router-id %s\n' "$rid"
    local asn=64500 p
    for p in "$@"; do
      printf ' neighbor %s remote-as %s\n' "$p" "$asn"
      printf ' neighbor %s route-map ALLOW_ALL_IN in\n' "$p"
      asn=$((asn + 1))
    done
    printf '!\n'
  } > "$ONIONARMOR_BGP_FRR_CONF"
  seed_daemons ""   # default: no -l (wildcard bind)
}

# seed_daemons <bind-ip-or-empty> : write /etc/frr/daemons with bgpd enabled and
# bgpd_options carrying -l <ip> when given (else a wildcard-ish default).
seed_daemons() {
  local ip="$1" opts="-A 127.0.0.1"
  [ -n "$ip" ] && opts="-A 127.0.0.1 -l $ip"
  mkdir -p "$(dirname "$ONIONARMOR_BGP_DAEMONS")"
  {
    printf 'zebra=yes\n'
    printf 'bgpd=yes\n'
    printf 'bgpd_options="%s"\n' "$opts"
    printf 'vtysh_enable=yes\n'
  } > "$ONIONARMOR_BGP_DAEMONS"
}

_build_stubs() {
  # systemctl: stateful per-unit active/enabled; logs verbs.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
S="${STUB_STATE:?}"; mkdir -p "$S/active" "$S/enabled"
verb=$1; shift; now=0; unit=""
for a in "$@"; do case "$a" in --now) now=1 ;; -*) ;; *) [ -z "$unit" ] && unit="$a" ;; esac; done
printf '%s %s now=%s\n' "$verb" "$unit" "$now" >> "$S/systemctl.log"
af="$S/active/$unit"; ef="$S/enabled/$unit"
case "$verb" in
  is-active)  cat "$af" 2>/dev/null || echo inactive ;;
  is-enabled) cat "$ef" 2>/dev/null || echo disabled ;;
  enable)     echo enabled > "$ef";  [ "$now" = 1 ] && echo active > "$af" ;;
  disable)    echo disabled > "$ef"; [ "$now" = 1 ] && echo inactive > "$af" ;;
  start)      echo active > "$af" ;;
  stop)       echo inactive > "$af" ;;
  restart|reload) echo active > "$af" ;;
esac
exit 0
EOF

  # vtysh: log every -c; emulate show version / show rpki cache.
  cat > "$STUB/vtysh" <<'EOF'
#!/bin/sh
LOG="${STUB_VTYSH_LOG:-/dev/null}"
printf '%s\n' "$*" >> "$LOG"
mode=""
for a in "$@"; do
  case "$a" in
    -c) mode="next" ;;
    *) if [ "$mode" = "next" ]; then
         case "$a" in
           "show version") echo "FRRouting ${FAKE_FRR_VERSION:-10.3.0} (host)." ;;
           "show rpki cache")
             if [ -e "${ONIONARMOR_BGP_STATE_DIR:-/nonexistent}/rpki.applied" ]; then
               echo "host: 127.0.0.1 port: 3323 preference: 1"
             fi ;;
           "show run"|"show running-config") cat "${ONIONARMOR_BGP_FRR_CONF:-/dev/null}" 2>/dev/null ;;
         esac
         mode=""
       fi ;;
  esac
done
exit 0
EOF

  # nft: a single managed table fragment stored in $NFT_STORE.
  cat > "$STUB/nft" <<'EOF'
#!/bin/sh
LOG="${STUB_NFT_LOG:-/dev/null}"; STORE="${NFT_STORE:?}"
printf '%s\n' "$*" >> "$LOG"
case "$1 $2" in
  "-f -") cat > "$STORE"; exit 0 ;;
esac
case "$1" in
  list)
    case "$2" in
      table) [ -s "$STORE" ] && { cat "$STORE"; exit 0; }; exit 1 ;;
      ruleset) cat "$STORE" 2>/dev/null; exit 0 ;;
    esac ;;
  delete)
    [ "$2" = "table" ] && { rm -f "$STORE"; exit 0; } ;;
esac
exit 0
EOF

  # ss: reflect the daemons -l option as the :179 listener bind.
  cat > "$STUB/ss" <<'EOF'
#!/bin/sh
d="${ONIONARMOR_BGP_DAEMONS:-/dev/null}"
ip=$(sed -n 's/^[[:space:]]*bgpd_options[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$d" 2>/dev/null \
       | awk '{for(i=1;i<=NF;i++) if($i=="-l"){print $(i+1); exit}}')
[ -z "$ip" ] && ip="0.0.0.0"
printf 'LISTEN 0 128 %s:179 0.0.0.0:*\n' "$ip"
exit 0
EOF

  # apt-get: log; on `install ... routinator`, create the routinator binary.
  cat > "$STUB/apt-get" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${STUB_APT_LOG:-/dev/null}"
case "$*" in
  *install*routinator*)
    mkdir -p "$(dirname "${ONIONARMOR_BGP_ROUTINATOR:?}")"
    printf '#!/bin/sh\nexit 0\n' > "$ONIONARMOR_BGP_ROUTINATOR"
    chmod +x "$ONIONARMOR_BGP_ROUTINATOR" ;;
esac
exit 0
EOF

  chmod +x "$STUB"/*
}
