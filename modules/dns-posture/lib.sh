# shellcheck shell=bash
# SC2034: the DNS_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/dns-posture/lib.sh — shared helpers for the dns-posture module's
# apply / audit / revert actions.
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
: "${ONIONARMOR_DNS_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_DNS_UNBOUND_CHECKCONF:=unbound-checkconf}"
: "${ONIONARMOR_DNS_UNBOUND_CONTROL:=unbound-control}"
: "${ONIONARMOR_DNS_DIG:=dig}"
: "${ONIONARMOR_DNS_GETENT:=getent}"
: "${ONIONARMOR_DNS_CHATTR:=chattr}"
: "${ONIONARMOR_DNS_INSTALL:=install}"
: "${ONIONARMOR_DNS_PKILL:=pkill}"
: "${ONIONARMOR_DNS_APT:=apt-get}"
: "${ONIONARMOR_DNS_STAT:=stat}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_DNS_UNBOUND_CONFD:=/etc/unbound/unbound.conf.d}"
: "${ONIONARMOR_DNS_SNIPPET_NAME:=99-onionarmor-dns-posture.conf}"
: "${ONIONARMOR_DNS_ANCHOR_FILE:=/var/lib/unbound/root.key}"
: "${ONIONARMOR_DNS_ANCHOR_SOURCE:=/usr/share/dns/root.key}"
: "${ONIONARMOR_DNS_RESOLV_CONF:=/etc/resolv.conf}"
: "${ONIONARMOR_DNS_STATE_DIR:=/var/lib/onionarmor/dns-posture}"
: "${ONIONARMOR_DNS_TLS_CERT_BUNDLE:=/etc/ssl/certs/ca-certificates.crt}"

# The 1aeo fleet default DoT upstream set — pinned by SNI, all on :853.
# Cloudflare + Quad9 + Google + AdGuard + Mullvad, v4 and a couple of v6.
OA_DNS_DEFAULT_UPSTREAMS='1.1.1.1@853#cloudflare-dns.com,1.0.0.1@853#cloudflare-dns.com,9.9.9.9@853#dns.quad9.net,149.112.112.112@853#dns.quad9.net,8.8.8.8@853#dns.google,94.140.14.14@853#dns.adguard-dns.com,194.242.2.2@853#dns.mullvad.net,2620:fe::fe@853#dns.quad9.net,2606:4700:4700::1111@853#cloudflare-dns.com'

# --- flag defaults --------------------------------------------------------
dns_set_defaults() {
  DNS_UPSTREAMS="$OA_DNS_DEFAULT_UPSTREAMS"
  DNS_DNSSEC=1
  DNS_LISTEN="127.0.0.1"
  DNS_LISTEN_PORT=53
  DNS_NUM_THREADS=4
  DNS_ANCHOR_FILE="$ONIONARMOR_DNS_ANCHOR_FILE"
  DNS_BOOTSTRAP_ANCHOR=1
  DNS_MASK_RESOLVED=1
  DNS_RESOLV_CONF="$ONIONARMOR_DNS_RESOLV_CONF"
  DNS_IMMUTABLE_RESOLV=0
  DNS_DRY_RUN=0
  DNS_VERIFY=1
}

# dns_parse_flags <args...>: populate DNS_* from the command line. Shared by all
# three actions (audit/revert ignore the ones that don't apply to them).
dns_parse_flags() {
  dns_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --upstreams)          DNS_UPSTREAMS=${2:-}; shift 2 ;;
      --upstreams=*)        DNS_UPSTREAMS=${1#--upstreams=}; shift ;;
      --no-dnssec)          DNS_DNSSEC=0; shift ;;
      --dnssec)             DNS_DNSSEC=1; shift ;;
      --listen)             DNS_LISTEN=${2:-}; shift 2 ;;
      --listen=*)           DNS_LISTEN=${1#--listen=}; shift ;;
      --listen-port)        DNS_LISTEN_PORT=${2:-}; shift 2 ;;
      --listen-port=*)      DNS_LISTEN_PORT=${1#--listen-port=}; shift ;;
      --num-threads)        DNS_NUM_THREADS=${2:-}; shift 2 ;;
      --num-threads=*)      DNS_NUM_THREADS=${1#--num-threads=}; shift ;;
      --anchor-file)        DNS_ANCHOR_FILE=${2:-}; shift 2 ;;
      --anchor-file=*)      DNS_ANCHOR_FILE=${1#--anchor-file=}; shift ;;
      --bootstrap-anchor)   DNS_BOOTSTRAP_ANCHOR=1; shift ;;
      --no-bootstrap-anchor) DNS_BOOTSTRAP_ANCHOR=0; shift ;;
      --mask-resolved)      DNS_MASK_RESOLVED=1; shift ;;
      --no-mask-resolved)   DNS_MASK_RESOLVED=0; shift ;;
      --resolv-conf)        DNS_RESOLV_CONF=${2:-}; shift 2 ;;
      --resolv-conf=*)      DNS_RESOLV_CONF=${1#--resolv-conf=}; shift ;;
      --immutable-resolv)   DNS_IMMUTABLE_RESOLV=1; shift ;;
      --dry-run)            DNS_DRY_RUN=1; shift ;;
      --verify)             DNS_VERIFY=1; shift ;;
      --no-verify)          DNS_VERIFY=0; shift ;;
      -h|--help)            dns_usage; exit 0 ;;
      *)                    die "dns-posture: unknown option: $1 (try --help)" ;;
    esac
  done
  dns_validate_flags
}

dns_validate_flags() {
  case "$DNS_LISTEN_PORT" in (*[!0-9]*|"") die "dns-posture: --listen-port must be numeric: $DNS_LISTEN_PORT" ;; esac
  [ "$DNS_LISTEN_PORT" -eq 53 ] || die "dns-posture: --listen-port must be 53 (resolv.conf cannot specify ports; non-53 breaks system DNS)"
  case "$DNS_NUM_THREADS" in (*[!0-9]*|"") die "dns-posture: --num-threads must be numeric: $DNS_NUM_THREADS" ;; esac
  [ -n "$DNS_UPSTREAMS" ] || die "dns-posture: --upstreams must not be empty"
  local entry
  # shellcheck disable=SC2086
  local IFS=,
  for entry in $DNS_UPSTREAMS; do
    case "$entry" in
      *@*\#*) : ;;  # has @port and #sni
      *) die "dns-posture: malformed upstream '$entry' — expected <ip>@<port>#<sni>" ;;
    esac
  done
}

dns_usage() {
  cat <<'EOF'
onionarmor apply --module dns-posture [options]   (also: audit, revert)

Bring DNS resolution under a local validating, DoT-only resolver (unbound),
matching the 1aeo fleet posture: DoT upstreams pinned by SNI, DNSSEC via the
stock Debian root anchor (never duplicated), systemd-resolved masked, and
/etc/resolv.conf pinned to the local resolver.

OPTIONS (every fleet default is overridable)
  --upstreams <list>     Comma-separated <ip>@<port>#<sni> DoT upstreams.
  --no-dnssec            Disable DNSSEC validation (default: on).
  --listen <addr>        unbound listen address (default: 127.0.0.1; 0.0.0.0 = LAN).
  --listen-port <port>   unbound listen port (default: 53).
  --num-threads <n>      unbound worker threads (default: 4).
  --anchor-file <path>   DNSSEC trust-anchor file (default: /var/lib/unbound/root.key).
  --bootstrap-anchor     Seed the anchor from the distro copy if missing (default).
  --no-bootstrap-anchor  Do not seed the anchor.
  --mask-resolved        Mask + stop systemd-resolved (default).
  --no-mask-resolved     Leave systemd-resolved alone.
  --resolv-conf <path>   resolv.conf to manage (default: /etc/resolv.conf).
  --immutable-resolv     chattr +i the managed resolv.conf (opt-in).
  --dry-run              Print the plan + rendered config, change nothing.
  --verify / --no-verify Post-apply verification (default: verify).
  -h, --help             This help.
EOF
}

# dns_snippet_path -> the managed unbound conf snippet path.
dns_snippet_path() {
  printf '%s/%s\n' "$ONIONARMOR_DNS_UNBOUND_CONFD" "$ONIONARMOR_DNS_SNIPPET_NAME"
}

# dns_resolv_backup -> the resolv.conf backup path.
dns_resolv_backup() {
  printf '%s/resolv.conf.bak\n' "$ONIONARMOR_DNS_STATE_DIR"
}

# dns_stub_addrs: print the addresses resolv.conf should list, one per line.
# A loopback or wildcard listener stubs to 127.0.0.1 + ::1; an explicit
# address stubs to just that address.
dns_stub_addrs() {
  case "$DNS_LISTEN" in
    127.0.0.1|0.0.0.0|::|"") printf '127.0.0.1\n::1\n' ;;
    *)                       printf '%s\n' "$DNS_LISTEN" ;;
  esac
}

# dns_count_anchor_lines: count `auto-trust-anchor-file` directives across every
# .conf in the unbound conf.d dir (our snippet included). This is the
# duplicate-anchor detector — the bug that crashed three fleet hosts.
dns_count_anchor_lines() {
  local d=$ONIONARMOR_DNS_UNBOUND_CONFD
  [ -d "$d" ] || { printf '0\n'; return 0; }
  # Count non-comment lines mentioning auto-trust-anchor-file. `|| true` keeps a
  # zero-match grep (exit 1) from tripping the caller's `set -o pipefail`.
  { grep -rhE '^[[:space:]]*auto-trust-anchor-file[[:space:]]*:' "$d" 2>/dev/null || true; } \
    | wc -l | awk '{print $1}'
}

# dns_external_anchor_present: true if a conf file OTHER than our snippet already
# declares auto-trust-anchor-file (i.e. Debian's stock root-auto-trust-anchor-file.conf).
dns_external_anchor_present() {
  local d=$ONIONARMOR_DNS_UNBOUND_CONFD snippet
  snippet=$(dns_snippet_path)
  [ -d "$d" ] || return 1
  local f
  for f in "$d"/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "$snippet" ] && continue
    if grep -qE '^[[:space:]]*auto-trust-anchor-file[[:space:]]*:' "$f" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

# dns_render_snippet: emit the managed unbound config to stdout. DNSSEC anchor
# is added HERE only when no other conf file declares one — guaranteeing
# exactly one trust anchor and never duplicating Debian's stock file.
dns_render_snippet() {
  local addr
  printf '# Managed by onionarmor (module: dns-posture) — do not edit by hand.\n'
  printf '# Revert with: onionarmor revert --module dns-posture\n'
  printf '#\n'
  printf '# DNSSEC trust anchor is intentionally NOT duplicated here when Debian'\''s\n'
  printf '# stock root-auto-trust-anchor-file.conf already provides it. Duplicating\n'
  printf '# auto-trust-anchor-file is what crashed fleet hosts — see module README.\n'
  printf 'server:\n'
  printf '    num-threads: %s\n' "$DNS_NUM_THREADS"
  while read -r addr; do
    [ -n "$addr" ] || continue
    printf '    interface: %s\n' "$addr"
  done < <(dns_interface_addrs)
  printf '    port: %s\n' "$DNS_LISTEN_PORT"
  printf '    do-tcp: yes\n'
  printf '    tls-cert-bundle: "%s"\n' "$ONIONARMOR_DNS_TLS_CERT_BUNDLE"
  if [ "$DNS_DNSSEC" -eq 1 ]; then
    if dns_external_anchor_present; then
      printf '    # DNSSEC anchor provided by the stock root-auto-trust-anchor-file.conf.\n'
    else
      printf '    # No stock anchor file found — declare exactly one here.\n'
      printf '    auto-trust-anchor-file: "%s"\n' "$DNS_ANCHOR_FILE"
    fi
  else
    printf '    # DNSSEC validation disabled by --no-dnssec (iterator only).\n'
    printf '    module-config: "iterator"\n'
  fi
  printf 'forward-zone:\n'
  printf '    name: "."\n'
  printf '    forward-tls-upstream: yes\n'
  local entry IFS=,
  # shellcheck disable=SC2086  # intentional comma-split of the upstreams list
  for entry in $DNS_UPSTREAMS; do
    [ -n "$entry" ] || continue
    printf '    forward-addr: %s\n' "$entry"
  done
}

# dns_interface_addrs: print the unbound interface addresses, one per line.
# Must stay dual-stack-consistent with dns_stub_addrs: when resolv.conf lists
# both loopback families (127.0.0.1 + ::1), unbound has to bind both families
# too, otherwise resolv.conf advertises a nameserver unbound never listens on.
# A loopback/default listener binds both loopback addrs; a wildcard listener
# binds both wildcard families.
dns_interface_addrs() {
  case "$DNS_LISTEN" in
    127.0.0.1|"") printf '127.0.0.1\n::1\n' ;;
    0.0.0.0|::)   printf '0.0.0.0\n::\n' ;;
    *)            printf '%s\n' "$DNS_LISTEN" ;;
  esac
}

# dns_render_resolv_conf: emit the managed /etc/resolv.conf to stdout.
dns_render_resolv_conf() {
  local addr backup; backup=$(dns_resolv_backup)
  printf '# Managed by onionarmor (module: dns-posture). Do not edit by hand.\n'
  printf '# Original backed up at: %s\n' "$backup"
  printf '# Revert with: onionarmor revert --module dns-posture\n'
  while read -r addr; do
    [ -n "$addr" ] || continue
    printf 'nameserver %s\n' "$addr"
  done < <(dns_stub_addrs)
}

# dns_file_owner <path> -> "user:group" via the (overridable) stat command.
dns_file_owner() {
  "$ONIONARMOR_DNS_STAT" -c '%U:%G' "$1" 2>/dev/null || printf ''
}

# dns_forwards_classify <list_forwards-output>: inspect `unbound-control
# list_forwards` text and print one of: only-dot / has-do53 / none.
#   only-dot  -> at least one forwarder address, every address is @853
#   has-do53  -> some forwarder address is not @853 (a plaintext :53 leak)
#   none      -> no forwarder addresses found at all
# An "address token" is one containing a dot or colon (v4/v6); the literal
# "." root-zone name and the IN/forward keywords are skipped.
dns_forwards_classify() {
  printf '%s\n' "$1" | awk '
    { for (i = 1; i <= NF; i++) {
        t = $i
        if (t == "." || t == "IN" || t == "forward") continue
        if (t ~ /[.:]/) {                 # looks like an address token
          total++
          if (t ~ /@853([#]|$)/) dot++
        }
      } }
    END {
      if (total == 0) { print "none" }
      else if (dot == total) { print "only-dot" }
      else { print "has-do53" }
    }'
}
