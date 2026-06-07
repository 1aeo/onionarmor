# shellcheck shell=bash
# SC2034: the colour vars + BGP_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/bgp-hardening/lib.sh — shared helpers for the bgp-hardening module's
# apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite drives the whole module against a
# sandbox with stub binaries (vtysh, nft, ufw, systemctl, ss, apt-get), never
# touching the real host.
#
# WHAT THIS MODULE DOES
#   Applies safe defaults to an FRR bgpd that takes a full feed from a single
#   trusted transit peer:
#     1. bind bgpd's listener to a specific peer-facing IP (not 0.0.0.0/[::]),
#     2. restrict inbound tcp/179 to the known peer IP(s) at the firewall,
#     3. validate inbound origins with RPKI (Routinator) — drop INVALID, keep
#        VALID + UNKNOWN (preserves the operator's full feed),
#     4. optionally enable GTSM/ttl-security (requires peer cooperation).
#   It deliberately does NOT enforce TCP-MD5, maximum-prefix, or a restrictive
#   inbound prefix filter — see the README "Out of scope" section.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_BGP_VTYSH:=vtysh}"
: "${ONIONARMOR_BGP_NFT:=nft}"
: "${ONIONARMOR_BGP_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_BGP_SS:=ss}"
: "${ONIONARMOR_BGP_APT:=apt-get}"
: "${ONIONARMOR_BGP_ROUTINATOR:=routinator}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_BGP_DAEMONS:=/etc/frr/daemons}"
: "${ONIONARMOR_BGP_FRR_CONF:=/etc/frr/frr.conf}"
: "${ONIONARMOR_BGP_STATE_DIR:=/var/lib/onionarmor/bgp-hardening}"

# --- constants ------------------------------------------------------------
# Dedicated nft table so revert can drop everything we added in one shot.
BGP_NFT_TABLE="onionarmor_bgp"
# Routinator's RTR-to-router default endpoint.
BGP_RPKI_CACHE_HOST_DEFAULT="127.0.0.1"
BGP_RPKI_CACHE_PORT_DEFAULT="3323"
# Inbound RPKI route-map we install: deny rpki-invalid, permit everything else
# (keeps the operator's full feed — this is NOT a switch to a default-only filter).
BGP_RPKI_ROUTEMAP="ONIONARMOR-RPKI-IN"
# FRR releases known to carry advisories the fleet flagged; audit warns on these.
# (Advisory only — version drift is a yellow, never a red.)
BGP_FRR_FLAGGED_VERSIONS="8.4.4 10.5.0"
# Minimum FRR release the fleet considers current.
BGP_FRR_MIN_VERSION="10.2"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_BGP_GREEN=$'\033[32m'; OA_BGP_YEL=$'\033[33m'; OA_BGP_RED=$'\033[31m'; OA_BGP_OFF=$'\033[0m'
else
  OA_BGP_GREEN=""; OA_BGP_YEL=""; OA_BGP_RED=""; OA_BGP_OFF=""
fi

# --- flag defaults --------------------------------------------------------
bgp_set_defaults() {
  BGP_BIND_IP=""          # empty => auto-detect from `bgp router-id`
  BGP_BIND_IP_SET=0
  BGP_BIND_FIX=1          # --no-bind-fix => 0 (listener bind is the headline)
  BGP_PEERS=""            # comma-joined; empty => auto-detect from neighbors
  BGP_DO_FIREWALL=0       # OFF by default; --enable-firewall => 1 (deferred work,
                          # offered as opt-in defense-in-depth)
  BGP_FIREWALL="nftables" # backend (nftables only; ufw deferred)
  BGP_RPKI=0              # OFF by default; --enable-rpki => 1. Minimal value for a
                          # single-homed stub AS (see README "When NOT to use RPKI").
  BGP_RPKI_SOURCES=""     # extra repo URLs, comma-joined
  BGP_RPKI_CACHE_HOST="$BGP_RPKI_CACHE_HOST_DEFAULT"
  BGP_RPKI_CACHE_PORT="$BGP_RPKI_CACHE_PORT_DEFAULT"
  BGP_GTSM=0              # --enable-gtsm => 1
  BGP_GTSM_HOPS=""        # required when BGP_GTSM=1
  BGP_DRY_RUN=0
}

# bgp_need_val <flag> <count>: guard a value-taking flag's `shift 2`.
bgp_need_val() {
  [ "$2" -ge 2 ] || die "bgp-hardening: $1 requires a value (try --help)"
}

# bgp_add_csv <varname> <token>: append a comma-separated token list to a var.
bgp_add_csv() {
  local cur; eval "cur=\${$1}"
  if [ -z "$cur" ]; then eval "$1=\$2"; else eval "$1=\$cur,\$2"; fi
}

bgp_parse_flags() {
  bgp_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --bind-ip)         bgp_need_val "$1" "$#"; BGP_BIND_IP=$2; BGP_BIND_IP_SET=1; shift 2 ;;
      --bind-ip=*)       BGP_BIND_IP=${1#--bind-ip=}; BGP_BIND_IP_SET=1; shift ;;
      --no-bind-fix)     BGP_BIND_FIX=0; shift ;;
      --peer-ip)         bgp_need_val "$1" "$#"; bgp_add_csv BGP_PEERS "$2"; shift 2 ;;
      --peer-ip=*)       bgp_add_csv BGP_PEERS "${1#--peer-ip=}"; shift ;;
      --enable-firewall) BGP_DO_FIREWALL=1; shift ;;
      --no-firewall)     BGP_DO_FIREWALL=0; shift ;;   # accepted (already the default)
      --enable-rpki)     BGP_RPKI=1; shift ;;
      --no-enable-rpki)  BGP_RPKI=0; shift ;;
      --rpki-source)     bgp_need_val "$1" "$#"; bgp_add_csv BGP_RPKI_SOURCES "$2"; shift 2 ;;
      --rpki-source=*)   bgp_add_csv BGP_RPKI_SOURCES "${1#--rpki-source=}"; shift ;;
      --enable-gtsm)     BGP_GTSM=1; shift ;;
      --gtsm-hops)       bgp_need_val "$1" "$#"; BGP_GTSM_HOPS=$2; shift 2 ;;
      --gtsm-hops=*)     BGP_GTSM_HOPS=${1#--gtsm-hops=}; shift ;;
      --dry-run)         BGP_DRY_RUN=1; shift ;;
      -h|--help)         bgp_usage; exit 0 ;;
      *)                 die "bgp-hardening: unknown option: $1 (try --help)" ;;
    esac
  done
  bgp_validate_flags
}

bgp_validate_flags() {
  if [ "$BGP_GTSM" -eq 1 ]; then
    case "$BGP_GTSM_HOPS" in
      ""|*[!0-9]*) die "bgp-hardening: --enable-gtsm requires --gtsm-hops <N> (1-255)" ;;
    esac
    { [ "$BGP_GTSM_HOPS" -ge 1 ] && [ "$BGP_GTSM_HOPS" -le 255 ]; } \
      || die "bgp-hardening: --gtsm-hops must be 1-255: $BGP_GTSM_HOPS"
  fi
  [ -n "$BGP_BIND_IP" ] && bgp_validate_ip "$BGP_BIND_IP" "--bind-ip"
  if [ -n "$BGP_PEERS" ]; then
    local p IFS=,
    # shellcheck disable=SC2086  # intentional comma-split of the peer list
    for p in $BGP_PEERS; do [ -n "$p" ] && bgp_validate_ip "$p" "--peer-ip"; done
  fi
  return 0
}

# bgp_validate_ip <addr> <flag-name>: light sanity check (v4 dotted or v6 colon).
bgp_validate_ip() {
  case "$1" in
    *[!0-9.]*) case "$1" in *:*) : ;; *) die "bgp-hardening: $2 '$1' is not an IP address" ;; esac ;;
    *.*.*.*) : ;;
    *) die "bgp-hardening: $2 '$1' is not an IP address" ;;
  esac
}

bgp_usage() {
  cat <<'EOF'
onionarmor apply --module bgp-hardening [options]   (also: audit, revert)

Bind the FRR bgpd listener to a specific peer-facing IP (the default, headline
fix). Firewall, RPKI, and GTSM are OPT-IN extras. Auto-detects from /etc/frr
(bgp router-id, neighbor lines).

OPTIONS
  --bind-ip <ip>          bgpd listener bind IP (default: auto from `bgp router-id`).
  --no-bind-fix           Skip the listener-bind step entirely.
  --peer-ip <ip>          Known peer IP(s); repeatable / comma-separated
                          (default: auto from `neighbor <ip> remote-as` lines).
  --enable-firewall       Restrict tcp/179 to the known peer(s) with nftables
                          (default: OFF — deferred; offered as defense-in-depth).
  --enable-rpki           Install/use Routinator + validate inbound (default OFF;
                          minimal value for a single-homed stub AS — see README).
  --no-enable-rpki        Leave RPKI alone (already the default).
  --rpki-source <url>     Extra RPKI repo URL; repeatable (default: the 5 RIRs).
  --enable-gtsm           Set `ttl-security hops <N>` per neighbor (peer must
                          cooperate); requires --gtsm-hops.
  --gtsm-hops <N>         GTSM hop count (1-255).
  --dry-run               Print the planned changes; mutate nothing.
  -h, --help              This help.

Out of scope (by operator constraint): TCP-MD5 (peer doesn't offer it),
maximum-prefix (unbounded feed wanted), and the inbound full-feed accept policy
(ALLOW_ALL_IN is kept — RPKI only removes INVALIDs).
EOF
}

# --- paths ----------------------------------------------------------------
bgp_daemons_path()        { printf '%s\n' "$ONIONARMOR_BGP_DAEMONS"; }
bgp_daemons_backup_path() { printf '%s/daemons.bak\n' "$ONIONARMOR_BGP_STATE_DIR"; }
bgp_nft_backup_path()     { printf '%s/nftables-%s.bak\n' "$ONIONARMOR_BGP_STATE_DIR" "$BGP_NFT_TABLE"; }
bgp_rpki_marker_path()    { printf '%s/rpki.applied\n' "$ONIONARMOR_BGP_STATE_DIR"; }
bgp_routinator_marker_path() { printf '%s/routinator.enabled\n' "$ONIONARMOR_BGP_STATE_DIR"; }
bgp_gtsm_marker_path()    { printf '%s/gtsm.applied\n' "$ONIONARMOR_BGP_STATE_DIR"; }
bgp_norib_marker_path()   { printf '%s/norib.applied\n' "$ONIONARMOR_BGP_STATE_DIR"; }

# --- FRR config auto-detection --------------------------------------------
# bgp_detect_router_id: first `bgp router-id <ip>` in the FRR config, or empty.
bgp_detect_router_id() {
  [ -f "$ONIONARMOR_BGP_FRR_CONF" ] || return 0
  awk '/^[[:space:]]*bgp[[:space:]]+router-id[[:space:]]+/ { print $3; exit }' \
    "$ONIONARMOR_BGP_FRR_CONF"
}

# bgp_detect_peers: unique neighbor IPs from `neighbor <ip> remote-as <asn>`,
# one per line, in first-seen order.
bgp_detect_peers() {
  [ -f "$ONIONARMOR_BGP_FRR_CONF" ] || return 0
  awk '
    /^[[:space:]]*neighbor[[:space:]]+/ {
      # neighbor <peer> remote-as <asn>   — only the remote-as form names a peer.
      for (i = 1; i < NF; i++) {
        if ($i == "remote-as") { peer = $2; if (!seen[peer]++) print peer }
      }
    }' "$ONIONARMOR_BGP_FRR_CONF"
}

# bgp_resolve_bind_ip: the bind IP to use (flag wins over router-id). Empty if
# neither is available (caller decides whether that is fatal).
bgp_resolve_bind_ip() {
  if [ -n "$BGP_BIND_IP" ]; then printf '%s\n' "$BGP_BIND_IP"; return 0; fi
  bgp_detect_router_id
}

# bgp_resolve_peers: the peer IPs to use (flags win over neighbor auto-detect),
# one per line, de-duplicated.
bgp_resolve_peers() {
  if [ -n "$BGP_PEERS" ]; then
    printf '%s' "$BGP_PEERS" | tr ',' '\n' | awk 'NF && !seen[$0]++'
    return 0
  fi
  bgp_detect_peers | awk 'NF && !seen[$0]++'
}

# bgp_is_v6 <addr>: succeed if the address looks like IPv6 (contains a colon).
bgp_is_v6() { case "$1" in *:*) return 0 ;; *) return 1 ;; esac; }

# --- /etc/frr/daemons listener-bind edit ----------------------------------
# bgp_daemons_current_options: the current bgpd_options value (without quotes),
# or empty if there is no bgpd_options line.
bgp_daemons_current_options() {
  local f; f=$(bgp_daemons_path)
  [ -f "$f" ] || return 0
  sed -n 's/^[[:space:]]*bgpd_options[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' "$f" | tail -1
}

# bgp_options_has_bind <options> <ip>: true if options already pin `-l <ip>`.
bgp_options_has_bind() {
  case " $1 " in *" -l $2 "*) return 0 ;; *) return 1 ;; esac
}

# bgp_options_with_bind <options> <ip>: drop any existing `-l <addr>` token(s)
# and append `-l <ip>`. Emits the new options string.
bgp_options_with_bind() {
  printf '%s\n' "$1" | awk -v ip="$2" '
    {
      out = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "-l") { i++; continue }   # skip "-l" and its value
        out = (out == "" ? $i : out " " $i)
      }
      printf "%s%s-l %s\n", out, (out == "" ? "" : " "), ip
    }'
}

# bgp_render_daemons <ip>: emit the full daemons file with bgpd_options carrying
# `-l <ip>`. Adds a bgpd_options line if the file has none.
bgp_render_daemons() {
  local ip=$1 f cur new
  f=$(bgp_daemons_path)
  cur=$(bgp_daemons_current_options)
  new=$(bgp_options_with_bind "$cur" "$ip")
  if grep -qE '^[[:space:]]*bgpd_options[[:space:]]*=' "$f" 2>/dev/null; then
    awk -v val="$new" '
      /^[[:space:]]*bgpd_options[[:space:]]*=/ && !done { print "bgpd_options=\"" val "\""; done=1; next }
      { print }
    ' "$f"
  else
    cat "$f" 2>/dev/null || true
    printf 'bgpd_options="%s"\n' "$new"
  fi
}

# --- firewall: nftables ----------------------------------------------------
# bgp_render_nft <peer-per-line-on-stdin>: emit the managed nft table fragment
# (an atomic flush-and-recreate) restricting tcp/179 to the given peers.
bgp_render_nft() {
  local peers v4 v6
  peers=$(cat)
  v4=$(printf '%s\n' "$peers" | awk 'NF && !/:/{printf "%s%s", sep, $0; sep=", "}')
  v6=$(printf '%s\n' "$peers" | awk 'NF && /:/{printf "%s%s", sep, $0; sep=", "}')
  printf '# Managed by onionarmor (module: bgp-hardening) — do not edit by hand.\n'
  printf 'table inet %s\n' "$BGP_NFT_TABLE"
  printf 'delete table inet %s\n' "$BGP_NFT_TABLE"
  printf 'table inet %s {\n' "$BGP_NFT_TABLE"
  printf '    chain input {\n'
  printf '        type filter hook input priority -10; policy accept;\n'
  [ -n "$v4" ] && printf '        tcp dport 179 ip saddr { %s } accept\n' "$v4"
  [ -n "$v6" ] && printf '        tcp dport 179 ip6 saddr { %s } accept\n' "$v6"
  printf '        tcp dport 179 drop\n'
  printf '    }\n'
  printf '}\n'
}

# bgp_nft_current: the live managed table as nft prints it, or empty.
bgp_nft_current() {
  "$ONIONARMOR_BGP_NFT" list table inet "$BGP_NFT_TABLE" 2>/dev/null || true
}

# --- RPKI + route-map FRR config ------------------------------------------
# bgp_render_rpki_config: the vtysh config lines installing the rpki cache and a
# deny-INVALID / permit-rest inbound route-map. Keeps the full feed (ALLOW_ALL_IN
# is preserved): this map only strips RPKI-invalids, it is not a default-only
# filter. Applying it to neighbors is left to the operator's existing inbound
# policy by design (see README) — we define the map + cache here.
bgp_render_rpki_config() {
  printf 'rpki\n'
  printf ' rpki cache %s %s preference 1\n' "$BGP_RPKI_CACHE_HOST" "$BGP_RPKI_CACHE_PORT"
  printf ' exit\n'
  printf '!\n'
  printf 'route-map %s deny 10\n' "$BGP_RPKI_ROUTEMAP"
  printf ' match rpki invalid\n'
  printf 'route-map %s permit 20\n' "$BGP_RPKI_ROUTEMAP"
  printf '!\n'
}

# bgp_render_norib_config: override the implicit --no_kernel behavior of -l.
# When bgpd starts with -l (listenon), it implicitly enables --no_kernel,
# preventing learned routes from being installed into the kernel. This function
# generates the config to override that default.
bgp_render_norib_config() {
  printf 'router bgp\n'
  printf ' no bgp no-rib\n'
  printf ' exit\n'
  printf '!\n'
}

# bgp_render_gtsm_config <peer-per-line-on-stdin>: per-neighbor ttl-security.
bgp_render_gtsm_config() {
  local p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    printf 'neighbor %s ttl-security hops %s\n' "$p" "$BGP_GTSM_HOPS"
  done
}

# bgp_vtysh_apply <config-lines-on-stdin>: feed config lines to vtysh inside a
# single configure-terminal batch, then persist. Best-effort wrapper used by
# apply for the rpki/route-map/gtsm config.
bgp_vtysh_apply() {
  local line args
  args=$(cat)
  [ -n "$args" ] || return 0
  # Build a single `vtysh -c "conf t" -c "<line>" ... -c "end"` invocation.
  local -a cmd=("$ONIONARMOR_BGP_VTYSH" -c "configure terminal")
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    cmd+=(-c "$line")
  done <<EOF
$args
EOF
  cmd+=(-c "end")
  "${cmd[@]}" >/dev/null 2>&1 || { warn "vtysh failed to apply BGP config (rpki/route-map/gtsm)"; return 1; }
  "$ONIONARMOR_BGP_VTYSH" -c "write memory" >/dev/null 2>&1 || warn "vtysh 'write memory' failed; config may not persist a reboot"
  return 0
}

# --- FRR version / CVE awareness ------------------------------------------
# bgp_frr_version: the running FRR version string (e.g. 10.5.0), or empty.
bgp_frr_version() {
  "$ONIONARMOR_BGP_VTYSH" -c "show version" 2>/dev/null \
    | sed -n 's/.*FRRouting \([0-9][0-9.]*\).*/\1/p' | head -1
}

# bgp_version_concern <ver>: print "flagged" if the version is on the advisory
# list, "old" if below the fleet minimum, "ok" otherwise, "unknown" if empty.
bgp_version_concern() {
  local ver=$1 f
  [ -n "$ver" ] || { printf 'unknown\n'; return 0; }
  for f in $BGP_FRR_FLAGGED_VERSIONS; do
    [ "$ver" = "$f" ] && { printf 'flagged\n'; return 0; }
  done
  # Numeric major.minor compare against the fleet minimum.
  awk -v v="$ver" -v min="$BGP_FRR_MIN_VERSION" '
    function mm(s,   a){ split(s, a, "."); return a[1] * 1000 + a[2] }
    BEGIN { print (mm(v) < mm(min)) ? "old" : "ok" }'
}

# --- listener bind inspection (audit) -------------------------------------
# bgp_listener_bind: the address bgpd's tcp/179 listener is bound to, via ss.
# Empty if no :179 listener is found.
bgp_listener_bind() {
  "$ONIONARMOR_BGP_SS" -ltnH 2>/dev/null \
    | awk '{ for (i=1;i<=NF;i++) if ($i ~ /:179$/) { a=$i; sub(/:179$/, "", a); print a; exit } }'
}

# bgp_bind_is_wildcard <addr>: true for 0.0.0.0, *, [::] / :: (any-address binds).
bgp_bind_is_wildcard() {
  case "$1" in
    0.0.0.0|"*"|"::"|"[::]"|""|"0.0.0.0%"*) return 0 ;;
    *) return 1 ;;
  esac
}

# --- service helpers (best-effort) ----------------------------------------
bgp_service_active() {
  [ "$("$ONIONARMOR_BGP_SYSTEMCTL" is-active "$1" 2>/dev/null || true)" = "active" ]
}
