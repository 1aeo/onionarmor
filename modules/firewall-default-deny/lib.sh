# shellcheck shell=bash
# SC2034: the colour vars + FW_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/firewall-default-deny/lib.sh — shared helpers for the
# firewall-default-deny module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite can drive the whole module against a
# sandbox with stub binaries (ss, ufw, at, ...), never touching the real host.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_FW_UFW:=ufw}"
: "${ONIONARMOR_FW_SS:=ss}"
: "${ONIONARMOR_FW_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_FW_AT:=at}"
: "${ONIONARMOR_FW_ATQ:=atq}"
: "${ONIONARMOR_FW_ATRM:=atrm}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_FW_SSHD_CONFIG:=/etc/ssh/sshd_config}"
: "${ONIONARMOR_FW_UFW_DEFAULTS:=/etc/default/ufw}"
: "${ONIONARMOR_FW_FRR_CONF:=/etc/frr/frr.conf}"
: "${ONIONARMOR_FW_FRR_DAEMONS:=/etc/frr/daemons}"
: "${ONIONARMOR_FW_STATE_DIR:=/var/lib/onionarmor/firewall-default-deny}"
: "${ONIONARMOR_FW_MANIFEST_NAME:=rules.manifest}"
: "${ONIONARMOR_FW_LATCH_STATE_NAME:=safety-latch.job}"
: "${ONIONARMOR_FW_IPV6_CHOICE_NAME:=ipv6.choice}"
: "${ONIONARMOR_FW_EXTRA_ALLOW_NAME:=extra-allow.state}"

# The unit restarted by the safety latch (sshd). Overridable for distros that
# name it sshd.service.
: "${ONIONARMOR_FW_SSH_UNIT:=ssh}"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_FW_GREEN=$'\033[32m'; OA_FW_YEL=$'\033[33m'; OA_FW_RED=$'\033[31m'; OA_FW_OFF=$'\033[0m'
else
  OA_FW_GREEN=""; OA_FW_YEL=""; OA_FW_RED=""; OA_FW_OFF=""
fi

# Ports always treated as known-safe public listeners (besides the detected SSH
# port). 443 = tor ORPort, 80 = DirPort/ACME. Overridable.
: "${ONIONARMOR_FW_SAFE_PORTS:=80 443}"

# --- flag defaults --------------------------------------------------------
fw_set_defaults() {
  FW_EXTRA_ALLOW=""     # space-separated extra ports the operator opted into
  FW_SSH_PORT_OVERRIDE=""
  FW_IPV6=1
  FW_SAFETY_LATCH=1
  FW_LATCH_MIN=5
  FW_DRY_RUN=0
  FW_VERIFY=1
}

fw_parse_flags() {
  fw_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --allow)            FW_EXTRA_ALLOW="$FW_EXTRA_ALLOW ${2:-}"; shift 2 ;;
      --allow=*)          FW_EXTRA_ALLOW="$FW_EXTRA_ALLOW ${1#--allow=}"; shift ;;
      --ssh-port)         FW_SSH_PORT_OVERRIDE=${2:-}; shift 2 ;;
      --ssh-port=*)       FW_SSH_PORT_OVERRIDE=${1#--ssh-port=}; shift ;;
      --ipv6)             FW_IPV6=1; shift ;;
      --no-ipv6)          FW_IPV6=0; shift ;;
      --safety-latch)     FW_SAFETY_LATCH=1; shift ;;
      --no-safety-latch)  FW_SAFETY_LATCH=0; shift ;;
      --latch-minutes)    FW_LATCH_MIN=${2:-}; shift 2 ;;
      --latch-minutes=*)  FW_LATCH_MIN=${1#--latch-minutes=}; shift ;;
      --dry-run)          FW_DRY_RUN=1; shift ;;
      --verify)           FW_VERIFY=1; shift ;;
      --no-verify)        FW_VERIFY=0; shift ;;
      -h|--help)          fw_usage; exit 0 ;;
      *)                  die "firewall-default-deny: unknown option: $1 (try --help)" ;;
    esac
  done
  fw_validate_flags
}

fw_validate_flags() {
  local p
  case "$FW_LATCH_MIN" in (*[!0-9]*|"") die "firewall-default-deny: --latch-minutes must be numeric: $FW_LATCH_MIN" ;; esac
  [ "$FW_LATCH_MIN" -ge 1 ] || die "firewall-default-deny: --latch-minutes must be >= 1"
  for p in $FW_EXTRA_ALLOW; do
    case "${p%%/*}" in (*[!0-9]*|"") die "firewall-default-deny: --allow expects a TCP port: $p" ;; esac
    # This module manages TCP listeners only, so the emitted rules are always
    # /tcp. Accept a bare port or an explicit /tcp; reject any other proto rather
    # than silently applying it as tcp.
    case "$p" in
      */*) case "${p#*/}" in tcp) : ;; *) die "firewall-default-deny: --allow only supports tcp (this module manages TCP listeners): $p" ;; esac ;;
    esac
  done
  if [ -n "$FW_SSH_PORT_OVERRIDE" ]; then
    case "$FW_SSH_PORT_OVERRIDE" in (*[!0-9]*|"") die "firewall-default-deny: --ssh-port must be numeric: $FW_SSH_PORT_OVERRIDE" ;; esac
  fi
}

fw_usage() {
  cat <<'EOF'
onionarmor apply --module firewall-default-deny [options]   (also: audit, revert)

Bring inbound traffic under a default-DENY UFW posture: drop SYNs to closed
ports (no kernel RST emitted, so port scans leave no onionleak flow and the
attack surface shrinks), while allowing only the detected service listeners
(SSH auto-detected from sshd_config, tor ORPort/DirPort, BGP restricted to
peers). Outbound stays allowed so tor's many connections keep working.

SAFETY: before enabling, schedules an `at` job that runs `ufw disable && restart
ssh` in 5 minutes, so a wrong SSH detection cannot lock you out. The apply prints
the one command to cancel it once you've confirmed your session survives.

OPTIONS
  --allow <port[/tcp]>    Allow an extra inbound TCP port (repeatable). Required
                          for any listener that is not auto-recognised. This
                          module manages TCP only; non-tcp protos are rejected.
  --ssh-port <n>          Override the auto-detected SSH port.
  --no-ipv6               Do not enable UFW IPv6 (default: enable v4+v6).
  --no-safety-latch       Skip the 5-minute auto-disable latch (console access!).
  --latch-minutes <n>     Latch delay in minutes (default: 5).
  --dry-run               Print the plan + rule manifest. Changes nothing.
  --verify / --no-verify  Post-apply verification (default: verify).
  -h, --help              This help.
EOF
}

fw_manifest_path()      { printf '%s/%s\n' "$ONIONARMOR_FW_STATE_DIR" "$ONIONARMOR_FW_MANIFEST_NAME"; }
fw_latch_state_path()   { printf '%s/%s\n' "$ONIONARMOR_FW_STATE_DIR" "$ONIONARMOR_FW_LATCH_STATE_NAME"; }
fw_ipv6_choice_path()   { printf '%s/%s\n' "$ONIONARMOR_FW_STATE_DIR" "$ONIONARMOR_FW_IPV6_CHOICE_NAME"; }
fw_extra_allow_path()   { printf '%s/%s\n' "$ONIONARMOR_FW_STATE_DIR" "$ONIONARMOR_FW_EXTRA_ALLOW_NAME"; }

# fw_frontend: echo "ufw" if ufw is available, else die telling the operator to
# install it. We never silently apt-install ufw (it pulls iptables-persistent).
fw_frontend() {
  if command -v "$ONIONARMOR_FW_UFW" >/dev/null 2>&1; then
    printf 'ufw\n'
    return 0
  fi
  die "firewall-default-deny: ufw not found. Install it first: apt install ufw (we do not install it silently). Raw nftables/iptables fallback is not yet implemented."
}

# fw_ssh_ports: echo the SSH port(s), one per line. Honours --ssh-port, else
# parses 'Port' lines from sshd_config, else defaults to 22.
fw_ssh_ports() {
  if [ -n "$FW_SSH_PORT_OVERRIDE" ]; then
    printf '%s\n' "$FW_SSH_PORT_OVERRIDE"
    return 0
  fi
  local found=""
  if [ -r "$ONIONARMOR_FW_SSHD_CONFIG" ]; then
    found=$(awk 'tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2 }' "$ONIONARMOR_FW_SSHD_CONFIG")
  fi
  if [ -n "$found" ]; then
    printf '%s\n' "$found"
  else
    printf '22\n'
  fi
}

# fw_listeners: print "addr port" for every non-loopback TCP listener, deduped.
# Loopback (127.0.0.0/8, ::1) is skipped — those never need a firewall rule, and
# this is what keeps us off the kernel-reserved-ports metrics ports on loopback.
fw_listeners() {
  "$ONIONARMOR_FW_SS" -tlnH 2>/dev/null | awk '{print $4}' | while IFS= read -r la; do
    [ -n "$la" ] || continue
    local_port=${la##*:}
    addr=${la%:*}
    addr=${addr#[}; addr=${addr%]}
    case "$addr" in
      127.*|::1|"") continue ;;
    esac
    case "$local_port" in (*[!0-9]*|"") continue ;; esac
    printf '%s %s\n' "$addr" "$local_port"
  done | sort -u
}

# fw_bgp_peers: print the BGP peer IPs (neighbor <ip> remote-as) from the FRR
# config, one per line. Empty if none / no config.
fw_bgp_peers() {
  [ -r "$ONIONARMOR_FW_FRR_CONF" ] || return 0
  awk '$1 == "neighbor" && $3 == "remote-as" { print $2 }' "$ONIONARMOR_FW_FRR_CONF" \
    | grep -E '^[0-9a-fA-F.:]+$' | sort -u || true
}

# fw_bgp_bind: echo the bgpd listen IP from /etc/frr/daemons bgpd_options
# (-l <ip> or -A <ip>), or empty.
fw_bgp_bind() {
  [ -r "$ONIONARMOR_FW_FRR_DAEMONS" ] || return 0
  local opts
  opts=$(grep -E '^[[:space:]]*bgpd_options=' "$ONIONARMOR_FW_FRR_DAEMONS" 2>/dev/null | tail -1 || true)
  printf '%s\n' "$opts" | grep -oE '(-l|-A)[[:space:]]+[0-9a-fA-F.:]+' | awk '{print $2}' | head -1 || true
}

# fw_bgp_rules: for a tcp/179 listener, emit the restricted ufw rule spec(s) —
# per-peer source restriction when peers are known, else a destination
# restriction to the bgpd bind IP. Emits nothing (caller warns) if neither.
fw_bgp_rules() {
  local peers bind p
  peers=$(fw_bgp_peers)
  if [ -n "$peers" ]; then
    while IFS= read -r p; do
      [ -n "$p" ] && printf 'allow from %s to any port 179 proto tcp\n' "$p"
    done <<EOF
$peers
EOF
    return 0
  fi
  bind=$(fw_bgp_bind)
  if [ -n "$bind" ]; then
    printf 'allow to %s port 179 proto tcp\n' "$bind"
  fi
}

# fw_build_manifest: compute the host's ufw rule set. Sets two GLOBALS (so it
# must be called directly, NOT in $(...), which would lose them to a subshell):
#   FW_RULES   newline-separated, sorted, deduped ufw rule specs
#   FW_UNKNOWN space-separated listener ports that were neither known-safe nor
#              explicitly --allow'd — left DENIED, and warned about.
FW_RULES=""
FW_UNKNOWN=""
fw_build_manifest() {
  FW_RULES=""
  FW_UNKNOWN=""
  local port addr have_bgp=0 rules="" ssh_set=" "
  local safe_set extra_set extra_ports="" e ep bgp

  safe_set=" $(printf '%s' "$ONIONARMOR_FW_SAFE_PORTS" | tr -s ' ') "
  for e in $FW_EXTRA_ALLOW; do
    ep=${e%%/*}
    [ -n "$ep" ] && extra_ports="$extra_ports $ep"
  done
  extra_set=" $(printf '%s' "$extra_ports" | tr -s ' ') "

  # SSH first — always allowed (the lockout-critical rule).
  while IFS= read -r port; do
    [ -n "$port" ] || continue
    ssh_set="$ssh_set$port "
    rules="$rules
allow $port/tcp"
  done <<EOF
$(fw_ssh_ports)
EOF

  # Each non-loopback listener: allow if SSH / known-safe / --allow, else deny.
  while IFS=' ' read -r addr port; do
    [ -n "$port" ] || continue
    [ "$port" = "179" ] && { have_bgp=1; continue; }    # BGP: restricted below
    case "$ssh_set" in *" $port "*) continue ;; esac
    case "$safe_set" in *" $port "*) rules="$rules
allow $port/tcp"; continue ;; esac
    case "$extra_set" in *" $port "*) rules="$rules
allow $port/tcp"; continue ;; esac
    FW_UNKNOWN="$FW_UNKNOWN $port"
  done <<EOF
$(fw_listeners)
EOF

  # Operator --allow ports that may have no current listener still get a rule.
  for ep in $extra_ports; do
    case "$rules" in *"
allow $ep/tcp"*) : ;; *) rules="$rules
allow $ep/tcp" ;; esac
  done

  # BGP/179: per-peer source restriction, else bind-IP restriction, else denied.
  if [ "$have_bgp" -eq 1 ]; then
    bgp=$(fw_bgp_rules)
    if [ -n "$bgp" ]; then
      rules="$rules
$bgp"
    else
      FW_UNKNOWN="$FW_UNKNOWN 179"
    fi
  fi

  FW_RULES=$(printf '%s\n' "$rules" | sed '/^$/d' | sort -u)
  FW_UNKNOWN=$(printf '%s' "$FW_UNKNOWN" | tr -s ' ' | sed 's/^ *//;s/ *$//')
}

# fw_render_manifest: header + the rule list (FW_RULES must be built first).
fw_render_manifest() {
  printf '# Managed by onionarmor (module: firewall-default-deny) — generated, do not edit.\n'
  printf '# default deny incoming / allow outgoing / allow in on lo, plus:\n'
  printf '%s\n' "$FW_RULES"
}

# fw_ufw_is_active: true if `ufw status` reports active.
fw_ufw_is_active() {
  "$ONIONARMOR_FW_UFW" status 2>/dev/null | head -1 | grep -qi 'Status: active'
}

# fw_ipv6_enabled: true if /etc/default/ufw has IPV6=yes.
fw_ipv6_enabled() {
  [ -r "$ONIONARMOR_FW_UFW_DEFAULTS" ] || return 1
  grep -qiE '^[[:space:]]*IPV6=yes' "$ONIONARMOR_FW_UFW_DEFAULTS"
}

# fw_latch_pending: echo the pending safety-latch at-job id if our recorded job
# is still queued, else empty.
fw_latch_pending() {
  local f job
  f=$(fw_latch_state_path)
  [ -f "$f" ] || return 0
  job=$(cat "$f" 2>/dev/null)
  [ -n "$job" ] || return 0
  if "$ONIONARMOR_FW_ATQ" 2>/dev/null | awk '{print $1}' | grep -qx "$job"; then
    printf '%s\n' "$job"
  fi
}

# fw_read_ipv6_choice: echo "1" if IPv6 was enabled at apply time, "0" if
# disabled, or empty if never applied (then caller uses default).
fw_read_ipv6_choice() {
  local f
  f=$(fw_ipv6_choice_path)
  [ -f "$f" ] && cat "$f" 2>/dev/null || true
}

# fw_read_extra_allow: echo the space-separated list of --allow ports persisted
# at apply time, or empty if never applied or no extra ports were allowed.
fw_read_extra_allow() {
  local f
  f=$(fw_extra_allow_path)
  [ -f "$f" ] && cat "$f" 2>/dev/null || true
}
