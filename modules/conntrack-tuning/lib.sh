# shellcheck shell=bash
# SC2034: the CT_* threshold/flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/conntrack-tuning/lib.sh — shared helpers for the conntrack-tuning
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log + oa_status_check, and the existing
# ONIONARMOR_SYSCTL_DIR / ONIONARMOR_SYSCTL_CMD knobs so the module's drop-in
# lives alongside the other managed sysctl files. EVERY external command and
# filesystem path is overridable via env so the bats suite drives the whole
# module against a sandbox with stub binaries, never touching the real host.
#
# WHAT THIS MODULE DOES
#   A relay running a stateful-firewall stack (e.g. tailscale, which installs
#   nftables `ct state` rules) loads the kernel's `nf_conntrack` connection
#   tracker. The tracker has a fixed-size table sized by net.netfilter.
#   nf_conntrack_max (kernel default 262144). Under exit-relay load (500k+
#   established TCP flows) that table pins full and the kernel drops NEW packets
#   host-wide — DNS lookups time out (including localhost UDP via `lo`), ssh
#   handshakes fail, tor circuit-build failures spike. This module raises the
#   table ceiling, shortens the wasteful 5-day established-flow timeout, and
#   resizes the conntrack hash bucket, persisted across reboots via a sysctl.d
#   drop-in plus a modprobe.d options line.
#
#   AUDIT is INERT on hosts where nf_conntrack is not loaded (no tailscale /
#   stateful nftables rules): it reports n/a and exits 0, since the failure mode
#   cannot occur without the tracker in the kernel. APPLY still writes the
#   persistence drop-ins pre-emptively so the fix is already in place if/when
#   tailscale later rolls to the host and loads the tracker.

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

# --- the sysctl keys this module manages ----------------------------------
CT_KEY_MAX="net.netfilter.nf_conntrack_max"
CT_KEY_TCP_ESTABLISHED="net.netfilter.nf_conntrack_tcp_timeout_established"
CT_KEY_COUNT="net.netfilter.nf_conntrack_count"   # read-only (live table size)

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_SYSCTL_CMD:=sysctl}"

# --- overridable filesystem paths -----------------------------------------
# sysctl drop-in lives in the same dir as the other managed sysctl files.
: "${ONIONARMOR_CT_DROPIN_NAME:=99-conntrack-tuning.conf}"
: "${ONIONARMOR_MODPROBE_DIR:=/etc/modprobe.d}"
: "${ONIONARMOR_CT_MODPROBE_NAME:=nf_conntrack.conf}"
: "${ONIONARMOR_CT_STATE_DIR:=/var/lib/onionarmor/conntrack-tuning}"
# Presence marker for "is nf_conntrack loaded?" — the netfilter sysctl tree only
# exists when the tracker module is in the kernel. Overridable so tests can
# simulate a loaded / not-loaded host without poking the real /proc.
: "${ONIONARMOR_CT_PROC_MARKER:=/proc/sys/net/netfilter/nf_conntrack_max}"

# --- thresholds (overridable; the audit's pass/fail boundaries) -----------
# Targets per the relay-guard remediation: a 2,097,152-entry ceiling (8x the
# kernel default), a 1-day established-flow timeout (vs the dangerous 5-day
# default), and an early-warning utilization band at 70%. ~max/4 hash buckets
# keep the average chain short.
: "${ONIONARMOR_CT_MIN_MAX:=2097152}"
: "${ONIONARMOR_CT_MAX_TCP_ESTABLISHED:=86400}"
: "${ONIONARMOR_CT_UTIL_WARN_PCT:=70}"
: "${ONIONARMOR_CT_HASHSIZE:=524288}"

# --- flag parsing ---------------------------------------------------------
ct_set_defaults() {
  CT_DRY_RUN=0
  CT_VERIFY=1
}

ct_parse_flags() {
  ct_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)    CT_DRY_RUN=1; shift ;;
      --verify)     CT_VERIFY=1; shift ;;
      --no-verify)  CT_VERIFY=0; shift ;;
      -h|--help)    ct_usage; exit 0 ;;
      *)            die "conntrack-tuning: unknown option: $1 (try --help)" ;;
    esac
  done
}

ct_usage() {
  cat <<'EOF'
onionarmor apply --module conntrack-tuning [--dry-run]   (also: audit, revert)

Size the kernel connection tracker (nf_conntrack) for exit-relay load so the
conntrack table cannot pin full and drop packets host-wide. AUDIT is inert
(reports n/a) on hosts where nf_conntrack is not loaded; APPLY writes the
persistence drop-ins pre-emptively so the fix is ready if tailscale later loads
the tracker.

Writes two persistence drop-ins:
  /etc/sysctl.d/99-conntrack-tuning.conf   net.netfilter.nf_conntrack_max +
                                           nf_conntrack_tcp_timeout_established
  /etc/modprobe.d/nf_conntrack.conf        options nf_conntrack hashsize=...

OPTIONS
  --dry-run              Print the planned drop-ins + sysctl reload. Changes
                         nothing on the host.
  --verify / --no-verify Post-apply verification of the live sysctl values
                         (default: verify).
  -h, --help             This help.
EOF
}

# ct_is_uint <val>: succeed iff <val> is a non-negative decimal integer. The
# threshold env overrides flow into sysctl values / arithmetic, so a malformed
# one must be rejected rather than silently written or scored.
ct_is_uint() {
  case "${1-}" in
    ""|*[!0-9]*) return 1 ;;
    *)           return 0 ;;
  esac
}

# --- paths ----------------------------------------------------------------
ct_sysctl_dropin_path()   { printf '%s/%s\n' "$ONIONARMOR_SYSCTL_DIR" "$ONIONARMOR_CT_DROPIN_NAME"; }
ct_modprobe_dropin_path() { printf '%s/%s\n' "$ONIONARMOR_MODPROBE_DIR" "$ONIONARMOR_CT_MODPROBE_NAME"; }
ct_sysctl_backup_path()   { printf '%s/sysctl-dropin.bak\n' "$ONIONARMOR_CT_STATE_DIR"; }
ct_modprobe_backup_path() { printf '%s/modprobe.bak\n' "$ONIONARMOR_CT_STATE_DIR"; }

# --- detection ------------------------------------------------------------
# ct_module_loaded: succeed iff the nf_conntrack tracker is present in the
# kernel (its netfilter sysctl tree exists). When it is absent the table-full
# failure mode cannot occur, so the audit is a graceful n/a.
ct_module_loaded() { [ -e "$ONIONARMOR_CT_PROC_MARKER" ]; }

# --- live sysctl reads ----------------------------------------------------
# ct_sysctl_runtime <key>: the live value of <key> (empty if unreadable).
ct_sysctl_runtime() { "$ONIONARMOR_SYSCTL_CMD" -n "$1" 2>/dev/null || printf ''; }

# --- drop-in render -------------------------------------------------------
ct_render_sysctl_dropin() {
  printf '# Managed by onionarmor (module: conntrack-tuning) — do not edit by hand.\n'
  printf '# Size the nf_conntrack table for exit-relay load so it cannot pin full\n'
  printf '# and drop packets host-wide. See: onionarmor list-modules / module README.\n'
  printf '# Revert with: onionarmor revert --module conntrack-tuning\n'
  printf '%s = %s\n' "$CT_KEY_MAX" "$ONIONARMOR_CT_MIN_MAX"
  printf '%s = %s\n' "$CT_KEY_TCP_ESTABLISHED" "$ONIONARMOR_CT_MAX_TCP_ESTABLISHED"
}

ct_render_modprobe_dropin() {
  printf '# Managed by onionarmor (module: conntrack-tuning) — do not edit by hand.\n'
  printf '# Resize the nf_conntrack hash table; takes effect on the next module load.\n'
  printf 'options nf_conntrack hashsize=%s\n' "$ONIONARMOR_CT_HASHSIZE"
}

# --- audit helpers --------------------------------------------------------
# ct_re <key>: escape a sysctl key's dots for use inside a regex.
ct_re() { printf '%s' "$1" | sed 's/\./\\./g'; }

# ct_sysctl_dropin_has_keys: succeed iff the sysctl drop-in exists AND declares
# both managed net.netfilter.* lines (presence, not value — value drift is
# caught by the live-vs-target checks).
ct_sysctl_dropin_has_keys() {
  local f; f=$(ct_sysctl_dropin_path)
  [ -f "$f" ] || return 1
  grep -Eq "^[[:space:]]*$(ct_re "$CT_KEY_MAX")[[:space:]]*=" "$f" || return 1
  grep -Eq "^[[:space:]]*$(ct_re "$CT_KEY_TCP_ESTABLISHED")[[:space:]]*=" "$f" || return 1
}

# ct_modprobe_has_option: succeed iff the modprobe drop-in exists AND sets the
# nf_conntrack hashsize option.
ct_modprobe_has_option() {
  local f; f=$(ct_modprobe_dropin_path)
  [ -f "$f" ] || return 1
  grep -Eq '^[[:space:]]*options[[:space:]]+nf_conntrack[[:space:]].*hashsize=[0-9]+' "$f"
}
