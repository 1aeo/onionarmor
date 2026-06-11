# shellcheck shell=bash
# SC2034: the KH_* flag/colour defaults set here are consumed by the apply/audit/
# revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/kernel-hardening/lib.sh — shared helpers for the kernel-hardening
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log, and the existing ONIONARMOR_SYSCTL_DIR /
# ONIONARMOR_SYSCTL_CMD knobs so the module's drop-in lives alongside the other
# managed sysctl files. EVERY external command and filesystem path is overridable
# via env so the bats suite drives the whole module against a sandbox with stub
# binaries, never touching the real host.
#
# WHAT THIS MODULE DOES
#   Writes a KSPP-recommended (Kernel Self-Protection Project) sysctl hardening
#   drop-in and loads it. These keys raise the runtime security posture of the
#   kernel — restrict dmesg/kptr leaks, lock down ptrace/bpf/perf, enable ASLR,
#   and turn on conservative network defaults (syncookies, rp_filter, no source
#   routing/redirects). Pure security uplift, runtime-reversible.
#   Source: https://kspp.github.io/Recommended_Settings

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
# Reuse the same sysctl command knob as the role-based path.
: "${ONIONARMOR_SYSCTL_CMD:=sysctl}"

# --- overridable filesystem paths -----------------------------------------
# Drop-in lives in the same dir as the other managed sysctl files.
: "${ONIONARMOR_KH_DROPIN_NAME:=99-onionarmor-kernel-hardening.conf}"
: "${ONIONARMOR_KH_STATE_DIR:=/var/lib/onionarmor/kernel-hardening}"

# --- the KSPP key set this module manages ---------------------------------
# Order is significant: the drop-in is rendered in exactly this order and the
# audit walks the same list. "key=value" tokens (no spaces) so a simple word
# split yields the pair.
KH_KEYS="
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
kernel.kptr_restrict=2
kernel.perf_event_paranoid=3
net.ipv4.tcp_syncookies=1
kernel.randomize_va_space=2
kernel.yama.ptrace_scope=1
kernel.kexec_load_disabled=1
net.core.bpf_jit_harden=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.log_martians=1
"

# kh_each_key: emit "key value" pairs (space-separated), one per line, in the
# canonical KSPP order. Shared by render/verify/audit so the order is defined
# in exactly one place.
kh_each_key() {
  local pair
  for pair in $KH_KEYS; do
    [ -n "$pair" ] || continue
    printf '%s %s\n' "${pair%%=*}" "${pair#*=}"
  done
}

# --- flag defaults --------------------------------------------------------
kh_set_defaults() {
  KH_DRY_RUN=0
  KH_VERIFY=1
}

# kh_need_val <flag> <count>: die unless a value-taking flag was given an
# argument. (No value-taking flags exist today, but the guard is kept for parity
# with the other modules and to future-proof kh_parse_flags's `shift 2` sites.)
kh_need_val() {
  [ "$2" -ge 2 ] || die "kernel-hardening: $1 requires a value (try --help)"
}

# kh_parse_flags <args...>: populate KH_* from the command line. Shared by all
# three actions (revert ignores the ones that don't apply to it).
kh_parse_flags() {
  kh_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)   KH_DRY_RUN=1; shift ;;
      --verify)    KH_VERIFY=1; shift ;;
      --no-verify) KH_VERIFY=0; shift ;;
      -h|--help)   kh_usage; exit 0 ;;
      *)           die "kernel-hardening: unknown option: $1 (try --help)" ;;
    esac
  done
  kh_validate_flags
}

# kh_validate_flags: nothing to validate yet (no value-taking flags). Kept as a
# named hook so the parse contract matches the other modules.
kh_validate_flags() {
  :
}

kh_usage() {
  cat <<'EOF'
onionarmor apply --module kernel-hardening [options]   (also: audit, revert)

Write and load a KSPP-recommended sysctl hardening drop-in (dmesg/kptr/ptrace/
bpf/perf restrictions, ASLR, and conservative network defaults). DEFAULT-ON,
very-low-risk security uplift; fully runtime-reversible.

OPTIONS
  --dry-run              Print the would-be drop-in + a before/after table of
                         live vs desired values. Changes nothing.
  --verify / --no-verify Post-apply verification of each live sysctl against the
                         KSPP target (default: verify).
  -h, --help             This help.

Source: https://kspp.github.io/Recommended_Settings
EOF
}

# --- paths ----------------------------------------------------------------
# kh_dropin_path -> the managed sysctl.d drop-in path.
kh_dropin_path() {
  printf '%s/%s\n' "$ONIONARMOR_SYSCTL_DIR" "$ONIONARMOR_KH_DROPIN_NAME"
}

# kh_backup_path -> the revert backup path.
kh_backup_path() {
  printf '%s/backup.conf\n' "$ONIONARMOR_KH_STATE_DIR"
}

# --- drop-in render -------------------------------------------------------
# kh_render_dropin: emit the managed sysctl.d drop-in to stdout (header block +
# the KSPP `key = value` lines in canonical order).
kh_render_dropin() {
  printf '# Managed by onionarmor (module: kernel-hardening) — do not edit by hand.\n'
  printf '# KSPP-recommended kernel hardening sysctls: restrict dmesg/kptr/ptrace/\n'
  printf '# bpf/perf, enable ASLR, and apply conservative network defaults.\n'
  printf '# Revert with: onionarmor revert --module kernel-hardening\n'
  printf '# Source: https://kspp.github.io/Recommended_Settings\n'
  kh_each_key | while read -r key val; do
    printf '%s = %s\n' "$key" "$val"
  done
}

# --- sysctl read / normalise ----------------------------------------------
# kh_normalise <val>: collapse internal whitespace to single spaces so values
# like "1\t1\t1" compare equal regardless of spacing.
kh_normalise() {
  printf '%s' "$1" | awk '{$1=$1; print}'
}

# kh_sysctl_runtime <key>: print the live value of <key> (empty if unreadable on
# this kernel — some keys are module/arch-dependent).
kh_sysctl_runtime() {
  "$ONIONARMOR_SYSCTL_CMD" -n "$1" 2>/dev/null || printf ''
}
