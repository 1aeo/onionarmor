# shellcheck shell=bash
# SC2034: the KH_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/kernel-hardening/lib.sh — shared helpers for the kernel-hardening
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log and the existing ONIONARMOR_SYSCTL_DIR /
# ONIONARMOR_SYSCTL_CMD knobs so the module's drop-in lives alongside the
# role-based managed files. EVERY external command and filesystem path is
# overridable via env so the bats suite drives the module against a sandbox with
# a stub sysctl, never touching the real host.
#
# WHAT THIS MODULE DOES
#   Writes the KSPP (Kernel Self-Protection Project) "recommended settings"
#   sysctls to a single sysctl.d drop-in and loads them. These are very-low-risk,
#   broadly-applicable kernel hardening knobs (restrict dmesg/kptr/bpf/perf,
#   ASLR, ptrace scope, kexec lockdown, and the standard network anti-spoofing
#   set). This is the only onionarmor module that is RECOMMENDED-ON by default
#   because nothing here changes the relay's externally observable behaviour.
#   Source: https://kspp.github.io/Recommended_Settings

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_SYSCTL_CMD:=sysctl}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_KH_DROPIN_NAME:=99-onionarmor-kernel-hardening.conf}"
: "${ONIONARMOR_KH_STATE_DIR:=/var/lib/onionarmor/kernel-hardening}"

# --- the KSPP recommended set this module manages -------------------------
# `key value` per line. Order is stable so the rendered drop-in is byte-
# deterministic for idempotency. Kept as policy (not overridable) — these are
# the published KSPP values, not a tunable.
KH_TARGETS="kernel.dmesg_restrict 1
kernel.unprivileged_bpf_disabled 1
kernel.kptr_restrict 2
kernel.perf_event_paranoid 3
kernel.randomize_va_space 2
kernel.yama.ptrace_scope 1
kernel.kexec_load_disabled 1
net.core.bpf_jit_harden 2
net.ipv4.tcp_syncookies 1
net.ipv4.conf.all.rp_filter 1
net.ipv4.conf.all.accept_source_route 0
net.ipv6.conf.all.accept_source_route 0
net.ipv4.conf.all.accept_redirects 0
net.ipv6.conf.all.accept_redirects 0
net.ipv4.conf.all.send_redirects 0
net.ipv4.conf.all.log_martians 1"

# --- flag defaults --------------------------------------------------------
kh_set_defaults() {
  KH_DRY_RUN=0
  KH_VERIFY=1
}

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
}

kh_usage() {
  cat <<'EOF'
onionarmor apply --module kernel-hardening [options]   (also: audit, revert)

Write the KSPP recommended kernel-hardening sysctls to
/etc/sysctl.d/99-onionarmor-kernel-hardening.conf and load them with
`sysctl --system`. Very low risk; RECOMMENDED-ON by default. Idempotent.

Managed sysctls (KSPP — https://kspp.github.io/Recommended_Settings):
  kernel.dmesg_restrict=1            kernel.unprivileged_bpf_disabled=1
  kernel.kptr_restrict=2            kernel.perf_event_paranoid=3
  kernel.randomize_va_space=2       kernel.yama.ptrace_scope=1
  kernel.kexec_load_disabled=1      net.core.bpf_jit_harden=2
  net.ipv4.tcp_syncookies=1         net.ipv4.conf.all.rp_filter=1
  net.ipv4/ipv6.conf.all.accept_source_route=0
  net.ipv4/ipv6.conf.all.accept_redirects=0
  net.ipv4.conf.all.send_redirects=0    net.ipv4.conf.all.log_martians=1

OPTIONS
  --dry-run              Print the would-be drop-in + planned sysctl call and a
                         before/after of each key. Changes nothing.
  --verify / --no-verify Post-apply verification of the live values (default on).
  -h, --help             This help.
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

# --- rendering + reading --------------------------------------------------
# kh_render_dropin: emit the managed sysctl.d drop-in to stdout.
kh_render_dropin() {
  printf '# Managed by onionarmor (module: kernel-hardening) — do not edit by hand.\n'
  printf '# KSPP recommended kernel-hardening sysctls. Source:\n'
  printf '#   https://kspp.github.io/Recommended_Settings\n'
  printf '# Revert with: onionarmor revert --module kernel-hardening\n'
  printf '%s\n' "$KH_TARGETS" | while read -r key val; do
    [ -n "$key" ] || continue
    printf '%s = %s\n' "$key" "$val"
  done
}

# kh_sysctl_runtime <key>: the live value of <key> (empty if unreadable).
kh_sysctl_runtime() {
  "$ONIONARMOR_SYSCTL_CMD" -n "$1" 2>/dev/null || printf ''
}

# kh_norm <val>: collapse internal whitespace so kernel tab-separated multi-value
# reads compare equal regardless of spacing.
kh_norm() {
  printf '%s' "$1" | awk '{$1=$1; print}'
}
