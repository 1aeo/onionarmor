# shellcheck shell=bash
# SC2034: the SSHD_* flag defaults set here are consumed by the apply/audit/revert
# scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/ssh-hardening/lib.sh — shared helpers for the ssh-hardening module's
# apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log and lib/safety_latch.sh for the 5-minute `at`
# dead-man's switch that protects the operator from a sshd config that locks them
# out on the NEXT login. EVERY external command and filesystem path is overridable
# via env so the bats suite drives the module against a sandbox with stub
# binaries (sshd, systemctl, ssh-keygen, at/atrm), never touching the real host.
#
# WHAT THIS MODULE DOES
#   Writes a Mozilla-OpenSSH-guidelines hardening drop-in to
#   /etc/ssh/sshd_config.d/99-onionarmor-hardening.conf: disables root login and
#   password auth, pins modern Kex/Cipher/MAC/HostKey algorithms, caps auth
#   retries, sets a client-alive timeout, and disables X11/agent/gateway/tunnel
#   forwarding. It also prunes weak host keys (DSA + ECDSA) and regenerates a
#   sub-4096-bit RSA host key. Maps to the onionauditor `ssh-hardness` category.
#   This is a medium-HIGH risk posture (a wrong cipher set or PasswordAuthentication
#   no with no key installed can lock you out) so it is RECOMMENDED-OFF by default
#   and arms the shared safety latch before reloading sshd.
#   Source: https://infosec.mozilla.org/guidelines/openssh

# --- locate + source the shared common.sh + safety latch ------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"
# shellcheck source=../../lib/safety_latch.sh
. "$ONIONARMOR_PREFIX/lib/safety_latch.sh"

# The literal latch module-name passed to oa_latch_* (keep in sync with the dir).
SSHD_LATCH_MODULE="ssh-hardening"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_SSHD_SSHD_CMD:=sshd}"
: "${ONIONARMOR_SSHD_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_SSHD_KEYGEN_CMD:=ssh-keygen}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_SSHD_DROPIN_DIR:=/etc/ssh/sshd_config.d}"
: "${ONIONARMOR_SSHD_DROPIN_NAME:=99-onionarmor-hardening.conf}"
: "${ONIONARMOR_SSHD_STATE_DIR:=/var/lib/onionarmor/ssh-hardening}"
: "${ONIONARMOR_SSHD_HOSTKEY_DIR:=/etc/ssh}"

# The systemd unit reloaded after a config change (sshd). Overridable for distros
# that name it sshd.service.
: "${ONIONARMOR_SSHD_UNIT:=ssh}"

# Minimum acceptable RSA host-key strength. Below this we regenerate at 4096.
: "${ONIONARMOR_SSHD_RSA_MIN_BITS:=4096}"

# --- the Mozilla-OpenSSH hardening directive set this module manages ------
# Byte-deterministic order so the rendered drop-in is stable for idempotency.
# A single overridable here-doc string (policy, but overridable for tests/distros).
: "${ONIONARMOR_SSHD_DIRECTIVES:=PermitRootLogin no
PasswordAuthentication no
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
MaxAuthTries 3
ClientAliveInterval 300
X11Forwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
UsePAM yes}"

# --- flag defaults --------------------------------------------------------
sshd_set_defaults() {
  SSHD_DRY_RUN=0
  SSHD_SAFETY_LATCH=1
  SSHD_CANCEL_LATCH=0
}

# sshd_need_val <flag> <count>: guard a value-taking flag's `shift 2`. Mirrors
# bgp_need_val / sh_need_val.
sshd_need_val() {
  [ "$2" -ge 2 ] || die "ssh-hardening: $1 requires a value (try --help)"
}

sshd_parse_flags() {
  sshd_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)              SSHD_DRY_RUN=1; shift ;;
      --no-safety-latch)      SSHD_SAFETY_LATCH=0; shift ;;
      --safety-latch)         SSHD_SAFETY_LATCH=1; shift ;;
      --cancel-safety-latch)  SSHD_CANCEL_LATCH=1; shift ;;
      --latch-minutes)        sshd_need_val "$1" "$#"; ONIONARMOR_LATCH_TIMEOUT_MIN=$2; shift 2 ;;
      --latch-minutes=*)      ONIONARMOR_LATCH_TIMEOUT_MIN=${1#--latch-minutes=}; shift ;;
      -h|--help)              sshd_usage; exit 0 ;;
      *)                      die "ssh-hardening: unknown option: $1 (try --help)" ;;
    esac
  done
  export ONIONARMOR_LATCH_TIMEOUT_MIN
  case "$ONIONARMOR_LATCH_TIMEOUT_MIN" in
    (*[!0-9]*|"") die "ssh-hardening: --latch-minutes must be numeric: $ONIONARMOR_LATCH_TIMEOUT_MIN" ;;
  esac
  [ "$ONIONARMOR_LATCH_TIMEOUT_MIN" -ge 1 ] || die "ssh-hardening: --latch-minutes must be >= 1"
}

sshd_usage() {
  cat <<'EOF'
onionarmor apply --module ssh-hardening [options]   (also: audit, revert)

Write a Mozilla-OpenSSH-guidelines hardening drop-in to
/etc/ssh/sshd_config.d/99-onionarmor-hardening.conf, validate it with `sshd -t`,
reload sshd, prune weak DSA/ECDSA host keys, and regenerate a sub-4096-bit RSA
host key. Medium-HIGH risk (can lock you out on the next login) — RECOMMENDED-OFF
by default; arms a 5-minute auto-revert safety latch before reloading sshd.

Managed directives (Mozilla — https://infosec.mozilla.org/guidelines/openssh):
  PermitRootLogin no            PasswordAuthentication no
  HostKeyAlgorithms / KexAlgorithms / Ciphers / MACs  (modern set)
  MaxAuthTries 3                ClientAliveInterval 300
  X11Forwarding no             AllowAgentForwarding no
  GatewayPorts no              PermitTunnel no            UsePAM yes

OPTIONS
  --dry-run               Print the rendered drop-in + the planned sshd -t check
                          + the latch plan. Changes nothing.
  --no-safety-latch       Skip the auto-revert latch (CONSOLE ACCESS REQUIRED:
                          a wrong config will lock you out with no auto-recovery).
  --cancel-safety-latch   Cancel a pending auto-revert latch and exit (run this
                          once you've confirmed you can still SSH in).
  --latch-minutes <N>     Auto-revert window in minutes (default 5).
  -h, --help              This help.
EOF
}

# --- paths ----------------------------------------------------------------
# sshd_dropin_path -> the managed sshd_config.d drop-in path.
sshd_dropin_path() {
  printf '%s/%s\n' "$ONIONARMOR_SSHD_DROPIN_DIR" "$ONIONARMOR_SSHD_DROPIN_NAME"
}

# sshd_backup_path -> the pre-apply drop-in backup (so the latch can restore it).
sshd_backup_path() {
  printf '%s/dropin.backup\n' "$ONIONARMOR_SSHD_STATE_DIR"
}

# sshd_preexist_path -> marker recording whether the drop-in pre-existed apply.
sshd_preexist_path() {
  printf '%s/dropin.preexisted\n' "$ONIONARMOR_SSHD_STATE_DIR"
}

# sshd_restore_path -> where the rendered restore script is staged before arming.
sshd_restore_path() {
  printf '%s/restore.sh\n' "$ONIONARMOR_SSHD_STATE_DIR"
}

# --- rendering ------------------------------------------------------------
# sshd_render_dropin: emit the managed sshd_config.d drop-in to stdout.
sshd_render_dropin() {
  printf '# Managed by onionarmor (module: ssh-hardening) — do not edit by hand.\n'
  printf '# Mozilla OpenSSH server hardening guidelines. Source:\n'
  printf '#   https://infosec.mozilla.org/guidelines/openssh\n'
  printf '# Revert with: onionarmor revert --module ssh-hardening\n'
  printf '%s\n' "$ONIONARMOR_SSHD_DIRECTIVES"
}

# sshd_render_restore <dropin> <backup> <preexisted> <sshd-cmd> <systemctl> <unit>:
# emit a self-contained /bin/sh restore script that the latch fires if the
# operator does not cancel: it undoes our drop-in (restore the backup if one
# pre-existed, else remove ours), then validates + reloads sshd. Paths are baked
# in so it runs standalone from the latch state dir with no onionarmor env.
sshd_render_restore() {
  local dropin=$1 backup=$2 preexisted=$3 sshd_cmd=$4 systemctl=$5 unit=$6
  cat <<EOF
#!/bin/sh
# onionarmor ssh-hardening auto-revert (safety latch). Fired by atd if the
# operator did not confirm access and cancel within the latch window.
set -u
DROPIN="$dropin"
BACKUP="$backup"
SSHD="$sshd_cmd"
SYSTEMCTL="$systemctl"
UNIT="$unit"
if [ "$preexisted" = "1" ] && [ -f "\$BACKUP" ]; then
  cp "\$BACKUP" "\$DROPIN" 2>/dev/null || rm -f "\$DROPIN"
else
  rm -f "\$DROPIN"
fi
# Only reload if the resulting config validates, so the auto-revert never leaves
# sshd unable to start.
if "\$SSHD" -t >/dev/null 2>&1; then
  "\$SYSTEMCTL" reload "\$UNIT" >/dev/null 2>&1 || "\$SYSTEMCTL" restart "\$UNIT" >/dev/null 2>&1 || true
fi
exit 0
EOF
}

# --- host-key helpers -----------------------------------------------------
# sshd_rsa_bits <keyfile>: print the RSA host key's bit count via `ssh-keygen
# -lf`, or empty if it cannot be determined. Isolated so tests can stub the bit
# count independently of the keygen "regenerate" path. `ssh-keygen -lf` prints
# e.g. "4096 SHA256:... comment (RSA)"; the first field is the bit count.
sshd_rsa_bits() {
  "$ONIONARMOR_SSHD_KEYGEN_CMD" -lf "$1" 2>/dev/null | awk '{print $1; exit}'
}
