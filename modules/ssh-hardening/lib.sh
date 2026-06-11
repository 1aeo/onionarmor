# shellcheck shell=bash
# SC2034: the SSH_* flag defaults + colour vars set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/ssh-hardening/lib.sh — shared helpers for the ssh-hardening module's
# apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log and the oa_status_* audit reporter. EVERY external
# command and filesystem path is overridable via env so the bats suite drives
# the whole module against a sandbox with stub binaries (sshd, ssh-keygen, at,
# systemctl, who, ...), never touching the real host.
#
# WHAT THIS MODULE DOES
#   Drops a Mozilla-OpenSSH-Guidelines hardening config into a sshd_config.d
#   drop-in (no edits to the operator's sshd_config), removes weak DSA/ECDSA host
#   keys, regrows a sub-4096-bit RSA host key, and reloads sshd — but ONLY behind
#   a 5-minute "safety latch": an `at` job that auto-restores the prior config if
#   the operator does not cancel it after confirming their session survived. The
#   loss-of-SSH risk here is the highest of any module, so the latch is on by
#   default and `AllowUsers` preserves whoever is currently logged in.

# --- locate + source the shared common.sh ---------------------------------
# apply/audit/revert are exec'd by bin/onionarmor with ONIONARMOR_PREFIX set,
# but they can also be run directly (tests) — fall back to deriving the prefix
# from this file's location.
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_SSH_SSHD:=sshd}"            # `sshd -t` config test
: "${ONIONARMOR_SSH_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_SSH_AT:=at}"
: "${ONIONARMOR_SSH_ATQ:=atq}"
: "${ONIONARMOR_SSH_ATRM:=atrm}"
: "${ONIONARMOR_SSH_KEYGEN:=ssh-keygen}"
: "${ONIONARMOR_SSH_WHO:=who}"

# --- overridable filesystem paths -----------------------------------------
: "${ONIONARMOR_SSH_SSHD_CONFIG:=/etc/ssh/sshd_config}"
: "${ONIONARMOR_SSH_CONFD_DIR:=/etc/ssh/sshd_config.d}"
: "${ONIONARMOR_SSH_DROPIN_NAME:=99-onionarmor-hardening.conf}"
: "${ONIONARMOR_SSH_HOSTKEY_DIR:=/etc/ssh}"
: "${ONIONARMOR_SSH_STATE_DIR:=/var/lib/onionarmor/ssh-hardening}"
: "${ONIONARMOR_SSH_LATCH_STATE_NAME:=safety-latch.job}"

# The systemd unit reloaded after a config change (ssh on Debian/Ubuntu,
# sshd.service on RHEL). Overridable.
: "${ONIONARMOR_SSH_UNIT:=ssh}"

# Minimum acceptable RSA host-key size; smaller keys are regenerated.
: "${ONIONARMOR_SSH_RSA_MIN_BITS:=4096}"

# --- status colours are provided by lib/common.sh (oa_status_check) --------

# --- the hardened directives this module enforces -------------------------
# Order matters only for human readability of the rendered drop-in. These are
# the Mozilla OpenSSH "modern" guideline values plus relay-operator session
# limits. AllowUsers is rendered separately (host-specific, lockout-critical).
ssh_hardening_directives() {
  cat <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
X11Forwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
UsePAM yes
Protocol 2
MaxAuthTries 3
LoginGraceTime 30s
ClientAliveInterval 300
ClientAliveCountMax 2
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF
}

# --- flag defaults --------------------------------------------------------
ssh_set_defaults() {
  SSH_ALLOW_USERS=""        # space-separated extra users for AllowUsers
  SSH_SAFETY_LATCH=1
  SSH_LATCH_MIN=5
  SSH_HOST_KEYS=1           # manage weak host keys + RSA size
  SSH_DRY_RUN=0
  SSH_VERIFY=1
}

# ssh_need_val <flag> <count>: die unless a value-taking flag was given an arg.
ssh_need_val() {
  [ "$2" -ge 2 ] || die "ssh-hardening: $1 requires a value (try --help)"
}

ssh_parse_flags() {
  ssh_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --allow-user)       ssh_need_val "$1" "$#"; SSH_ALLOW_USERS="$SSH_ALLOW_USERS $2"; shift 2 ;;
      --allow-user=*)     SSH_ALLOW_USERS="$SSH_ALLOW_USERS ${1#--allow-user=}"; shift ;;
      --safety-latch)     SSH_SAFETY_LATCH=1; shift ;;
      --no-safety-latch)  SSH_SAFETY_LATCH=0; shift ;;
      --latch-minutes)    ssh_need_val "$1" "$#"; SSH_LATCH_MIN=$2; shift 2 ;;
      --latch-minutes=*)  SSH_LATCH_MIN=${1#--latch-minutes=}; shift ;;
      --host-keys)        SSH_HOST_KEYS=1; shift ;;
      --no-host-keys)     SSH_HOST_KEYS=0; shift ;;
      --ssh-unit)         ssh_need_val "$1" "$#"; ONIONARMOR_SSH_UNIT=$2; shift 2 ;;
      --ssh-unit=*)       ONIONARMOR_SSH_UNIT=${1#--ssh-unit=}; shift ;;
      --dry-run)          SSH_DRY_RUN=1; shift ;;
      --verify)           SSH_VERIFY=1; shift ;;
      --no-verify)        SSH_VERIFY=0; shift ;;
      -h|--help)          ssh_usage; exit 0 ;;
      *)                  die "ssh-hardening: unknown option: $1 (try --help)" ;;
    esac
  done
  ssh_validate_flags
}

ssh_validate_flags() {
  local u
  case "$SSH_LATCH_MIN" in (*[!0-9]*|"") die "ssh-hardening: --latch-minutes must be numeric: $SSH_LATCH_MIN" ;; esac
  [ "$SSH_LATCH_MIN" -ge 1 ] || die "ssh-hardening: --latch-minutes must be >= 1"
  for u in $SSH_ALLOW_USERS; do
    # Conservative username charset; a bad AllowUsers entry is lockout-grade.
    case "$u" in
      *[!A-Za-z0-9._-]*|"") die "ssh-hardening: invalid --allow-user value: $u" ;;
    esac
  done
}

ssh_usage() {
  cat <<'EOF'
onionarmor apply --module ssh-hardening [options]   (also: audit, revert)

Apply the Mozilla OpenSSH "modern" guidelines to a sshd_config.d drop-in
(99-onionarmor-hardening.conf): disable root/password login, pin modern
KEX/cipher/MAC primitives, tighten session limits, drop weak DSA/ECDSA host
keys, and regrow a sub-4096-bit RSA host key.

SAFETY: this is the highest lockout-risk module. Before reloading sshd it
validates the config with `sshd -t` and schedules a 5-minute `at` job that
auto-restores the prior config if you do not cancel it. AllowUsers preserves
whoever is currently logged in plus any --allow-user you pass, so a key/login
misconfiguration cannot strand you. The apply prints the one command to cancel
the latch once you have confirmed a fresh SSH session still works.

OPTIONS
  --allow-user <name>     Add a user to AllowUsers (repeatable). Detected
                          logged-in users + any existing AllowUsers are kept.
  --no-host-keys          Do not touch host keys (skip DSA/ECDSA removal + RSA
                          regrow); apply only the config drop-in.
  --no-safety-latch       Skip the 5-minute auto-restore latch (console access!).
  --latch-minutes <n>     Latch delay in minutes (default: 5).
  --ssh-unit <name>       systemd unit to reload (default: ssh; RHEL: sshd).
  --dry-run               Print the plan + rendered drop-in. Changes nothing.
  --verify / --no-verify  Post-apply verification (default: verify).
  -h, --help              This help.
EOF
}

# --- paths ----------------------------------------------------------------
ssh_dropin_path()     { printf '%s/%s\n' "$ONIONARMOR_SSH_CONFD_DIR" "$ONIONARMOR_SSH_DROPIN_NAME"; }
ssh_backup_path()     { printf '%s.bak\n' "$(ssh_dropin_path)"; }
ssh_latch_state_path(){ printf '%s/%s\n' "$ONIONARMOR_SSH_STATE_DIR" "$ONIONARMOR_SSH_LATCH_STATE_NAME"; }

# ssh_existing_allow_users: print AllowUsers tokens already configured in the
# operator's sshd_config (and its Include'd drop-ins, EXCLUDING our own), one
# per line. Empty if none.
ssh_existing_allow_users() {
  local our; our=$(ssh_dropin_path)
  {
    [ -r "$ONIONARMOR_SSH_SSHD_CONFIG" ] && \
      awk 'tolower($1)=="allowusers" { for (i=2;i<=NF;i++) print $i }' "$ONIONARMOR_SSH_SSHD_CONFIG"
    if [ -d "$ONIONARMOR_SSH_CONFD_DIR" ]; then
      local f
      for f in "$ONIONARMOR_SSH_CONFD_DIR"/*.conf; do
        [ -e "$f" ] || continue
        [ "$f" = "$our" ] && continue
        awk 'tolower($1)=="allowusers" { for (i=2;i<=NF;i++) print $i }' "$f"
      done
    fi
  } 2>/dev/null | sed '/^$/d' | sort -u || true
}

# ssh_logged_in_users: print currently logged-in non-root users (so hardening
# never strands an active operator session), one per line.
ssh_logged_in_users() {
  "$ONIONARMOR_SSH_WHO" 2>/dev/null | awk '{print $1}' | grep -vx 'root' | sed '/^$/d' | sort -u || true
}

# ssh_allow_user_set: the merged, deduped AllowUsers set (existing ∪ logged-in ∪
# --allow-user), space-separated on one line. Empty when we have no confident
# user to list — in which case apply.sh deliberately omits AllowUsers rather than
# risk locking everyone out.
ssh_allow_user_set() {
  {
    ssh_existing_allow_users
    ssh_logged_in_users
    local u
    for u in $SSH_ALLOW_USERS; do [ -n "$u" ] && printf '%s\n' "$u"; done
  } | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ *$//'
}

# ssh_render_dropin: emit the managed sshd_config.d drop-in to stdout. Includes
# AllowUsers only when ssh_allow_user_set is non-empty.
ssh_render_dropin() {
  local allow; allow=$(ssh_allow_user_set)
  printf '# Managed by onionarmor (module: ssh-hardening) — do not edit by hand.\n'
  printf '# Mozilla OpenSSH "modern" guidelines + relay session limits.\n'
  printf '# Revert with: onionarmor revert --module ssh-hardening\n'
  ssh_hardening_directives
  if [ -n "$allow" ]; then
    printf 'AllowUsers %s\n' "$allow"
  fi
}

# ssh_rsa_bits: print the bit-size of the RSA host key, or empty if absent.
ssh_rsa_bits() {
  local pub="$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_rsa_key.pub"
  [ -r "$pub" ] || return 0
  "$ONIONARMOR_SSH_KEYGEN" -lf "$pub" 2>/dev/null | awk '{print $1}' | head -1
}

# ssh_weak_hostkeys: print the paths of weak DSA/ECDSA host-key files present.
ssh_weak_hostkeys() {
  local f
  for f in "$ONIONARMOR_SSH_HOSTKEY_DIR"/ssh_host_dsa_key* "$ONIONARMOR_SSH_HOSTKEY_DIR"/ssh_host_ecdsa_key*; do
    [ -e "$f" ] && printf '%s\n' "$f"
  done
  return 0
}

# ssh_config_test: run `sshd -t`. Returns sshd's exit status. Overridable stub
# in tests. Honours ONIONARMOR_SKIP_RELOAD only in that callers gate the live
# reload, not the syntax test (a syntax test never touches the running daemon).
ssh_config_test() {
  "$ONIONARMOR_SSH_SSHD" -t 2>&1
}

# ssh_latch_pending: echo the pending safety-latch at-job id if our recorded job
# is still queued, else empty.
ssh_latch_pending() {
  local f job
  f=$(ssh_latch_state_path)
  [ -f "$f" ] || return 0
  job=$(cat "$f" 2>/dev/null)
  [ -n "$job" ] || return 0
  if "$ONIONARMOR_SSH_ATQ" 2>/dev/null | awk '{print $1}' | grep -qx "$job"; then
    printf '%s\n' "$job"
  fi
}

# ssh_latch_command: the shell command the `at` job runs to auto-restore the
# pre-apply config and reload sshd. If a prior drop-in was backed up, restore it;
# otherwise remove our drop-in. Validate with `sshd -t` before reloading so the
# latch never reloads a broken config.
ssh_latch_command() {
  local dropin bak
  dropin=$(ssh_dropin_path)
  bak=$(ssh_backup_path)
  printf "if [ -f '%s' ]; then cp '%s' '%s'; else rm -f '%s'; fi; '%s' -t && '%s' reload '%s'\n" \
    "$bak" "$bak" "$dropin" "$dropin" \
    "$ONIONARMOR_SSH_SSHD" "$ONIONARMOR_SSH_SYSTEMCTL" "$ONIONARMOR_SSH_UNIT"
}
