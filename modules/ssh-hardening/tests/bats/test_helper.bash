# Test helper for the ssh-hardening module bats suite.
#
# Builds a throwaway sandbox with stub binaries (sshd, ssh-keygen, at, atq,
# atrm, systemctl, who) so the module's apply/audit/revert run fully offline and
# never touch the real host or the real sshd. mktemp -d (not $BATS_TEST_TMPDIR)
# for compatibility with the older bats on ubuntu-22.04.

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
  mkdir -p "$STUB"

  # --- sandbox paths the module manages ---
  export ONIONARMOR_SSH_CONFD_DIR="$SB/etc/ssh/sshd_config.d"
  export ONIONARMOR_SSH_SSHD_CONFIG="$SB/etc/ssh/sshd_config"
  export ONIONARMOR_SSH_HOSTKEY_DIR="$SB/etc/ssh"
  export ONIONARMOR_SSH_STATE_DIR="$SB/var/lib/onionarmor/ssh-hardening"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  export ONIONARMOR_SSH_UNIT="ssh"
  : "${ONIONARMOR_SSH_DROPIN_NAME:=99-onionarmor-hardening.conf}"
  export ONIONARMOR_SSH_DROPIN_NAME
  export DROPIN="$ONIONARMOR_SSH_CONFD_DIR/$ONIONARMOR_SSH_DROPIN_NAME"

  mkdir -p "$ONIONARMOR_SSH_CONFD_DIR" "$ONIONARMOR_SSH_HOSTKEY_DIR" \
           "$(dirname "$ONIONARMOR_AUDIT_LOG")"
  : > "$ONIONARMOR_SSH_SSHD_CONFIG"

  # Stub-state files.
  export SSHD_INVALID="$SB/sshd-invalid"        # presence => `sshd -t` fails
  export RSA_BITS_FILE="$SB/rsa-bits"            # current RSA host-key size
  export WHO_USERS="$SB/who-users"              # logged-in users (one per line)
  export ATQ_FILE="$SB/atq"                     # pending at jobs
  export AT_COUNTER="$SB/at-counter"
  export SYSTEMCTL_LOG="$SB/systemctl.log"
  : > "$ATQ_FILE"; : > "$WHO_USERS"; : > "$SYSTEMCTL_LOG"; printf '6\n' > "$AT_COUNTER"

  _build_stubs
  export ONIONARMOR_SSH_SSHD="$STUB/sshd"
  export ONIONARMOR_SSH_KEYGEN="$STUB/ssh-keygen"
  export ONIONARMOR_SSH_AT="$STUB/at"
  export ONIONARMOR_SSH_ATQ="$STUB/atq"
  export ONIONARMOR_SSH_ATRM="$STUB/atrm"
  export ONIONARMOR_SSH_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_SSH_WHO="$STUB/who"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_login <user...> : mark these users as currently logged in (for AllowUsers).
seed_login() { printf '%s\n' "$@" > "$WHO_USERS"; }

# seed_rsa <bits> : create an RSA host key reporting <bits> via ssh-keygen -lf.
seed_rsa() {
  printf '%s\n' "$1" > "$RSA_BITS_FILE"
  printf 'PRIVATE\n' > "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_rsa_key"
  printf 'ssh-rsa AAAA fake\n' > "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_rsa_key.pub"
}

# seed_weak_hostkeys : create DSA + ECDSA host keys the module should remove.
seed_weak_hostkeys() {
  for t in dsa ecdsa; do
    printf 'PRIVATE\n' > "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_${t}_key"
    printf 'ssh-%s AAAA fake\n' "$t" > "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_${t}_key.pub"
  done
}

# force_sshd_invalid : make the next `sshd -t` fail.
force_sshd_invalid() { : > "$SSHD_INVALID"; }
clear_sshd_invalid() { rm -f "$SSHD_INVALID"; }

dropin_has() { grep -qiE "$1" "$DROPIN"; }

_build_stubs() {
  cat > "$STUB/sshd" <<'EOF'
#!/bin/sh
# `sshd -t` succeeds unless the sentinel file exists.
if [ -f "${SSHD_INVALID:-/nonexistent}" ]; then
  echo "sshd: stub: forced invalid config" >&2
  exit 255
fi
exit 0
EOF

  cat > "$STUB/ssh-keygen" <<'EOF'
#!/bin/sh
# -lf <pub> : print "<bits> SHA256:... (RSA)" using the sandbox RSA_BITS_FILE.
# -t rsa -b <bits> -f <path> : (re)generate a key + record the new bit size.
mode=""; bits=""; outfile=""
while [ $# -gt 0 ]; do
  case "$1" in
    -l) mode=fingerprint ;;
    -f) outfile=$2; shift ;;
    -b) bits=$2; shift ;;
    -lf) mode=fingerprint; outfile=$2; shift ;;
    *) : ;;
  esac
  shift
done
if [ "$mode" = fingerprint ]; then
  b=$(cat "${RSA_BITS_FILE:-/nonexistent}" 2>/dev/null || echo 2048)
  echo "$b SHA256:AAAAfakefingerprint stub (RSA)"
  exit 0
fi
# generate
if [ -n "$outfile" ]; then
  printf 'PRIVATE\n' > "$outfile"
  printf 'ssh-rsa AAAA regen\n' > "$outfile.pub"
  [ -n "$bits" ] && printf '%s\n' "$bits" > "${RSA_BITS_FILE:-/dev/null}"
fi
exit 0
EOF

  cat > "$STUB/at" <<'EOF'
#!/bin/sh
# Consume the command on stdin, allocate a job id, record it in ATQ_FILE, and
# print "job <n> at <when>" the way real `at` does (to stderr).
cat >/dev/null
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 6)
n=$((n + 1)); printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${ATQ_FILE:?}"
echo "job $n at Thu Jan  1 00:00:00 2026" >&2
exit 0
EOF

  cat > "$STUB/atq" <<'EOF'
#!/bin/sh
# Print one "<job> <when>" line per pending job.
while IFS= read -r j; do
  [ -n "$j" ] && echo "$j Thu Jan  1 00:00:00 2026 a operator"
done < "${ATQ_FILE:?}"
exit 0
EOF

  cat > "$STUB/atrm" <<'EOF'
#!/bin/sh
# Remove the given job id(s) from ATQ_FILE.
tmp="${ATQ_FILE:?}.tmp.$$"
: > "$tmp"
while IFS= read -r j; do
  keep=1
  for victim in "$@"; do [ "$j" = "$victim" ] && keep=0; done
  [ "$keep" = 1 ] && [ -n "$j" ] && echo "$j" >> "$tmp"
done < "$ATQ_FILE"
mv "$tmp" "$ATQ_FILE"
exit 0
EOF

  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "${SYSTEMCTL_LOG:?}"
exit 0
EOF

  cat > "$STUB/who" <<'EOF'
#!/bin/sh
# Emulate `who`: "<user> tty ..." lines from WHO_USERS.
while IFS= read -r u; do
  [ -n "$u" ] && echo "$u pts/0 2026-01-01 00:00 (198.51.100.10)"
done < "${WHO_USERS:?}"
exit 0
EOF

  chmod +x "$STUB"/*
}
