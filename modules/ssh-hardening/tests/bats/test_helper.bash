# Test helper for the ssh-hardening module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (sshd, systemctl, ssh-keygen, at, atrm) so the suite is fully
# offline, needs no root, and never touches the real host or real sshd. The
# `at`/`atrm` stubs are copied from the firewall-default-deny suite and wired to
# the SHARED safety_latch.sh via ONIONARMOR_AT_CMD/ONIONARMOR_ATRM_CMD/
# ONIONARMOR_LATCH_STATE_DIR. mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04's
# older bats.

setup() {
  MOD_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export MOD_ROOT
  REPO_ROOT="$(cd "$MOD_ROOT/../.." && pwd)"
  export REPO_ROOT
  export ONIONARMOR_PREFIX="$REPO_ROOT"

  APPLY="$MOD_ROOT/apply.sh"
  AUDIT="$MOD_ROOT/audit.sh"
  REVERT="$MOD_ROOT/revert.sh"
  export APPLY AUDIT REVERT

  SB="$(mktemp -d)"
  export SB
  STUB="$SB/stubs"
  export STUB
  mkdir -p "$STUB"

  # --- sandbox paths the module reads/manages ---
  export ONIONARMOR_SSHD_DROPIN_DIR="$SB/etc/ssh/sshd_config.d"
  export ONIONARMOR_SSHD_HOSTKEY_DIR="$SB/etc/ssh"
  export ONIONARMOR_SSHD_STATE_DIR="$SB/var/lib/onionarmor/ssh-hardening"
  export ONIONARMOR_LATCH_STATE_DIR="$SB/var/lib/onionarmor/latch"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  export ONIONARMOR_SSHD_DROPIN_NAME="99-onionarmor-hardening.conf"
  export DROPIN="$ONIONARMOR_SSHD_DROPIN_DIR/$ONIONARMOR_SSHD_DROPIN_NAME"
  export LATCH_DIR="$ONIONARMOR_LATCH_STATE_DIR/ssh-hardening"
  mkdir -p "$ONIONARMOR_SSHD_DROPIN_DIR" "$ONIONARMOR_SSHD_HOSTKEY_DIR"

  # Shorten the latch window so nothing real lingers (also exercises the flag path).
  export ONIONARMOR_LATCH_TIMEOUT_MIN=5

  # at queue + counter (copied from the firewall suite).
  export AT_QUEUE="$SB/at-queue"
  export AT_COUNTER="$SB/at-counter"
  : > "$AT_QUEUE"
  printf '0\n' > "$AT_COUNTER"

  # ssh-keygen knobs: reported RSA bit count for `-lf`, and a log of regen calls.
  export SSHD_RSA_BITS=4096
  export KEYGEN_LOG="$SB/keygen.log"
  : > "$KEYGEN_LOG"
  # systemctl reload log; sshd -t exit code knob.
  export SYSTEMCTL_LOG="$SB/systemctl.log"
  : > "$SYSTEMCTL_LOG"
  export SSHD_T_RC=0

  _build_stubs

  export ONIONARMOR_SSHD_SSHD_CMD="$STUB/sshd"
  export ONIONARMOR_SSHD_SYSTEMCTL="$STUB/systemctl"
  export ONIONARMOR_SSHD_KEYGEN_CMD="$STUB/ssh-keygen"
  export ONIONARMOR_AT_CMD="$STUB/at"
  export ONIONARMOR_ATRM_CMD="$STUB/atrm"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_hostkey <stem>: create a fake host-key pair (private + .pub).
seed_hostkey() {
  printf 'PRIV %s\n' "$1" > "$ONIONARMOR_SSHD_HOSTKEY_DIR/$1"
  printf 'PUB %s\n' "$1"  > "$ONIONARMOR_SSHD_HOSTKEY_DIR/$1.pub"
}

# latch_jobid: echo the recorded latch at-job id, if armed.
latch_jobid() { cat "$LATCH_DIR/jobid" 2>/dev/null || true; }

_build_stubs() {
  # sshd: `-t` validates (exit code from SSHD_T_RC). Anything else is a no-op.
  cat > "$STUB/sshd" <<'EOF'
#!/bin/sh
case "$1" in
  -t) exit "${SSHD_T_RC:-0}" ;;
esac
exit 0
EOF

  # systemctl: record reload/restart invocations for assertions.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${SYSTEMCTL_LOG:-/dev/null}"
exit 0
EOF

  # ssh-keygen:
  #   -lf <file>  -> print "<bits> SHA256:... comment (RSA)" using SSHD_RSA_BITS.
  #   -t rsa ...  -> "regenerate": log the call + create the key files.
  cat > "$STUB/ssh-keygen" <<'EOF'
#!/bin/sh
LOG="${KEYGEN_LOG:-/dev/null}"
mode=""
keyfile=""
prev=""
for a in "$@"; do
  case "$prev" in
    -f) keyfile=$a ;;
  esac
  case "$a" in
    -lf) mode=fingerprint ;;
    -t)  mode=generate ;;
  esac
  prev=$a
done
# -lf takes the file as the very next token after -lf.
if [ "$mode" = fingerprint ]; then
  f=""
  prev=""
  for a in "$@"; do
    [ "$prev" = "-lf" ] && f=$a
    prev=$a
  done
  printf '%s SHA256:AAAA test@onionarmor (RSA)\n' "${SSHD_RSA_BITS:-4096}"
  exit 0
fi
if [ "$mode" = generate ]; then
  printf 'generate %s\n' "$*" >> "$LOG"
  [ -n "$keyfile" ] && { printf 'PRIV regen\n' > "$keyfile"; printf 'PUB regen\n' > "$keyfile.pub"; }
  exit 0
fi
exit 0
EOF

  # at: enqueue a job id, print "job N at <when>" (firewall suite shape).
  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat >/dev/null
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${AT_QUEUE:?}"
echo "warning: commands will be executed using /bin/sh" >&2
echo "job $n at Mon Jun  8 03:00:00 2026" >&2
exit 0
EOF

  # atrm: remove a job id from the queue.
  cat > "$STUB/atrm" <<'EOF'
#!/bin/sh
q="${AT_QUEUE:?}"; tmp="$q.tmp"
grep -vx "$1" "$q" > "$tmp" 2>/dev/null || :
mv "$tmp" "$q"
exit 0
EOF

  chmod +x "$STUB"/*
}
