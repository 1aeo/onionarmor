# Test helper for the firewall-default-deny module bats suite.
#
# Builds a throwaway sandbox with stub binaries for every external command the
# module touches (ss, ufw, at, atq, atrm, systemctl) so the suite is fully
# offline, needs no root, and never changes the real host. The ufw stub is
# stateful (active flag, default policies, rule list) so audit can observe what
# apply did. mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04's older bats.

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
  export UFW_STATE="$SB/ufw-state"
  mkdir -p "$STUB" "$UFW_STATE"

  # --- sandbox paths the module reads/manages ---
  export ONIONARMOR_FW_SSHD_CONFIG="$SB/etc/ssh/sshd_config"
  export ONIONARMOR_FW_UFW_DEFAULTS="$SB/etc/default/ufw"
  export ONIONARMOR_FW_FRR_CONF="$SB/etc/frr/frr.conf"
  export ONIONARMOR_FW_FRR_DAEMONS="$SB/etc/frr/daemons"
  export ONIONARMOR_FW_STATE_DIR="$SB/var/lib/onionarmor/firewall-default-deny"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$(dirname "$ONIONARMOR_FW_SSHD_CONFIG")" \
           "$(dirname "$ONIONARMOR_FW_UFW_DEFAULTS")" \
           "$(dirname "$ONIONARMOR_FW_FRR_CONF")"

  # Defaults: sshd on 22, ufw defaults with IPV6=no, empty listener set.
  printf 'Port 22\nPermitRootLogin no\n' > "$ONIONARMOR_FW_SSHD_CONFIG"
  printf 'IPV6=no\n' > "$ONIONARMOR_FW_UFW_DEFAULTS"
  export FAKE_SS_FILE="$SB/ss-listeners"
  : > "$FAKE_SS_FILE"

  # at queue + counter
  export AT_QUEUE="$SB/at-queue"
  export AT_COUNTER="$SB/at-counter"
  : > "$AT_QUEUE"
  printf '0\n' > "$AT_COUNTER"

  _build_stubs

  export ONIONARMOR_FW_UFW="$STUB/ufw"
  export ONIONARMOR_FW_SS="$STUB/ss"
  export ONIONARMOR_FW_AT="$STUB/at"
  export ONIONARMOR_FW_ATQ="$STUB/atq"
  export ONIONARMOR_FW_ATRM="$STUB/atrm"
  export ONIONARMOR_FW_SYSTEMCTL="$STUB/systemctl"

  # ufw initial state: inactive, no rules.
  printf 'inactive\n' > "$UFW_STATE/active"
  : > "$UFW_STATE/rules"
  printf 'deny\n'  > "$UFW_STATE/default_in"
  printf 'allow\n' > "$UFW_STATE/default_out"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# set_listeners <line>...: replace the fake `ss -tlnH` output. Each arg is a raw
# ss row; use the helper add_listener for convenience.
set_listeners() { : > "$FAKE_SS_FILE"; }
# add_listener <addr> <port>: append a LISTEN row in `ss -tlnH` shape.
add_listener() {
  printf 'LISTEN 0      4096   %s:%s      0.0.0.0:*\n' "$1" "$2" >> "$FAKE_SS_FILE"
}
# add_listener6 <addr-in-brackets-or-bare> <port>: IPv6 row.
add_listener6() {
  printf 'LISTEN 0      128    [%s]:%s     [::]:*\n' "$1" "$2" >> "$FAKE_SS_FILE"
}

# seed_frr_daemons <bind-ip>: write a daemons file with a bgpd_options -l/-A.
seed_frr_daemons() {
  printf 'bgpd=yes\nbgpd_options="-A %s -l %s"\n' "$1" "$1" > "$ONIONARMOR_FW_FRR_DAEMONS"
}
# seed_frr_neighbors <ip>...: write an frr.conf with neighbor remote-as lines.
seed_frr_neighbors() {
  : > "$ONIONARMOR_FW_FRR_CONF"
  for ip in "$@"; do
    printf ' neighbor %s remote-as 64512\n' "$ip" >> "$ONIONARMOR_FW_FRR_CONF"
  done
}

_build_stubs() {
  # ss: ignore args, print the fake listener file.
  cat > "$STUB/ss" <<'EOF'
#!/bin/sh
cat "${FAKE_SS_FILE:?}" 2>/dev/null
exit 0
EOF

  # ufw: stateful front-end emulation.
  cat > "$STUB/ufw" <<'EOF'
#!/bin/sh
S="${UFW_STATE:?}"
# strip a leading --force
[ "$1" = "--force" ] && shift
case "$1" in
  status)
    active=$(cat "$S/active" 2>/dev/null || echo inactive)
    case "$2" in
      verbose)
        echo "Status: $active"
        echo "Logging: on (low)"
        printf 'Default: %s (incoming), %s (outgoing), disabled (routed)\n' \
          "$(cat "$S/default_in" 2>/dev/null || echo deny)" \
          "$(cat "$S/default_out" 2>/dev/null || echo allow)"
        echo
        cat "$S/rules" 2>/dev/null
        ;;
      numbered)
        echo "Status: $active"
        echo
        i=1
        while IFS= read -r r; do
          [ -n "$r" ] || continue
          printf '[%2d] %s\n' "$i" "$r"
          i=$((i + 1))
        done < "$S/rules"
        ;;
      *) echo "Status: $active" ;;
    esac
    ;;
  default)
    case "$2" in
      deny)  echo "$3" | grep -qi incoming && echo deny  > "$S/default_in" ;;
      allow) echo "$3" | grep -qi outgoing && echo allow > "$S/default_out" ;;
      reject) : ;;
    esac
    ;;
  allow)
    shift
    printf '%s ALLOW IN\n' "$*" >> "$S/rules"
    ;;
  enable)  echo active   > "$S/active" ;;
  disable) echo inactive > "$S/active" ;;
  reset)   : > "$S/rules"; echo inactive > "$S/active" ;;
  *) : ;;
esac
exit 0
EOF

  # at: enqueue a job id, print "job N at <when>".
  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat >/dev/null    # consume the scheduled command on stdin
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${AT_QUEUE:?}"
echo "warning: commands will be executed using /bin/sh" >&2
echo "job $n at Mon Jun  8 03:00:00 2026" >&2
exit 0
EOF

  # atq: list queued job ids (id in column 1).
  cat > "$STUB/atq" <<'EOF'
#!/bin/sh
while IFS= read -r j; do
  [ -n "$j" ] && printf '%s\tMon Jun  8 03:00:00 2026 a root\n' "$j"
done < "${AT_QUEUE:?}" 2>/dev/null
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

  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF

  chmod +x "$STUB"/*
}
