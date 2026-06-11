# Test helper for the account-hygiene module bats suite.
#
# Builds a throwaway sandbox with a fake account database (passwd/group/locked
# files) and stub binaries (getent, gpasswd, usermod, passwd, userdel, at, atq,
# atrm) so apply/audit/revert run fully offline and never touch real accounts.
# mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04 bats compatibility.

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

  export ONIONARMOR_ACCT_STATE_DIR="$SB/var/lib/onionarmor/account-hygiene"
  export ONIONARMOR_ACCT_SUDOERS_D="$SB/etc/sudoers.d"
  export ONIONARMOR_ACCT_ALLOWLIST="$SB/etc/onionarmor/sudo-allowlist.conf"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  export ONIONARMOR_AUTO_CONFIRM="yes"

  mkdir -p "$ONIONARMOR_ACCT_SUDOERS_D" "$(dirname "$ONIONARMOR_ACCT_ALLOWLIST")" \
           "$(dirname "$ONIONARMOR_AUDIT_LOG")"

  # Fake account DB.
  export ACCT_PASSWD_FILE="$SB/passwd"
  export ACCT_GROUP_FILE="$SB/group"
  export ACCT_LOCKED_FILE="$SB/locked"
  cat > "$ACCT_PASSWD_FILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
operator:x:1000:1000:operator:/home/operator:/bin/bash
EOF
  cat > "$ACCT_GROUP_FILE" <<'EOF'
root:x:0:
sudo:x:27:operator
wheel:x:10:
admin:x:999:
EOF
  : > "$ACCT_LOCKED_FILE"

  # at-stub state.
  export ATQ_FILE="$SB/atq"; export AT_COUNTER="$SB/at-counter"
  : > "$ATQ_FILE"; printf '20\n' > "$AT_COUNTER"

  _build_stubs
  export ONIONARMOR_ACCT_GETENT="$STUB/getent"
  export ONIONARMOR_ACCT_GPASSWD="$STUB/gpasswd"
  export ONIONARMOR_ACCT_USERMOD="$STUB/usermod"
  export ONIONARMOR_ACCT_PASSWD="$STUB/passwd"
  export ONIONARMOR_ACCT_USERDEL="$STUB/userdel"
  export ONIONARMOR_ACCT_AT="$STUB/at"
  export ONIONARMOR_ACCT_ATQ="$STUB/atq"
  export ONIONARMOR_ACCT_ATRM="$STUB/atrm"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# seed_user <name> <uid> : add an account (gid = uid).
seed_user() {
  printf '%s:x:%s:%s:%s:/home/%s:/bin/bash\n' "$1" "$2" "$2" "$1" "$1" >> "$ACCT_PASSWD_FILE"
}

# add_to_group <user> <group> : append user to the group's member list.
add_to_group() { "$STUB/gpasswd" -a "$1" "$2"; }

# add_uid0 <name> : add a shared UID-0 account (a red audit finding).
add_uid0() { printf '%s:x:0:0:%s:/root:/bin/bash\n' "$1" "$1" >> "$ACCT_PASSWD_FILE"; }

# set_allowlist <user...> : write the sudo allowlist.
set_allowlist() { printf '%s\n' "$@" > "$ONIONARMOR_ACCT_ALLOWLIST"; }

# add_nopasswd_all <file> : drop a blanket NOPASSWD: ALL sudoers entry.
add_nopasswd_all() { printf '%%admins ALL=(ALL) NOPASSWD: ALL\n' > "$ONIONARMOR_ACCT_SUDOERS_D/$1"; }

group_members() {
  awk -F: -v g="$1" '$1==g { print $4 }' "$ACCT_GROUP_FILE"
}
is_locked() { grep -qx "$1" "$ACCT_LOCKED_FILE"; }

_build_stubs() {
  cat > "$STUB/getent" <<'EOF'
#!/bin/sh
db=$1; key=$2
case "$db" in
  group)
    if [ -n "$key" ]; then
      line=$(grep "^$key:" "$ACCT_GROUP_FILE" 2>/dev/null)
      [ -n "$line" ] && { echo "$line"; exit 0; }; exit 2
    fi
    cat "$ACCT_GROUP_FILE" 2>/dev/null; exit 0 ;;
  passwd)
    if [ -n "$key" ]; then
      line=$(grep "^$key:" "$ACCT_PASSWD_FILE" 2>/dev/null)
      [ -n "$line" ] && { echo "$line"; exit 0; }; exit 2
    fi
    cat "$ACCT_PASSWD_FILE" 2>/dev/null; exit 0 ;;
esac
exit 0
EOF

  cat > "$STUB/gpasswd" <<'EOF'
#!/bin/sh
op=$1; user=$2; group=$3
tmp="$ACCT_GROUP_FILE.tmp.$$"
awk -F: -v u="$user" -v g="$group" -v op="$op" 'BEGIN{OFS=":"}
{
  if ($1==g) {
    n=split($4,m,","); out="";
    for(i=1;i<=n;i++){ if(m[i]!="" && m[i]!=u){ out=(out==""?m[i]:out","m[i]) } }
    if(op=="-a"){ out=(out==""?u:out","u) }
    $4=out
  }
  print
}' "$ACCT_GROUP_FILE" > "$tmp" && mv "$tmp" "$ACCT_GROUP_FILE"
exit 0
EOF

  cat > "$STUB/usermod" <<'EOF'
#!/bin/sh
case "$1" in
  -L) u=$2; grep -qx "$u" "$ACCT_LOCKED_FILE" 2>/dev/null || echo "$u" >> "$ACCT_LOCKED_FILE" ;;
  -U) u=$2; tmp="$ACCT_LOCKED_FILE.tmp.$$"; grep -vx "$u" "$ACCT_LOCKED_FILE" 2>/dev/null > "$tmp" || true; mv "$tmp" "$ACCT_LOCKED_FILE" ;;
esac
exit 0
EOF

  cat > "$STUB/passwd" <<'EOF'
#!/bin/sh
if [ "$1" = "-S" ]; then
  u=$2
  if grep -qx "$u" "$ACCT_LOCKED_FILE" 2>/dev/null; then echo "$u L 01/01/2026 0 99999 7 -1"; else echo "$u P 01/01/2026 0 99999 7 -1"; fi
fi
exit 0
EOF

  cat > "$STUB/userdel" <<'EOF'
#!/bin/sh
u=$2
tmp="$ACCT_PASSWD_FILE.tmp.$$"; grep -v "^$u:" "$ACCT_PASSWD_FILE" > "$tmp" || true; mv "$tmp" "$ACCT_PASSWD_FILE"
tmp2="$ACCT_GROUP_FILE.tmp.$$"
awk -F: -v u="$u" 'BEGIN{OFS=":"}{ n=split($4,m,","); out=""; for(i=1;i<=n;i++){if(m[i]!="" && m[i]!=u){out=(out==""?m[i]:out","m[i])}} $4=out; print }' "$ACCT_GROUP_FILE" > "$tmp2" && mv "$tmp2" "$ACCT_GROUP_FILE"
exit 0
EOF

  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat >/dev/null
n=$(cat "$AT_COUNTER" 2>/dev/null || echo 20); n=$((n + 1)); printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "$ATQ_FILE"
echo "job $n at Thu Jan  1 00:00:00 2026" >&2
exit 0
EOF

  cat > "$STUB/atq" <<'EOF'
#!/bin/sh
while IFS= read -r j; do [ -n "$j" ] && echo "$j Thu Jan  1 00:00 a operator"; done < "$ATQ_FILE"
exit 0
EOF

  cat > "$STUB/atrm" <<'EOF'
#!/bin/sh
tmp="$ATQ_FILE.tmp.$$"; : > "$tmp"
while IFS= read -r j; do
  keep=1; for v in "$@"; do [ "$j" = "$v" ] && keep=0; done
  [ "$keep" = 1 ] && [ -n "$j" ] && echo "$j" >> "$tmp"
done < "$ATQ_FILE"
mv "$tmp" "$ATQ_FILE"; exit 0
EOF

  chmod +x "$STUB"/*
}
