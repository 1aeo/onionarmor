# Test helper for the account-hygiene module bats suite.
#
# Builds a throwaway sandbox with stub account tools (getent/usermod/passwd/
# gpasswd) backed by a fake passwd + group + lock database, plus at/atrm stubs
# (copied from the firewall module) so the shared safety latch schedules against
# a queue file instead of real atd. Fully offline; needs no root; NEVER touches
# the real host's accounts. mktemp -d (not $BATS_TEST_TMPDIR) for ubuntu-22.04's
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

  # --- fake account databases the stubs read/mutate ---
  # passwd db: "name:x:uid:gid" lines.  group db: "name:x:gid:m1,m2".
  # locks db: one locked username per line.
  export AH_PASSWD_DB="$SB/passwd"
  export AH_GROUP_DB="$SB/group"
  export AH_LOCK_DB="$SB/locks"
  : > "$AH_PASSWD_DB"; : > "$AH_GROUP_DB"; : > "$AH_LOCK_DB"

  # Baseline host: root (UID 0) + one operator account, empty sudo/wheel/admin.
  add_account root 0
  add_account operator 1000
  add_group sudo 27 ""
  add_group wheel 998 ""
  add_group admin 999 ""

  # --- sandbox paths the module reads/manages ---
  export ONIONARMOR_AH_ALLOWLIST="$SB/etc/onionarmor/sudo-allowlist.conf"
  export ONIONARMOR_AH_SUDOERS_D="$SB/etc/sudoers.d"
  export ONIONARMOR_AH_STATE_DIR="$SB/var/lib/onionarmor/account-hygiene"
  export ONIONARMOR_AUDIT_LOG="$SB/var/log/onionarmor/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  mkdir -p "$(dirname "$ONIONARMOR_AH_ALLOWLIST")" "$ONIONARMOR_AH_SUDOERS_D"

  # --- shared safety-latch sandbox (at/atrm + state dir) ---
  export ONIONARMOR_LATCH_STATE_DIR="$SB/var/lib/onionarmor/latch"
  export AT_QUEUE="$SB/at-queue"
  export AT_COUNTER="$SB/at-counter"
  : > "$AT_QUEUE"
  printf '0\n' > "$AT_COUNTER"

  _build_stubs

  export ONIONARMOR_AH_GETENT="$STUB/getent"
  export ONIONARMOR_AH_USERMOD="$STUB/usermod"
  export ONIONARMOR_AH_PASSWD="$STUB/passwd"
  export ONIONARMOR_AH_GPASSWD="$STUB/gpasswd"
  export ONIONARMOR_AT_CMD="$STUB/at"
  export ONIONARMOR_ATRM_CMD="$STUB/atrm"

  # Tests confirm explicitly; default auto-confirm off so bare-apply refusal works.
  unset ONIONARMOR_AUTO_CONFIRM
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

# ---------------------------------------------------------------------------
# Fixture helpers (manipulate the fake DBs from tests).
# ---------------------------------------------------------------------------

# add_account <name> <uid>: append a passwd entry.
add_account() {
  printf '%s:x:%s:%s\n' "$1" "$2" "$2" >> "$AH_PASSWD_DB"
}

# add_group <name> <gid> <members-csv>: append a group entry.
add_group() {
  printf '%s:x:%s:%s\n' "$1" "$2" "$3" >> "$AH_GROUP_DB"
}

# set_group_members <group> <members-csv>: rewrite a group's member list.
set_group_members() {
  local g=$1 m=$2 tmp="$AH_GROUP_DB.tmp.$$"
  awk -F: -v g="$g" -v m="$m" 'BEGIN{OFS=":"} $1==g{$4=m} {print}' "$AH_GROUP_DB" > "$tmp"
  mv "$tmp" "$AH_GROUP_DB"
}

# lock_account <name>: mark an account locked in the lock db.
lock_account() {
  printf '%s\n' "$1" >> "$AH_LOCK_DB"
}

# group_members <group>: print the current member csv (for assertions).
group_members() {
  awk -F: -v g="$1" '$1==g{print $4}' "$AH_GROUP_DB"
}

# is_locked <name>: succeed if account is marked locked.
is_locked() {
  grep -qxF "$1" "$AH_LOCK_DB"
}

# write_allowlist <user>...: write the operator allowlist file.
write_allowlist() {
  : > "$ONIONARMOR_AH_ALLOWLIST"
  printf '# operator sudo allowlist\n' >> "$ONIONARMOR_AH_ALLOWLIST"
  for u in "$@"; do printf '%s\n' "$u" >> "$ONIONARMOR_AH_ALLOWLIST"; done
}

# write_nopasswd_sudoers <file>: drop a blanket NOPASSWD:ALL sudoers.d file.
write_nopasswd_sudoers() {
  printf '%%devs ALL=(ALL) NOPASSWD: ALL\n' > "$ONIONARMOR_AH_SUDOERS_D/$1"
}

# at_queue_count: number of pending at jobs (non-empty lines in the queue file).
at_queue_count() {
  awk 'NF{n++} END{print n+0}' "$AT_QUEUE" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Stub binaries. All read/mutate the fake DB files; never touch the real host.
# ---------------------------------------------------------------------------
_build_stubs() {
  # getent: passwd [name] / group [name], reading the fake DBs.
  cat > "$STUB/getent" <<'EOF'
#!/bin/sh
db=$1; key=$2
case "$db" in
  passwd)
    if [ -n "$key" ]; then grep "^$key:" "${AH_PASSWD_DB:?}" 2>/dev/null; exit $?; fi
    cat "${AH_PASSWD_DB:?}" 2>/dev/null; exit 0 ;;
  group)
    if [ -n "$key" ]; then grep "^$key:" "${AH_GROUP_DB:?}" 2>/dev/null; exit $?; fi
    cat "${AH_GROUP_DB:?}" 2>/dev/null; exit 0 ;;
esac
exit 2
EOF

  # passwd: -S <user> reports lock status ("<u> L|P ..."); -l locks.
  cat > "$STUB/passwd" <<'EOF'
#!/bin/sh
case "$1" in
  -S) u=$2
      if grep -qxF "$u" "${AH_LOCK_DB:?}" 2>/dev/null; then st=L; else st=P; fi
      printf '%s %s 2026-01-01 0 99999 7 -1\n' "$u" "$st"; exit 0 ;;
  -l) printf '%s\n' "$2" >> "${AH_LOCK_DB:?}"; exit 0 ;;
esac
exit 0
EOF

  # usermod: -L <user> locks; -U <user> unlocks (mutates the lock db).
  cat > "$STUB/usermod" <<'EOF'
#!/bin/sh
case "$1" in
  -L) printf '%s\n' "$2" >> "${AH_LOCK_DB:?}" ;;
  -U) tmp="${AH_LOCK_DB:?}.tmp.$$"; grep -vxF "$2" "$AH_LOCK_DB" > "$tmp" 2>/dev/null || :; mv "$tmp" "$AH_LOCK_DB" ;;
esac
exit 0
EOF

  # gpasswd: -d <user> <group> removes; -a <user> <group> adds. Mutates group db.
  cat > "$STUB/gpasswd" <<'EOF'
#!/bin/sh
op=$1; u=$2; g=$3
DB="${AH_GROUP_DB:?}"
[ -n "$g" ] || exit 2
grep -q "^$g:" "$DB" 2>/dev/null || exit 2
tmp="$DB.tmp.$$"
awk -F: -v g="$g" -v u="$u" -v op="$op" 'BEGIN{OFS=":"}
  $1==g {
    n=split($4, m, ","); out="";
    for (i=1;i<=n;i++) if (m[i]!="" && m[i]!=u) out=(out==""?m[i]:out","m[i]);
    if (op=="-a") out=(out==""?u:out","u);
    $4=out;
  }
  {print}
' "$DB" > "$tmp"
mv "$tmp" "$DB"
exit 0
EOF

  # at: enqueue a job id, print "job N at <when>" on stderr (real `at` shape).
  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat >/dev/null    # consume the scheduled command on stdin
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${AT_QUEUE:?}"
echo "warning: commands will be executed using /bin/sh" >&2
echo "job $n at Mon Jun  8 03:00:00 2026" >&2
exit "${AH_AT_RC:-0}"
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
