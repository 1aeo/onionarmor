# shellcheck shell=bash
# lib/role.sh — role config loading, validation, and parsing.
#
# A role config is a .conf file with optional `# DOC:`, `# REF:`, `# COMPAT:`
# comment lines followed by `key = value` lines. Blank lines and other comments
# are ignored. Parsing yields `key value` pairs on stdout, one per line.

# role_file_for <role-name> -> path
role_file_for() {
  printf '%s/%s.conf\n' "$ONIONARMOR_ROLES_DIR" "$1"
}

# role_validate <role-name>: die unless the role file exists and is readable.
role_validate() {
  local role=$1
  case "$role" in
    "" ) die "role is required (--role <name>)" ;;
    */*|*..*|*$'\n'* ) die "invalid role name: $role" ;;
  esac
  local f; f=$(role_file_for "$role")
  [ -r "$f" ] || die "role config not found or unreadable: $f"
}

# role_list: print one role name per line for every readable .conf in
#            ONIONARMOR_ROLES_DIR.
role_list() {
  local f base
  if [ ! -d "$ONIONARMOR_ROLES_DIR" ]; then return 0; fi
  for f in "$ONIONARMOR_ROLES_DIR"/*.conf; do
    [ -r "$f" ] || continue
    base=$(basename "$f" .conf)
    printf '%s\n' "$base"
  done
}

# role_parse <role-name>: emit `key value` pairs (space-separated) to stdout,
# one per line. Skips comments and blanks. Trims trailing comments on the
# value line.
role_parse() {
  local role=$1 f
  f=$(role_file_for "$role")
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      # split on first =
      idx = index($0, "=")
      if (idx == 0) next
      k = substr($0, 1, idx-1)
      v = substr($0, idx+1)
      # strip inline # comment from v
      hi = index(v, "#"); if (hi > 0) v = substr(v, 1, hi-1)
      # trim
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (k == "" || v == "") next
      print k, v
    }
  ' "$f"
}

# host_role_file_path -> path of /etc/onionarmor/role.conf
host_role_file_path() { printf '%s/role.conf\n' "$ONIONARMOR_ETC_DIR"; }

# host_role_read -> the value of `role=` in /etc/onionarmor/role.conf, or empty.
host_role_read() {
  local f; f=$(host_role_file_path)
  [ -r "$f" ] || return 0
  awk -F= '
    /^[[:space:]]*#/ { next }
    $1 ~ /^[[:space:]]*role[[:space:]]*$/ {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
      print $2; exit
    }
  ' "$f"
}

# host_role_assert <role>: die unless /etc/onionarmor/role.conf confirms <role>.
# This is the cross-check that prevents "I typed --role tor-relay on a
# workstation by mistake".
host_role_assert() {
  local want=$1 have f
  f=$(host_role_file_path)
  have=$(host_role_read)
  if [ -z "$have" ]; then
    die "host role is not declared. Create $f with a single line: role=$want
(this confirms the host is intentionally classified as a '$want'; apply
is refused until this file exists)"
  fi
  if [ "$have" != "$want" ]; then
    die "host role mismatch: $f says role=$have but --role=$want
(refuse to apply a $want profile to a host classified as $have)"
  fi
}
