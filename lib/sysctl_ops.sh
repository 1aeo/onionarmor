# shellcheck shell=bash
# lib/sysctl_ops.sh — sysctl read / write / diff helpers.

# sysctl_current <key>: print the current live value, or empty if unreadable.
# Uses $ONIONARMOR_SYSCTL_CMD so tests can substitute a fake.
sysctl_current() {
  local key=$1 v
  v=$("$ONIONARMOR_SYSCTL_CMD" -n "$key" 2>/dev/null) || v=""
  printf '%s' "$v"
}

# sysctl_normalise_value <val>: collapse internal whitespace to a single space
# so values like "1\t1\t1" (kernel.printk) compare equal regardless of spacing.
sysctl_normalise_value() {
  printf '%s' "$1" | awk '{$1=$1; print}'
}

# managed_sysctl_path <role> -> /etc/sysctl.d/99-onionarmor-<role>.conf
managed_sysctl_path() {
  printf '%s/99-onionarmor-%s.conf\n' "$ONIONARMOR_SYSCTL_DIR" "$1"
}

# managed_sysctl_backup_glob <role> -> glob pattern matching backup files
managed_sysctl_backup_glob() {
  printf '%s/99-onionarmor-%s.conf.bak.*\n' "$ONIONARMOR_SYSCTL_DIR" "$1"
}

# write_managed_sysctl <role> <pairs-file>: write the canonical .conf file
# from a `key value` pairs file (one pair per line). Returns non-zero (warning
# the specific reason) on any failure rather than dying internally, so the
# caller can log its own audit `*.fail` line before failing closed. Dying here
# would make that caller-side audit_fail_die unreachable.
write_managed_sysctl() {
  local role=$1 pairs=$2 path tmp
  path=$(managed_sysctl_path "$role")
  mkdir -p "$ONIONARMOR_SYSCTL_DIR" || { warn "cannot create $ONIONARMOR_SYSCTL_DIR"; return 1; }
  tmp="$path.tmp.$$"
  {
    printf '# Managed by onionarmor — do not edit by hand.\n'
    printf '# Role: %s\n' "$role"
    printf '# Written: %s by %s\n' "$(oa_utc_iso)" "$ONIONARMOR_OPERATOR"
    printf '# To roll back: onionarmor rollback --role %s\n\n' "$role"
    awk '{print $1 " = " $2}' "$pairs"
  } > "$tmp" || { rm -f "$tmp"; warn "cannot write $tmp"; return 1; }
  mv "$tmp" "$path" || { warn "cannot move $tmp -> $path"; return 1; }
}

# reload_sysctl: ask the kernel to re-read /etc/sysctl.d. Returns the exit
# status of the sysctl reload so the caller can fail loudly.
reload_sysctl() {
  if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then return 0; fi
  "$ONIONARMOR_SYSCTL_CMD" --system >/dev/null 2>&1
}

# backup_managed_sysctl <role> -> path of backup (or empty if nothing to back up).
backup_managed_sysctl() {
  local role=$1 src dst ts
  src=$(managed_sysctl_path "$role")
  if [ ! -e "$src" ]; then return 0; fi
  ts=$(oa_utc_ts)
  dst="$src.bak.$ts"
  cp -p "$src" "$dst" || die "backup failed: $src -> $dst"
  printf '%s\n' "$dst"
}

# newest_backup <role> -> path of most recent backup, or empty.
newest_backup() {
  local role=$1 g latest=""
  g=$(managed_sysctl_backup_glob "$role")
  # shellcheck disable=SC2086
  for f in $g; do
    [ -e "$f" ] || continue
    [ -z "$latest" ] || [ "$f" \> "$latest" ] && latest=$f
  done
  printf '%s' "$latest"
}
