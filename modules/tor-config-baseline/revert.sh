#!/usr/bin/env bash
# revert.sh — undo the tor-config-baseline posture: for each instance strip the
# managed block (restoring the pre-apply backup byte-for-byte when present), then
# reload that instance. Best-effort; clears module state on success.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

tcb_parse_flags "$@"

instances=$(tcb_instances)

# --- dry-run: preview the revert plan, change nothing -----------------------
if [ "${TCB_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header tor-config-baseline revert
  if [ -z "$instances" ]; then
    oa_would "nothing to revert — no tor instances found"
  else
    would_reload=0
    while IFS=' ' read -r name file; do
      [ -n "$name" ] || continue
      backup=$(tcb_backup_path "$name")
      if [ ! -f "$file" ]; then
        oa_would "$name: skip — torrc $file is gone"
        continue
      fi
      if [ -f "$backup" ]; then
        if cmp -s "$backup" "$file"; then
          oa_would "$name: already matches backup — nothing to restore"
        else
          oa_would "$name: restore original torrc $file from backup $backup"
          would_reload=1
        fi
      elif tcb_block_present "$file"; then
        oa_would "$name: strip the managed block from $file"
        would_reload=1
      else
        oa_would "$name: nothing to do (no backup and no managed block in $file)"
      fi
    done <<EOF
$instances
EOF
    if [ "$would_reload" -eq 1 ]; then
      if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
        oa_would "skip reloads of changed instances (ONIONARMOR_SKIP_RELOAD=yes)"
      else
        oa_would "reload each changed instance"
      fi
    fi
    oa_would "clear module state $ONIONARMOR_TCB_STATE_DIR (only if every instance reverts cleanly)"
  fi
  exit 0
fi

audit_log tcb.revert.start "instances=$(printf '%s' "$instances" | awk '{print $1}' | tr '\n' ',')"

if [ -z "$instances" ]; then
  warn "no tor instances found — nothing to revert"
fi

affected=""        # instances whose torrc we changed back
revert_failed=0

while IFS=' ' read -r name file; do
  [ -n "$name" ] || continue
  backup=$(tcb_backup_path "$name")

  if [ ! -f "$file" ]; then
    warn "$name: torrc $file is gone — skipping"
    continue
  fi

  if [ -f "$backup" ]; then
    # Restore the pre-apply original byte-for-byte.
    if cmp -s "$backup" "$file"; then
      info "$name: already matches backup — nothing to restore"
    else
      cp -p "$backup" "$file" \
        || { warn "$name: failed to restore $backup -> $file"; revert_failed=1; continue; }
      info "$name: restored original torrc from backup"
      affected="$affected$name
"
    fi
    audit_log tcb.revert.instance "instance=$name restored=backup"
  elif tcb_block_present "$file"; then
    # No backup but our block is present — strip just the managed block.
    stripped=$(tcb_strip_block < "$file" | awk '
      { lines[NR] = $0 }
      END { last = NR; while (last > 0 && lines[last] == "") last--
            for (i = 1; i <= last; i++) print lines[i] }')
    if printf '%s\n' "$stripped" > "$file.tmp.$$" && mv "$file.tmp.$$" "$file"; then
      info "$name: stripped managed block (no backup present)"
      audit_log tcb.revert.instance "instance=$name restored=strip"
      affected="$affected$name
"
    else
      rm -f "$file.tmp.$$" 2>/dev/null || true
      warn "$name: failed to strip managed block from $file"
      revert_failed=1
    fi
  else
    info "$name: no managed block and no backup — nothing to do"
  fi
done <<EOF
$instances
EOF

# ---------------------------------------------------------------------------
# Reload each affected instance (unless skipped), so tor drops our directives.
# ---------------------------------------------------------------------------
if [ -z "$affected" ]; then
  info "no torrc changed — nothing to reload"
elif [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping reloads"
else
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    target=$(tcb_reload_target "$name")
    if "$ONIONARMOR_TCB_SYSTEMCTL" reload "$target" >/dev/null 2>&1; then
      info "$name: reloaded $target"
      audit_log tcb.revert.reload "instance=$name target=$target ok=1"
    else
      warn "$name: '$ONIONARMOR_TCB_SYSTEMCTL reload $target' returned nonzero"
      audit_log tcb.revert.reload "instance=$name target=$target ok=0"
    fi
  done <<EOF
$affected
EOF
fi

# ---------------------------------------------------------------------------
# Clear module state (backups) only when every instance reverted cleanly, so a
# partial failure keeps the backups around for a retry.
# ---------------------------------------------------------------------------
if [ "$revert_failed" -eq 0 ] && [ -d "$ONIONARMOR_TCB_STATE_DIR" ]; then
  rm -rf "$ONIONARMOR_TCB_STATE_DIR" 2>/dev/null \
    || warn "could not remove state dir $ONIONARMOR_TCB_STATE_DIR"
fi

audit_log tcb.revert.done "ok=$([ "$revert_failed" -eq 0 ] && echo 1 || echo 0)"

cat <<EOF

[tor-config-baseline] reverted.
  instances : $(printf '%s' "$instances" | awk '{print $1}' | tr '\n' ' ')
  state     : $([ "$revert_failed" -eq 0 ] && echo "cleared ($ONIONARMOR_TCB_STATE_DIR)" || echo "kept for retry ($ONIONARMOR_TCB_STATE_DIR)")

Re-apply the baseline:  onionarmor apply --module tor-config-baseline
EOF

[ "$revert_failed" -eq 0 ] || { warn "revert did not fully complete on one or more instances — re-run revert"; exit 1; }
