#!/usr/bin/env bash
# MODULE: tor-config-baseline — apply a baseline set of safe torrc directives (stats off, signing-key pin, loopback Metrics/ControlPort) in a managed block across every tor instance, never touching operator-domain directives.
#
# apply.sh — for each tor instance, insert-or-replace a clearly-delimited managed
# block of baseline torrc directives, back up the original once, then reload the
# instance. Idempotent (byte-identical -> "already current", no reload);
# --dry-run prints the plan and changes nothing.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

tcb_parse_flags "$@"

instances=$(tcb_instances)
if [ -z "$instances" ]; then
  die "tor-config-baseline: no tor instances found — looked in $ONIONARMOR_TCB_INSTANCES_DIR/*/torrc and $ONIONARMOR_TCB_TORRC"
fi

# ---------------------------------------------------------------------------
# Dry run: per instance, print the rendered block + which directives are added
# vs preserved. Change nothing, never reload.
# ---------------------------------------------------------------------------
if [ "$TCB_DRY_RUN" -eq 1 ]; then
  info "dry-run: tor-config-baseline (no host changes)"
  while IFS=' ' read -r name file; do
    [ -n "$name" ] || continue
    printf '\nINSTANCE %s (%s)\n' "$name" "$file"
    for d in MetricsPort ControlPort; do
      if tcb_has_loopback_port "$d" "$file"; then
        printf '  %-12s -> preserved (operator loopback bind)\n' "$d"
      elif tcb_has_nonloopback_port "$d" "$file"; then
        printf '  %-12s -> NOT overridden (operator NON-loopback bind — warned)\n' "$d"
      else
        printf '  %-12s -> add loopback default\n' "$d"
      fi
    done
    if [ "$TCB_CONFIRM_OMK" -eq 1 ]; then
      printf '  %-12s -> add (confirmed)\n' "OfflineMasterKey"
    else
      printf '  %-12s -> skipped (pass --confirm-offline-master-key)\n' "OfflineMasterKey"
    fi
    printf '  --- rendered managed block ---\n'
    tcb_render_block "$file" | sed 's/^/  /'
  done <<EOF
$instances
EOF
  exit 0
fi

audit_log tcb.apply.start "confirm_omk=$TCB_CONFIRM_OMK instances=$(printf '%s' "$instances" | awk '{print $1}' | tr '\n' ',')"
mkdir -p "$ONIONARMOR_TCB_STATE_DIR" || die "cannot create state dir $ONIONARMOR_TCB_STATE_DIR"

[ "$TCB_CONFIRM_OMK" -eq 1 ] || info "OfflineMasterKey: skipped (pass --confirm-offline-master-key to emit it)"

affected=""        # newline-separated instance names whose torrc changed
verify_failed=0

while IFS=' ' read -r name file; do
  [ -n "$name" ] || continue

  # Warn loudly about a non-loopback operator MetricsPort/ControlPort we refuse
  # to override (operator domain — record a yellow finding, change nothing).
  for d in MetricsPort ControlPort; do
    if ! tcb_has_loopback_port "$d" "$file" && tcb_has_nonloopback_port "$d" "$file"; then
      warn "$name: operator $d is bound to a NON-loopback address — NOT overriding it (left exactly as written)"
      audit_log tcb.apply.nonloopback "instance=$name directive=$d"
    fi
  done

  # Back up the original torrc once (only if no backup yet), before editing.
  backup=$(tcb_backup_path "$name")
  if [ ! -f "$backup" ]; then
    cp -p "$file" "$backup" \
      || audit_fail_die tcb.apply.fail "stage=backup instance=$name" "failed to back up $file -> $backup"
    audit_log tcb.apply.backup "instance=$name from=$file to=$backup"
  fi

  # Insert-or-replace the managed block (strip any existing one, append fresh).
  composed=$(tcb_compose "$file")
  if oa_write_if_changed "$file" "$composed"; then
    audit_log tcb.apply.instance "instance=$name changed=1 torrc=$file"
    info "$name: managed block installed in $file"
    affected="$affected$name
"
  else
    info "$name: already current ($file)"
    audit_log tcb.apply.instance "instance=$name changed=0 torrc=$file"
  fi
done <<EOF
$instances
EOF

# ---------------------------------------------------------------------------
# Reload each affected instance (unless skipped). A reload failure is a warning,
# not a rollback — the torrc is already written; we surface exit 2 under verify.
# ---------------------------------------------------------------------------
reload_failed=0
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
      audit_log tcb.apply.reload "instance=$name target=$target ok=1"
    else
      warn "$name: '$ONIONARMOR_TCB_SYSTEMCTL reload $target' returned nonzero — torrc written but tor may not have picked it up"
      audit_log tcb.apply.reload "instance=$name target=$target ok=0"
      reload_failed=1
    fi
  done <<EOF
$affected
EOF
fi

# ---------------------------------------------------------------------------
# Verify (default on): every instance carries a well-formed managed block.
# ---------------------------------------------------------------------------
if [ "$TCB_VERIFY" -eq 1 ]; then
  while IFS=' ' read -r name file; do
    [ -n "$name" ] || continue
    if tcb_block_present "$file"; then
      info "verify: $name managed block present"
    else
      warn "verify: $name has no well-formed managed block in $file"
      verify_failed=1
    fi
  done <<EOF
$instances
EOF
fi

[ "$reload_failed" -eq 0 ] || verify_failed=1

audit_log tcb.apply.done "verify_failed=$verify_failed reload_failed=$reload_failed"

cat <<EOF

[tor-config-baseline] applied.
  instances : $(printf '%s' "$instances" | awk '{print $1}' | tr '\n' ' ')
  block     : SigningKeyLifetime / DirReq+ConnDirection+ExtraInfo stats off / loopback Metrics+ControlPort
  omk       : $([ "$TCB_CONFIRM_OMK" -eq 1 ] && echo "OfflineMasterKey 1 (confirmed)" || echo "skipped (no --confirm-offline-master-key)")
  state     : $ONIONARMOR_TCB_STATE_DIR

Check status any time:  onionarmor audit  --module tor-config-baseline
Undo the baseline:      onionarmor revert --module tor-config-baseline
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification/reload reported problems above"; exit 2; }
