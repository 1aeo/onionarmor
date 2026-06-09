#!/usr/bin/env bash
# MODULE: systemd-unit hardening — sandbox drop-ins for tor@/onionwarden/onionleak units (auto-reverts a unit that won't restart).
#
# apply.sh — write a 99-onionarmor-hardening.conf [Service] drop-in for each
# present relay unit, daemon-reload, and restart only the affected units.
# Idempotent; supports --dry-run.
#
# SAFETY NET: after restarting a unit, we poll is-active for up to 30s. If the
# unit does not come up (e.g. ReadWritePaths scoped too tight), apply removes
# THAT unit's drop-in, daemon-reloads and restarts it, and exits non-zero — a
# bad scoping decision can never leave a service down.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sh_parse_flags "$@"

# Resolve the unit set up front so dry-run and apply agree. (Portable array
# fill — avoid mapfile so the module runs on bash 3.2 too.)
UNITS=()
while IFS= read -r _u; do [ -n "$_u" ] && UNITS+=("$_u"); done < <(sh_detect_units)

if [ "${#UNITS[@]}" -eq 0 ]; then
  info "systemd-hardening: no managed units present (nothing to do)"
  info "looked for: tor@*.service (enabled instances), $OA_SH_STATIC_UNITS"
  exit 0
fi

# ---------------------------------------------------------------------------
# Dry run: print the plan + every rendered drop-in, change nothing.
# ---------------------------------------------------------------------------
if [ "$SH_DRY_RUN" -eq 1 ]; then
  info "dry-run: systemd-hardening (no host changes)"
  printf '\nPLAN — units to harden:\n'
  for u in "${UNITS[@]}"; do
    printf '  %-32s caps=[%s] rwpaths=[%s]\n' "$u" "$(sh_caps_for_unit "$u")" "$(sh_rwpaths_for_unit "$u")"
  done
  for u in "${UNITS[@]}"; do
    printf '\n--- %s ---\n' "$(sh_dropin_path "$u")"
    sh_render_dropin "$u"
  done
  exit 0
fi

audit_log sh.apply.start "units=${UNITS[*]} no_restart=$SH_NO_RESTART"
mkdir -p "$ONIONARMOR_SH_STATE_DIR" || die "cannot create state dir $ONIONARMOR_SH_STATE_DIR"

# ---------------------------------------------------------------------------
# 1. Write each unit's drop-in (idempotent: skip if byte-identical). Collect the
#    units whose drop-in actually changed — only those get restarted.
# ---------------------------------------------------------------------------
changed=()
skipped=()
for u in "${UNITS[@]}"; do
  dir=$(sh_dropin_dir "$u")
  path=$(sh_dropin_path "$u")
  rendered=$(sh_render_dropin "$u")
  if [ -f "$path" ] && [ "$(cat "$path")" = "$rendered" ]; then
    info "drop-in already current: $path"
    continue
  fi
  if [ -f "$path" ] && ! sh_is_managed_dropin "$path"; then
    warn "drop-in exists but is NOT onionarmor-managed — refusing to overwrite: $path"
    audit_log sh.apply.skip "unit=$u reason=foreign-dropin path=$path"
    skipped+=("$u")
    continue
  fi
  mkdir -p "$dir" || die "cannot create $dir"
  tmp="$path.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$path" || { rm -f "$tmp"; die "cannot move $tmp -> $path"; }
  audit_log sh.apply.dropin "wrote=$path unit=$u"
  info "wrote drop-in: $path"
  changed+=("$u")
done

# ---------------------------------------------------------------------------
# 2. --no-restart: drop-ins are on disk but NOT live. The auto-revert safety net
#    cannot run without a restart, so warn the operator they own the risk.
# ---------------------------------------------------------------------------
if [ "$SH_NO_RESTART" -eq 1 ]; then
  audit_log sh.apply.done "no_restart=1 changed=${changed[*]:-none}"
  warn "--no-restart: drop-ins written but units NOT restarted; the auto-revert safety net is DISABLED"
  warn "restart the affected units yourself and confirm they come up: ${changed[*]:-none}"
  exit 0
fi

if [ "${#changed[@]}" -eq 0 ]; then
  audit_log sh.apply.done "changed=none skipped=${skipped[*]:-none}"
  if [ "${#skipped[@]}" -gt 0 ]; then
    info "no changes: ${#skipped[@]} unit(s) skipped due to foreign drop-ins"
    printf '\n[systemd-hardening] no changes (units skipped due to foreign drop-ins).\n'
  else
    info "all drop-ins already current — nothing to restart"
    printf '\n[systemd-hardening] already applied (no changes).\n'
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# 3. daemon-reload once, then restart ONLY the changed units. After each
#    restart, wait up to 30s for the unit to be active; auto-revert on failure.
# ---------------------------------------------------------------------------
"$ONIONARMOR_SH_SYSTEMCTL" daemon-reload >/dev/null 2>&1 \
  || warn "systemctl daemon-reload returned nonzero (continuing)"

reverted=()
for u in "${changed[@]}"; do
  path=$(sh_dropin_path "$u")
  if "$ONIONARMOR_SH_SYSTEMCTL" restart "$u" >/dev/null 2>&1 && sh_wait_active "$u"; then
    info "restarted + active: $u"
    audit_log sh.apply.restart "unit=$u ok=1"
    continue
  fi

  # --- AUTO-REVERT this unit: its drop-in is suspected of breaking startup. ---
  warn "$u did not become active within ${ONIONARMOR_SH_RESTART_TIMEOUT}s — auto-reverting its drop-in"
  audit_log sh.apply.autorevert "unit=$u stage=detect"
  if ! rm -f "$path"; then
    warn "FATAL: could not remove $path during auto-revert — $u may remain down"
    audit_log sh.apply.autorevert "unit=$u stage=removal-failed"
    reverted+=("$u")
    continue
  fi
  dir=$(sh_dropin_dir "$u")
  rmdir "$dir" 2>/dev/null || true
  "$ONIONARMOR_SH_SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
  if "$ONIONARMOR_SH_SYSTEMCTL" restart "$u" >/dev/null 2>&1 && sh_wait_active "$u"; then
    warn "auto-revert OK: $u is back up WITHOUT hardening (drop-in removed)"
    audit_log sh.apply.autorevert "unit=$u stage=recovered"
  else
    warn "auto-revert restart of $u STILL failed — manual intervention required (systemctl status $u)"
    audit_log sh.apply.autorevert "unit=$u stage=still-down"
  fi
  reverted+=("$u")
done

audit_log sh.apply.done "changed=${changed[*]} reverted=${reverted[*]:-none}"

printf '\n[systemd-hardening] applied.\n'
printf '  hardened : '
for u in "${UNITS[@]}"; do
  case " ${reverted[*]:-} " in *" $u "*) continue ;; esac
  case " ${skipped[*]:-} " in *" $u "*) continue ;; esac
  printf '%s ' "$u"
done
printf '\n'
if [ "${#reverted[@]}" -gt 0 ]; then
  printf '  REVERTED : %s  (would not start hardened — see audit log)\n' "${reverted[*]}"
fi
cat <<EOF

Check status any time:  onionarmor audit  --module systemd-hardening
Undo the posture:       onionarmor revert --module systemd-hardening
EOF

[ "${#reverted[@]}" -eq 0 ] || { warn "one or more units were auto-reverted; review their ReadWritePaths/CapabilityBoundingSet"; exit 2; }
