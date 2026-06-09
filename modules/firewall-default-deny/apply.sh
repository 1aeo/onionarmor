#!/usr/bin/env bash
# MODULE: firewall default-deny — UFW default-deny inbound (drops scan SYNs, no kernel RST) allowing only detected listeners; 5-min SSH safety latch.
#
# apply.sh — bring inbound under a default-DENY UFW posture. Allows only the
# detected service listeners (SSH auto-detected, tor ORPort/DirPort, BGP peers),
# keeps outbound open for tor, and schedules a 5-minute auto-disable latch so a
# wrong SSH detection cannot lock the operator out. Idempotent; --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

fw_parse_flags "$@"

frontend=$(fw_frontend)            # "ufw" or dies with an install hint
manifest_path=$(fw_manifest_path)
latch_state=$(fw_latch_state_path)

fw_build_manifest                  # sets FW_RULES + FW_UNKNOWN (globals)
rendered=$(fw_render_manifest)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rule manifest + warnings, change nothing.
# ---------------------------------------------------------------------------
if [ "$FW_DRY_RUN" -eq 1 ]; then
  info "dry-run: firewall-default-deny (no host changes)"
  cat <<EOF

PLAN ($frontend)
  default           -> deny incoming / allow outgoing / allow in on lo
  IPv6              -> $([ "$FW_IPV6" -eq 1 ] && echo "enable (v4+v6)" || echo "v4 only")
  SSH port(s)       -> $(fw_ssh_ports | paste -sd, - 2>/dev/null || fw_ssh_ports | tr '\n' ',')
  safety latch      -> $([ "$FW_SAFETY_LATCH" -eq 1 ] && echo "at now + $FW_LATCH_MIN min (ufw disable && restart $ONIONARMOR_FW_SSH_UNIT)" || echo "DISABLED (--no-safety-latch)")

--- rule manifest ($manifest_path) ---
$rendered
EOF
  if [ -n "$FW_UNKNOWN" ]; then
    printf '\nWARNING: unrecognised listener port(s) will be DENIED: %s\n' "$FW_UNKNOWN"
    printf '  Re-run with --allow <port> for any you intend to expose.\n'
  fi
  exit 0
fi

audit_log fw.apply.start "ipv6=$FW_IPV6 latch=$FW_SAFETY_LATCH rules=$(printf '%s' "$FW_RULES" | tr '\n' ';')"
mkdir -p "$ONIONARMOR_FW_STATE_DIR" || die "cannot create state dir $ONIONARMOR_FW_STATE_DIR"

# ---------------------------------------------------------------------------
# Idempotency: if ufw is already active and the manifest is unchanged, there is
# nothing to do — and we must NOT schedule a fresh latch.
# ---------------------------------------------------------------------------
if fw_ufw_is_active && [ -f "$manifest_path" ] && [ "$(cat "$manifest_path")" = "$rendered" ]; then
  info "ufw already active and rule manifest unchanged — nothing to do"
  printf '\n[firewall-default-deny] already applied (no changes).\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# If ufw is active but the manifest changed, reset to remove stale rules.
# ---------------------------------------------------------------------------
if fw_ufw_is_active && [ -f "$manifest_path" ]; then
  info "manifest changed — resetting ufw to remove stale rules"
  "$ONIONARMOR_FW_UFW" disable >/dev/null 2>&1 || die "ufw disable failed before reset — cannot safely proceed"
  "$ONIONARMOR_FW_UFW" --force reset >/dev/null 2>&1 \
    || "$ONIONARMOR_FW_UFW" reset >/dev/null 2>&1 \
    || die "ufw reset failed — cannot apply new rules over stale state"
  audit_log fw.apply.reset "reason=manifest-changed"
fi

# ---------------------------------------------------------------------------
# 1. Configure IPv6 in /etc/default/ufw BEFORE enabling ufw (so rules cover v6).
# ---------------------------------------------------------------------------
if [ -f "$ONIONARMOR_FW_UFW_DEFAULTS" ]; then
  if [ "$FW_IPV6" -eq 1 ]; then
    if ! fw_ipv6_enabled; then
      # Portable in-place edit (no `sed -i` — BSD vs GNU differ): awk to a temp,
      # rewriting any IPV6= line to IPV6=yes, else append it.
      uf_tmp="$ONIONARMOR_FW_UFW_DEFAULTS.tmp.$$"
      if grep -qiE '^[[:space:]]*IPV6=' "$ONIONARMOR_FW_UFW_DEFAULTS"; then
        awk '/^[[:space:]]*IPV6=/ { print "IPV6=yes"; next } { print }' \
          "$ONIONARMOR_FW_UFW_DEFAULTS" > "$uf_tmp" \
          || { rm -f "$uf_tmp"; die "cannot rewrite $ONIONARMOR_FW_UFW_DEFAULTS"; }
      else
        cat "$ONIONARMOR_FW_UFW_DEFAULTS" > "$uf_tmp" || { rm -f "$uf_tmp"; die "cannot read $ONIONARMOR_FW_UFW_DEFAULTS"; }
        printf 'IPV6=yes\n' >> "$uf_tmp"
      fi
      mv "$uf_tmp" "$ONIONARMOR_FW_UFW_DEFAULTS" \
        || { rm -f "$uf_tmp"; die "cannot set IPV6=yes in $ONIONARMOR_FW_UFW_DEFAULTS"; }
      audit_log fw.apply.ipv6 "set=IPV6=yes file=$ONIONARMOR_FW_UFW_DEFAULTS"
      info "enabled IPv6 in $ONIONARMOR_FW_UFW_DEFAULTS"
    fi
  else
    if fw_ipv6_enabled; then
      # Disable IPv6 when --no-ipv6 is specified
      uf_tmp="$ONIONARMOR_FW_UFW_DEFAULTS.tmp.$$"
      if grep -qiE '^[[:space:]]*IPV6=' "$ONIONARMOR_FW_UFW_DEFAULTS"; then
        awk '/^[[:space:]]*IPV6=/ { print "IPV6=no"; next } { print }' \
          "$ONIONARMOR_FW_UFW_DEFAULTS" > "$uf_tmp" \
          || { rm -f "$uf_tmp"; die "cannot rewrite $ONIONARMOR_FW_UFW_DEFAULTS"; }
      else
        cat "$ONIONARMOR_FW_UFW_DEFAULTS" > "$uf_tmp" || { rm -f "$uf_tmp"; die "cannot read $ONIONARMOR_FW_UFW_DEFAULTS"; }
        printf 'IPV6=no\n' >> "$uf_tmp"
      fi
      mv "$uf_tmp" "$ONIONARMOR_FW_UFW_DEFAULTS" \
        || { rm -f "$uf_tmp"; die "cannot set IPV6=no in $ONIONARMOR_FW_UFW_DEFAULTS"; }
      audit_log fw.apply.ipv6 "set=IPV6=no file=$ONIONARMOR_FW_UFW_DEFAULTS"
      info "disabled IPv6 in $ONIONARMOR_FW_UFW_DEFAULTS"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2. Stage the default policies + allow rules while ufw is (possibly) inactive,
#    so enabling never has a window where SSH is denied.
# ---------------------------------------------------------------------------
"$ONIONARMOR_FW_UFW" default deny incoming  >/dev/null 2>&1 || warn "ufw default deny incoming failed"
"$ONIONARMOR_FW_UFW" default allow outgoing >/dev/null 2>&1 || warn "ufw default allow outgoing failed"
"$ONIONARMOR_FW_UFW" allow in on lo         >/dev/null 2>&1 || warn "ufw allow in on lo failed"

while IFS= read -r spec; do
  [ -n "$spec" ] || continue
  # shellcheck disable=SC2086  # spec is a deliberate multi-word ufw rule
  "$ONIONARMOR_FW_UFW" $spec >/dev/null 2>&1 \
    || warn "ufw rule failed: $spec"
done <<EOF
$FW_RULES
EOF
audit_log fw.apply.rules "applied=$(printf '%s' "$FW_RULES" | tr '\n' ';')"

# Warn (loudly) about any listener we are about to DENY.
if [ -n "$FW_UNKNOWN" ]; then
  warn "DENYING unrecognised listener port(s): $FW_UNKNOWN — re-run with --allow <port> to expose any of these"
  audit_log fw.apply.denied-listeners "ports=$FW_UNKNOWN"
fi

# ---------------------------------------------------------------------------
# 3. SAFETY LATCH: schedule an at-job to auto-disable ufw + restart ssh, BEFORE
#    we enable, so a wrong SSH rule cannot lock the operator out for good.
#    Cancel any pending latch first to avoid stacking jobs.
# ---------------------------------------------------------------------------
latch_job=""
if [ "$FW_SAFETY_LATCH" -eq 1 ]; then
  if ! command -v "$ONIONARMOR_FW_AT" >/dev/null 2>&1; then
    die "firewall-default-deny: 'at' not found — needed for the SSH safety latch. Install it (apt install at) or re-run with --no-safety-latch (console access required)."
  fi
  # Cancel any existing latch before scheduling a new one
  old_job=$(fw_latch_pending)
  if [ -n "$old_job" ]; then
    "$ONIONARMOR_FW_ATRM" "$old_job" >/dev/null 2>&1 \
      && info "cancelled previous safety-latch at job $old_job" \
      || warn "could not cancel previous safety-latch at job $old_job"
  fi
  latch_cmd="$ONIONARMOR_FW_UFW disable && $ONIONARMOR_FW_SYSTEMCTL restart $ONIONARMOR_FW_SSH_UNIT"
  latch_out=$(printf '%s\n' "$latch_cmd" | "$ONIONARMOR_FW_AT" now + "$FW_LATCH_MIN" minutes 2>&1 || true)
  latch_job=$(printf '%s\n' "$latch_out" | grep -oE 'job[[:space:]]+[0-9]+' | awk '{print $2}' | head -1)
  if [ -z "$latch_job" ]; then
    audit_log fw.apply.fail "stage=latch-parse output=$latch_out"
    die "could not parse the at job id — refusing to enable without latch tracking (use --no-safety-latch to skip)"
  fi
else
  warn "--no-safety-latch: no auto-disable scheduled — make sure you have console access"
fi

# ---------------------------------------------------------------------------
# 4. Enable ufw (now that rules + latch are in place).
# ---------------------------------------------------------------------------
"$ONIONARMOR_FW_UFW" --force enable >/dev/null 2>&1 \
  || { audit_log fw.apply.fail "stage=enable"; die "ufw --force enable failed — firewall NOT active"; }

# ---------------------------------------------------------------------------
# 5. Write auxiliary state (manifest, latch, IPv6 choice, extra allow) AFTER enable succeeds.
#    Best-effort: warn but return 0 on failure (primary operation already done).
# ---------------------------------------------------------------------------
ipv6_choice_path=$(fw_ipv6_choice_path)
if ! printf '%s\n' "$FW_IPV6" > "$ipv6_choice_path" 2>/dev/null; then
  warn "could not write IPv6 choice to $ipv6_choice_path"
fi

extra_allow_path=$(fw_extra_allow_path)
if ! printf '%s\n' "$FW_EXTRA_ALLOW" > "$extra_allow_path" 2>/dev/null; then
  warn "could not write extra allow ports to $extra_allow_path"
fi

if [ -n "$latch_job" ]; then
  if printf '%s\n' "$latch_job" > "$latch_state" 2>/dev/null; then
    audit_log fw.apply.latch "job=$latch_job minutes=$FW_LATCH_MIN"
    info "scheduled safety latch (at job $latch_job): auto-disable in $FW_LATCH_MIN min"
  else
    warn "could not write latch state to $latch_state (job $latch_job is queued but not tracked)"
  fi
fi

if [ -f "$manifest_path" ] && [ "$(cat "$manifest_path")" = "$rendered" ]; then
  info "manifest already current: $manifest_path"
else
  tmp="$manifest_path.tmp.$$"
  if printf '%s\n' "$rendered" > "$tmp" 2>/dev/null && mv "$tmp" "$manifest_path" 2>/dev/null; then
    audit_log fw.apply.manifest "wrote=$manifest_path"
    info "wrote rule manifest: $manifest_path"
  else
    rm -f "$tmp" 2>/dev/null
    audit_log fw.apply.fail "stage=manifest-write path=$manifest_path"
    die "could not write manifest to $manifest_path — idempotent apply requires this file"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Verify (default on): ufw reports active.
# ---------------------------------------------------------------------------
verify_failed=0
if [ "$FW_VERIFY" -eq 1 ]; then
  if fw_ufw_is_active; then
    info "verify: ufw is active"
  else
    warn "verify: ufw is NOT active after enable"; verify_failed=1
  fi
fi

audit_log fw.apply.done "verify_failed=$verify_failed latch_job=${latch_job:-none}"

cat <<EOF

[firewall-default-deny] applied.
  frontend    : $frontend (default deny incoming / allow outgoing)
  rules       : $(printf '%s' "$FW_RULES" | tr '\n' ' ')
  IPv6        : $([ "$FW_IPV6" -eq 1 ] && echo enabled || echo "v4 only")
  manifest    : $manifest_path
EOF
if [ -n "$latch_job" ]; then
  cat <<EOF

  *** SSH SAFETY LATCH ACTIVE — ufw will auto-disable in $FW_LATCH_MIN minutes. ***
  Confirm your SSH session still works, THEN cancel the latch within $FW_LATCH_MIN min:

      atrm $latch_job
      # (or, generally:)  atrm \$(atq | head -1 | awk '{print \$1}')

  If you do NOT cancel it, the firewall will be disabled automatically.
EOF
fi
cat <<EOF

Check status any time:  onionarmor audit  --module firewall-default-deny
Undo the posture:       onionarmor revert --module firewall-default-deny
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
