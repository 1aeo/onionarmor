#!/usr/bin/env bash
# revert.sh — undo the bgp-hardening posture: restore the previous
# /etc/frr/daemons, drop the managed firewall rules, remove the FRR rpki
# cache + route-map, and disable the validator (left INSTALLED, not purged).
# Reloads FRR gracefully at the end.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

bgp_parse_flags "$@"

daemons=$ONIONARMOR_BGP_DAEMONS
backup=$(bgp_daemons_backup_path)
marker=$(bgp_rpki_marker_path)
touched=0

# --- dry-run: preview the revert plan, change nothing -----------------------
# Each real action is gated on an apply-time ownership marker (or the daemons
# backup); the preview mirrors those exact gates so it never claims a change the
# live revert would skip. would_touch tracks whether anything is owned, which is
# what decides the final FRR reload/restart (and whether it happens at all).
if [ "${BGP_DRY_RUN:-0}" -eq 1 ]; then
  oa_dryrun_header bgp-hardening revert
  would_touch=0
  if [ -f "$backup" ]; then
    oa_would "restore $daemons from backup $backup"
    would_touch=1
  else
    oa_would "leave $daemons as-is (no apply-time backup present)"
  fi
  [ -e "$(bgp_firewall_peers_path)" ] && { oa_would "delete nft table inet $BGP_NFT_TABLE and clear the firewall.peers marker"; would_touch=1; }
  [ -e "$marker" ] && { oa_would "remove the FRR rpki cache + route-map (vtysh) and clear $marker"; would_touch=1; }
  [ -e "$(bgp_norib_marker_path)" ] && { oa_would "re-assert 'no bgp no-rib' (vtysh) and clear its marker"; would_touch=1; }
  [ -e "$(bgp_routinator_marker_path)" ] && { oa_would "disable routinator (left installed) and clear its marker"; would_touch=1; }
  [ -e "$(bgp_gtsm_marker_path)" ] && { oa_would "remove GTSM ttl-security config (vtysh) and clear its marker"; would_touch=1; }
  if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
    oa_would "skip FRR reload (ONIONARMOR_SKIP_RELOAD=yes)"
  elif [ "$would_touch" -eq 0 ]; then
    oa_would "make no changes — nothing of ours is present (no FRR reload)"
  elif [ -f "$backup" ]; then
    oa_would "restart FRR (daemons file restored)"
  else
    oa_would "reload FRR"
  fi
  exit 0
fi

audit_log bgp.revert.start "daemons=$daemons firewall=$BGP_FIREWALL"

# ---------------------------------------------------------------------------
# 1. Restore the original /etc/frr/daemons from the apply-time backup.
# ---------------------------------------------------------------------------
daemons_restored=0
if [ -f "$backup" ]; then
  cp -p "$backup" "$daemons" \
    || audit_fail_die bgp.revert.fail "stage=daemons" "failed to restore $daemons from $backup"
  audit_log bgp.revert.daemons "restored=$daemons from=$backup"
  info "restored daemons from $backup"
  touched=1
  daemons_restored=1
else
  warn "no daemons backup at $backup — leaving $daemons as-is"
fi

# ---------------------------------------------------------------------------
# 2. Remove the managed firewall rules (nftables; ufw is out of scope here).
# Only if the module actually created it (check for the firewall.peers marker).
# ---------------------------------------------------------------------------
firewall_peers_marker=$(bgp_firewall_peers_path)
if [ -e "$firewall_peers_marker" ]; then
  # Drop the ownership marker ONLY when the table is actually gone — otherwise a
  # failed delete would lose ownership state while tcp/179 is still filtered.
  fw_table_gone=1
  if [ -n "$(bgp_nft_current)" ]; then
    if "$ONIONARMOR_BGP_NFT" delete table inet "$BGP_NFT_TABLE" >/dev/null 2>&1; then
      audit_log bgp.revert.firewall "removed=nft:$BGP_NFT_TABLE"; info "removed nft table inet $BGP_NFT_TABLE"; touched=1
    else
      warn "could not delete nft table inet $BGP_NFT_TABLE — keeping firewall.peers marker so a re-run retries"
      fw_table_gone=0
    fi
  else
    info "no managed nft table inet $BGP_NFT_TABLE to remove"
  fi
  [ "$fw_table_gone" -eq 1 ] && rm -f "$firewall_peers_marker" 2>/dev/null || true
else
  info "firewall not managed by this module (no ownership marker) — leaving nft table inet $BGP_NFT_TABLE as-is"
fi

# ---------------------------------------------------------------------------
# 3. Remove the FRR rpki cache + route-map; disable (but keep) the validator.
# ---------------------------------------------------------------------------
if [ -e "$marker" ]; then
  # Only clear the marker if vtysh actually removed the live config — otherwise
  # FRR may still hold the onionarmor RPKI settings while audit would report it
  # unconfigured. Keeping the marker lets a re-run retry the removal.
  if {
       printf 'rpki\n'
       printf ' no rpki cache %s %s\n' "$BGP_RPKI_CACHE_HOST" "$BGP_RPKI_CACHE_PORT"
       printf ' exit\n'
       printf 'no route-map %s\n' "$BGP_RPKI_ROUTEMAP"
     } | bgp_vtysh_apply; then
    rm -f "$marker" || true
    audit_log bgp.revert.rpki "removed=$BGP_RPKI_ROUTEMAP"
    info "removed FRR rpki cache + route-map $BGP_RPKI_ROUTEMAP"
    touched=1
  else
    warn "could not remove FRR rpki/route-map via vtysh — keeping marker so a re-run retries"
  fi
fi

# Undo the no-rib override if we applied it. CRITICAL: re-assert 'no bgp no-rib'
# (rib ON) — never push 'bgp no-rib', which would DISABLE kernel route
# installation and leave bgpd worse than the pre-apply full-feed posture. With
# the daemons file restored (no -l), 'no bgp no-rib' equals the FRR default.
norib_marker=$(bgp_norib_marker_path)
if [ -e "$norib_marker" ]; then
  if {
       printf 'router bgp\n'
       printf ' no bgp no-rib\n'
       printf ' exit\n'
     } | bgp_vtysh_apply; then
    rm -f "$norib_marker" || true
    audit_log bgp.revert.norib "restored=rib-on"
    info "ensured 'no bgp no-rib' (kernel route installation stays on)"
    touched=1
  else
    warn "could not re-assert 'no bgp no-rib' via vtysh — keeping marker so a re-run retries"
  fi
fi

# Validator stays installed, just stopped + disabled (only if we enabled it).
routinator_marker=$(bgp_routinator_marker_path)
if [ -e "$routinator_marker" ]; then
  if "$ONIONARMOR_BGP_SYSTEMCTL" disable --now routinator >/dev/null 2>&1; then
    rm -f "$routinator_marker" || true
    info "disabled routinator (left installed)"
  else
    info "routinator disable failed (not present or error) — keeping marker so a re-run retries"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Remove GTSM / ttl-security configuration if we applied it.
# ---------------------------------------------------------------------------
gtsm_marker=$(bgp_gtsm_marker_path)
if [ -e "$gtsm_marker" ]; then
  gtsm_data=$(cat "$gtsm_marker" 2>/dev/null || true)
  if [ -n "$gtsm_data" ]; then
    # Only clear the marker if vtysh actually removed the live config — otherwise
    # FRR may still hold the GTSM settings while audit would report it unconfigured.
    # Keeping the marker lets a re-run retry the removal.
    if {
      printf 'router bgp\n'
      while read -r p hops; do
        [ -n "$p" ] || continue
        [ -n "$hops" ] || hops=1
        printf ' no neighbor %s ttl-security hops %s\n' "$p" "$hops"
      done <<EOF
$gtsm_data
EOF
      printf ' exit\n'
    } | bgp_vtysh_apply; then
      rm -f "$gtsm_marker" || true
      audit_log bgp.revert.gtsm "removed_peers=$(printf '%s' "$gtsm_data" | awk '{print $1}' | tr '\n' ' ')"
      info "removed GTSM ttl-security configuration"
      touched=1
    else
      warn "could not remove FRR GTSM config via vtysh — keeping marker so a re-run retries"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 5. Reload or restart FRR (restart if daemons restored, reload otherwise).
# ---------------------------------------------------------------------------
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping FRR reload"
elif [ "$touched" -eq 0 ]; then
  info "no changes made — skipping FRR reload"
else
  if [ "$daemons_restored" -eq 1 ]; then
    # Daemons file restored means bgpd_options changed, which requires restart.
    "$ONIONARMOR_BGP_SYSTEMCTL" restart frr >/dev/null 2>&1 \
      || warn "could not restart FRR via systemctl — restored config is on disk; restart manually"
  else
    "$ONIONARMOR_BGP_SYSTEMCTL" reload frr >/dev/null 2>&1 \
      || warn "could not reload FRR via systemctl — restored config is on disk; reload manually"
  fi
fi

audit_log bgp.revert.done "touched=$touched"
cat <<EOF

[bgp-hardening] reverted.
  daemons  : $([ -f "$backup" ] && echo "restored from $backup" || echo "no backup — left as-is")
  firewall : $BGP_FIREWALL tcp/179 rules removed
  RPKI     : FRR cache/route-map removed; routinator disabled (still installed)
EOF
