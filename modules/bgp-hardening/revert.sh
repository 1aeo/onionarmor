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

daemons=$(bgp_daemons_path)
backup=$(bgp_daemons_backup_path)
marker=$(bgp_rpki_marker_path)
touched=0

audit_log bgp.revert.start "daemons=$daemons firewall=$BGP_FIREWALL"

# ---------------------------------------------------------------------------
# 1. Restore the original /etc/frr/daemons from the apply-time backup.
# ---------------------------------------------------------------------------
if [ -f "$backup" ]; then
  cp -p "$backup" "$daemons" \
    || audit_fail_die bgp.revert.fail "stage=daemons" "failed to restore $daemons from $backup"
  audit_log bgp.revert.daemons "restored=$daemons from=$backup"
  info "restored daemons from $backup"
  touched=1
else
  warn "no daemons backup at $backup — leaving $daemons as-is"
fi

# ---------------------------------------------------------------------------
# 2. Remove the managed firewall rules.
# ---------------------------------------------------------------------------
if [ "$BGP_FIREWALL" = "nftables" ]; then
  if [ -n "$(bgp_nft_current)" ]; then
    "$ONIONARMOR_BGP_NFT" delete table inet "$BGP_NFT_TABLE" >/dev/null 2>&1 \
      && { audit_log bgp.revert.firewall "removed=nft:$BGP_NFT_TABLE"; info "removed nft table inet $BGP_NFT_TABLE"; touched=1; } \
      || warn "could not delete nft table inet $BGP_NFT_TABLE"
  else
    info "no managed nft table inet $BGP_NFT_TABLE to remove"
  fi
else
  # ufw: best-effort delete of the rules apply would have added.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    # shellcheck disable=SC2086  # controlled, space-split ufw delete command
    "$ONIONARMOR_BGP_UFW" delete $line >/dev/null 2>&1 || true
  done < <(printf '' | bgp_render_ufw)
  info "removed ufw tcp/179 rules (best-effort)"
fi

# ---------------------------------------------------------------------------
# 3. Remove the FRR rpki cache + route-map; disable (but keep) the validator.
# ---------------------------------------------------------------------------
if [ -e "$marker" ]; then
  {
    printf 'rpki\n'
    printf ' no rpki cache %s %s\n' "$BGP_RPKI_CACHE_HOST" "$BGP_RPKI_CACHE_PORT"
    printf ' exit\n'
    printf 'no route-map %s\n' "$BGP_RPKI_ROUTEMAP"
  } | bgp_vtysh_apply || warn "could not remove FRR rpki/route-map config via vtysh"
  rm -f "$marker" || true
  audit_log bgp.revert.rpki "removed=$BGP_RPKI_ROUTEMAP"
  info "removed FRR rpki cache + route-map $BGP_RPKI_ROUTEMAP"
  touched=1
fi
# Validator stays installed, just stopped + disabled.
"$ONIONARMOR_BGP_SYSTEMCTL" disable --now routinator >/dev/null 2>&1 \
  && info "disabled routinator (left installed)" \
  || info "routinator not disabled (not present or already inactive)"

# ---------------------------------------------------------------------------
# 4. Reload FRR gracefully so the restored config takes effect.
# ---------------------------------------------------------------------------
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping FRR reload"
else
  "$ONIONARMOR_BGP_SYSTEMCTL" reload frr >/dev/null 2>&1 \
    || warn "could not reload FRR via systemctl — restored config is on disk; reload manually"
fi

audit_log bgp.revert.done "touched=$touched"
cat <<EOF

[bgp-hardening] reverted.
  daemons  : $([ -f "$backup" ] && echo "restored from $backup" || echo "no backup — left as-is")
  firewall : $BGP_FIREWALL tcp/179 rules removed
  RPKI     : FRR cache/route-map removed; routinator disabled (still installed)
EOF
