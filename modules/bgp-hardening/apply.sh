#!/usr/bin/env bash
# MODULE: BGP hardening — bind bgpd to a specific IP, firewall tcp/179 to known peers, RPKI-validate inbound, optional GTSM.
#
# apply.sh — apply the FRR bgpd safe-defaults. Idempotent; supports --dry-run.
# Auto-detects the bind IP (bgp router-id) and peers (neighbor remote-as lines)
# from /etc/frr; both are overridable via --bind-ip / --peer-ip.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

bgp_parse_flags "$@"

# ---------------------------------------------------------------------------
# Resolve the bind IP and peer set up front so dry-run and apply agree, and so
# a missing required input fails before we touch any state.
# ---------------------------------------------------------------------------
bind_ip=""
if [ "$BGP_BIND_FIX" -eq 1 ]; then
  bind_ip=$(bgp_resolve_bind_ip)
  [ -n "$bind_ip" ] \
    || die "bgp-hardening: could not determine the listener bind IP — no 'bgp router-id' in $ONIONARMOR_BGP_FRR_CONF; pass --bind-ip <ip> (or --no-bind-fix)"
fi

peers=""
if [ "$BGP_DO_FIREWALL" -eq 1 ] || [ "$BGP_GTSM" -eq 1 ]; then
  peers=$(bgp_resolve_peers)
  if [ -z "$peers" ]; then
    [ "$BGP_DO_FIREWALL" -eq 1 ] \
      && die "bgp-hardening: no peer IPs — no 'neighbor <ip> remote-as' in $ONIONARMOR_BGP_FRR_CONF; pass --peer-ip <ip> (or --no-firewall)"
    [ "$BGP_GTSM" -eq 1 ] \
      && die "bgp-hardening: --enable-gtsm needs peers — none detected; pass --peer-ip <ip>"
  fi
fi

dropin_daemons=$(bgp_daemons_path)
peer_list_oneline=$(printf '%s' "$peers" | tr '\n' ' ' | sed 's/[[:space:]]*$//')

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered artefacts; change nothing.
# ---------------------------------------------------------------------------
if [ "$BGP_DRY_RUN" -eq 1 ]; then
  info "dry-run: bgp-hardening (no host changes)"
  cat <<EOF

PLAN
  listener bind     -> $([ "$BGP_BIND_FIX" -eq 1 ] && echo "$bind_ip (in $dropin_daemons bgpd_options)" || echo "skipped (--no-bind-fix)")
  firewall          -> $([ "$BGP_DO_FIREWALL" -eq 1 ] && echo "$BGP_FIREWALL: tcp/179 from { ${peer_list_oneline:-none} } only" || echo "skipped (--no-firewall)")
  RPKI              -> $([ "$BGP_RPKI" -eq 1 ] && echo "Routinator + route-map $BGP_RPKI_ROUTEMAP (cache $BGP_RPKI_CACHE_HOST:$BGP_RPKI_CACHE_PORT)" || echo "skipped (--no-enable-rpki)")
  GTSM              -> $([ "$BGP_GTSM" -eq 1 ] && echo "ttl-security hops $BGP_GTSM_HOPS per neighbor" || echo "off (peer cooperation required)")
EOF
  if [ "$BGP_BIND_FIX" -eq 1 ]; then
    printf '\n--- %s (bgpd_options) ---\n' "$dropin_daemons"
    bgp_render_daemons "$bind_ip" | grep -E '^bgpd_options=' || true
  fi
  if [ "$BGP_DO_FIREWALL" -eq 1 ]; then
    printf '\n--- firewall (%s) ---\n' "$BGP_FIREWALL"
    if [ "$BGP_FIREWALL" = "nftables" ]; then printf '%s\n' "$peers" | bgp_render_nft
    else printf '%s\n' "$peers" | bgp_render_ufw; fi
  fi
  if [ "$BGP_RPKI" -eq 1 ]; then
    printf '\n--- FRR RPKI config (via vtysh) ---\n'; bgp_render_rpki_config
  fi
  if [ "$BGP_GTSM" -eq 1 ]; then
    printf '\n--- FRR GTSM config (via vtysh) ---\n'; printf '%s\n' "$peers" | bgp_render_gtsm_config
  fi
  exit 0
fi

audit_log bgp.apply.start "bind_fix=$BGP_BIND_FIX bind_ip=${bind_ip:-none} firewall=$([ "$BGP_DO_FIREWALL" -eq 1 ] && echo "$BGP_FIREWALL" || echo no) peers=${peer_list_oneline:-none} rpki=$BGP_RPKI gtsm=$BGP_GTSM"

mkdir -p "$ONIONARMOR_BGP_STATE_DIR" || die "cannot create $ONIONARMOR_BGP_STATE_DIR"
# frr_changed gates the graceful FRR reload (daemons/rpki/gtsm touch FRR);
# any_changed only drives the closing "no changes" message. Firewall edits are
# independent of FRR and never trigger a reload on their own.
frr_changed=0
any_changed=0

# ---------------------------------------------------------------------------
# 1. Listener bind: set -l <ip> in /etc/frr/daemons bgpd_options.
# ---------------------------------------------------------------------------
if [ "$BGP_BIND_FIX" -eq 1 ]; then
  [ -f "$dropin_daemons" ] || die "bgp-hardening: $dropin_daemons not found (is FRR installed?)"
  # Back up the original daemons file once, before our first edit.
  backup=$(bgp_daemons_backup_path)
  if [ ! -e "$backup" ]; then
    cp -p "$dropin_daemons" "$backup" || die "cannot back up $dropin_daemons -> $backup"
    audit_log bgp.apply.backup "from=$dropin_daemons to=$backup"
    info "backed up daemons -> $backup"
  fi
  rendered=$(bgp_render_daemons "$bind_ip")
  if [ "$(cat "$dropin_daemons")" = "$rendered" ]; then
    info "listener bind already current: bgpd_options has -l $bind_ip"
  else
    tmp="$dropin_daemons.oa.$$"
    printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
    mv "$tmp" "$dropin_daemons" || { rm -f "$tmp"; die "cannot move $tmp -> $dropin_daemons"; }
    audit_log bgp.apply.bind "daemons=$dropin_daemons bind=$bind_ip"
    info "set bgpd listener bind -> $bind_ip"
    frr_changed=1; any_changed=1
  fi
fi

# ---------------------------------------------------------------------------
# 2. Firewall: restrict tcp/179 to the known peer IP(s).
# ---------------------------------------------------------------------------
if [ "$BGP_DO_FIREWALL" -eq 1 ]; then
  if [ "$BGP_FIREWALL" = "nftables" ]; then
    rendered_nft=$(printf '%s\n' "$peers" | bgp_render_nft)
    if [ "$(bgp_nft_current)" = "$rendered_nft" ]; then
      info "firewall already current: nft table inet $BGP_NFT_TABLE"
    else
      # Snapshot the existing managed table (if any) for revert/debugging.
      bgp_nft_current > "$(bgp_nft_backup_path)" 2>/dev/null || true
      printf '%s\n' "$rendered_nft" | "$ONIONARMOR_BGP_NFT" -f - \
        || die "bgp-hardening: nft failed to load the tcp/179 ruleset"
      audit_log bgp.apply.firewall "nft_table=$BGP_NFT_TABLE peers=$peer_list_oneline"
      info "firewall: nft table inet $BGP_NFT_TABLE restricts tcp/179 to { $peer_list_oneline }"
      any_changed=1
    fi
  else
    # ufw path: best-effort, additive.
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # shellcheck disable=SC2086  # ufw args are a controlled, space-split command
      "$ONIONARMOR_BGP_UFW" $line >/dev/null 2>&1 || warn "ufw command failed: $line"
    done < <(printf '%s\n' "$peers" | bgp_render_ufw)
    audit_log bgp.apply.firewall "ufw peers=$peer_list_oneline"
    info "firewall: ufw restricts tcp/179 to { $peer_list_oneline }"
    any_changed=1
  fi
fi

# ---------------------------------------------------------------------------
# 3. RPKI: install + run Routinator, configure FRR's rpki cache + route-map.
# ---------------------------------------------------------------------------
if [ "$BGP_RPKI" -eq 1 ]; then
  # Ensure the validator is running (install + enable only when needed).
  if bgp_service_active routinator; then
    info "RPKI: routinator already running"
  else
    if ! command -v "$ONIONARMOR_BGP_ROUTINATOR" >/dev/null 2>&1; then
      info "RPKI: installing routinator via apt"
      DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_BGP_APT" update >/dev/null 2>&1 \
        || warn "apt-get update failed; continuing"
      DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_BGP_APT" install -y --no-install-recommends routinator \
        || die "bgp-hardening: apt-get install routinator failed"
    fi
    "$ONIONARMOR_BGP_SYSTEMCTL" enable --now routinator >/dev/null 2>&1 \
      || warn "could not enable+start routinator via systemctl"
    any_changed=1
  fi
  # Configure FRR's rpki cache + route-map once (idempotent: the marker means
  # we already installed the live config; re-running vtysh would be a needless
  # FRR reload). Re-apply explicitly by reverting first if the cache changes.
  if [ -e "$(bgp_rpki_marker_path)" ]; then
    info "RPKI: FRR already configured (route-map $BGP_RPKI_ROUTEMAP)"
  elif bgp_render_rpki_config | bgp_vtysh_apply; then
    : > "$(bgp_rpki_marker_path)"
    audit_log bgp.apply.rpki "routemap=$BGP_RPKI_ROUTEMAP cache=$BGP_RPKI_CACHE_HOST:$BGP_RPKI_CACHE_PORT"
    info "RPKI: configured FRR cache + route-map $BGP_RPKI_ROUTEMAP (drop INVALID, keep VALID+UNKNOWN)"
    frr_changed=1; any_changed=1
  else
    warn "RPKI: FRR config not applied (vtysh unavailable?) — routinator may still be running"
  fi
fi

# ---------------------------------------------------------------------------
# 4. GTSM / ttl-security (opt-in; requires peer cooperation).
# ---------------------------------------------------------------------------
if [ "$BGP_GTSM" -eq 1 ]; then
  if printf '%s\n' "$peers" | bgp_render_gtsm_config | bgp_vtysh_apply; then
    audit_log bgp.apply.gtsm "hops=$BGP_GTSM_HOPS peers=$peer_list_oneline"
    info "GTSM: set ttl-security hops $BGP_GTSM_HOPS per neighbor (requires peer cooperation to take effect)"
    frr_changed=1; any_changed=1
  else
    warn "GTSM: vtysh did not apply ttl-security"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Reload FRR gracefully (preserves the forwarding plane).
# ---------------------------------------------------------------------------
if [ "${ONIONARMOR_SKIP_RELOAD:-}" = "yes" ]; then
  info "ONIONARMOR_SKIP_RELOAD=yes — skipping FRR reload"
elif [ "$frr_changed" -eq 1 ]; then
  # Graceful reload preserves the forwarding plane. NB: a bgpd_options (-l)
  # change is only picked up when bgpd restarts — FRR's graceful restart keeps
  # the FIB across that; see the module README.
  "$ONIONARMOR_BGP_SYSTEMCTL" reload frr >/dev/null 2>&1 \
    && info "reloaded FRR (graceful; forwarding plane preserved)" \
    || warn "could not reload FRR via systemctl — apply changes are on disk; reload manually"
else
  info "no FRR-affecting changes — reload not needed"
fi

[ "$any_changed" -eq 0 ] && info "bgp-hardening: nothing to do — posture already current"
audit_log bgp.apply.done "frr_changed=$frr_changed any_changed=$any_changed"

cat <<EOF

[bgp-hardening] applied.
  listener bind : $([ "$BGP_BIND_FIX" -eq 1 ] && echo "$bind_ip" || echo "(unchanged)")
  firewall      : $([ "$BGP_DO_FIREWALL" -eq 1 ] && echo "$BGP_FIREWALL tcp/179 -> { $peer_list_oneline }" || echo "(unchanged)")
  RPKI          : $([ "$BGP_RPKI" -eq 1 ] && echo "on (route-map $BGP_RPKI_ROUTEMAP)" || echo "(unchanged)")
  GTSM          : $([ "$BGP_GTSM" -eq 1 ] && echo "ttl-security hops $BGP_GTSM_HOPS" || echo "off")

Kept by operator constraint: full feed (ALLOW_ALL_IN), no TCP-MD5, no maximum-prefix.
Check status:  onionarmor audit  --module bgp-hardening
Undo:          onionarmor revert --module bgp-hardening
EOF
