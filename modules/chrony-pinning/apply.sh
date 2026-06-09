#!/usr/bin/env bash
# MODULE: chrony multi-stratum-1 pinning — diverse NTP time sources (NIST/USNO/PTB/NICT) via chrony; mask systemd-timesyncd.
#
# apply.sh — pin the clock to a geographically + operationally diverse stratum-1
# source set via chrony, with stratum-2 + pool fallbacks, and mask
# systemd-timesyncd. Idempotent; supports --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

chr_parse_flags "$@"

sources=$(chr_sources_path)
conf=$(chr_conf_path)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered config, change nothing.
# ---------------------------------------------------------------------------
if [ "$CHR_DRY_RUN" -eq 1 ]; then
  info "dry-run: chrony-pinning (no host changes)"
  cat <<EOF

PLAN
  sources file      -> $sources
  conf file         -> $conf
  makestep          -> $CHR_MAKESTEP
  leapsectz         -> $CHR_LEAPSECTZ
  mask timesyncd    -> $([ "$CHR_MASK_TIMESYNCD" -eq 1 ] && echo yes || echo no)
  service           -> enable + restart $ONIONARMOR_CHR_SERVICE

--- $sources ---
$(chr_render_sources)

--- $conf ---
$(chr_render_conf)
EOF
  exit 0
fi

audit_log chr.apply.start "mask_timesyncd=$CHR_MASK_TIMESYNCD makestep=$CHR_MAKESTEP"

# ---------------------------------------------------------------------------
# 1. Ensure chrony is installed.
# ---------------------------------------------------------------------------
if ! chr_chrony_installed; then
  info "chrony not found — installing via apt"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_CHR_APT" update \
    || audit_fail_die chr.apply.fail "stage=apt-update" "apt-get update failed"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_CHR_APT" install -y --no-install-recommends chrony \
    || audit_fail_die chr.apply.fail "stage=apt-install" "apt-get install chrony failed"
fi

mkdir -p "$ONIONARMOR_CHR_SOURCES_DIR" "$ONIONARMOR_CHR_CONF_DIR" "$ONIONARMOR_CHR_STATE_DIR" \
  || die "cannot create chrony config/state dirs"

# ---------------------------------------------------------------------------
# 2. Make sure the main chrony.conf actually pulls in sources.d / conf.d. Most
#    modern packages already do; if not, append a managed include block (backing
#    up chrony.conf once first).
# ---------------------------------------------------------------------------
if [ -f "$ONIONARMOR_CHR_MAIN_CONF" ]; then
  need_block=0
  chr_main_reads sourcedir "$ONIONARMOR_CHR_SOURCES_DIR" || need_block=1
  chr_main_reads confdir "$ONIONARMOR_CHR_CONF_DIR" || need_block=1
  if [ "$need_block" -eq 1 ]; then
    backup=$(chr_mainconf_backup)
    [ -e "$backup" ] || cp -p "$ONIONARMOR_CHR_MAIN_CONF" "$backup" \
      || die "cannot back up $ONIONARMOR_CHR_MAIN_CONF -> $backup"
    if ! grep -Fxq '# --- onionarmor chrony-pinning include block (managed) ---' "$ONIONARMOR_CHR_MAIN_CONF" 2>/dev/null; then
      {
        printf '\n# --- onionarmor chrony-pinning include block (managed) ---\n'
        chr_main_reads sourcedir "$ONIONARMOR_CHR_SOURCES_DIR" || printf 'sourcedir %s\n' "$ONIONARMOR_CHR_SOURCES_DIR"
        chr_main_reads confdir "$ONIONARMOR_CHR_CONF_DIR" || printf 'confdir %s\n' "$ONIONARMOR_CHR_CONF_DIR"
      } >> "$ONIONARMOR_CHR_MAIN_CONF" || die "cannot append include block to $ONIONARMOR_CHR_MAIN_CONF"
      audit_log chr.apply.include "appended sourcedir/confdir to=$ONIONARMOR_CHR_MAIN_CONF backup=$backup"
      info "added sourcedir/confdir include block to $ONIONARMOR_CHR_MAIN_CONF (backup: $backup)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 3. Write the managed sources + conf files (idempotent: skip if identical).
# ---------------------------------------------------------------------------
chr_write_if_changed() {
  # chr_write_if_changed <path> <rendered> <audit-tag>
  local path=$1 rendered=$2 tag=$3 tmp
  if [ -f "$path" ] && [ "$(cat "$path")" = "$rendered" ]; then
    info "already current: $path"
    return 0
  fi
  tmp="$path.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$path" || { rm -f "$tmp"; die "cannot move $tmp -> $path"; }
  audit_log "$tag" "wrote=$path"
  info "wrote: $path"
}

chr_write_if_changed "$sources" "$(chr_render_sources)" chr.apply.sources
chr_write_if_changed "$conf" "$(chr_render_conf)" chr.apply.conf

# ---------------------------------------------------------------------------
# 3a. Write state file so audit can read back the mask_timesyncd choice.
# ---------------------------------------------------------------------------
chr_write_state || warn "could not write state file"

# ---------------------------------------------------------------------------
# 4. Mask + stop systemd-timesyncd so only chrony disciplines the clock.
# ---------------------------------------------------------------------------
if [ "$CHR_MASK_TIMESYNCD" -eq 1 ]; then
  "$ONIONARMOR_CHR_SYSTEMCTL" disable --now "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 || true
  "$ONIONARMOR_CHR_SYSTEMCTL" mask "$ONIONARMOR_CHR_TIMESYNCD" >/dev/null 2>&1 \
    || warn "could not mask $ONIONARMOR_CHR_TIMESYNCD"
  audit_log chr.apply.mask "masked=$ONIONARMOR_CHR_TIMESYNCD"
  info "masked + stopped $ONIONARMOR_CHR_TIMESYNCD"
fi

# ---------------------------------------------------------------------------
# 5. Enable + (re)start chrony so the pinned sources are live.
# ---------------------------------------------------------------------------
restart_failed=0
"$ONIONARMOR_CHR_SYSTEMCTL" enable "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 \
  || warn "could not enable $ONIONARMOR_CHR_SERVICE — chrony may not start on reboot"
"$ONIONARMOR_CHR_SYSTEMCTL" restart "$ONIONARMOR_CHR_SERVICE" >/dev/null 2>&1 \
  || { warn "could not restart $ONIONARMOR_CHR_SERVICE via systemctl"; restart_failed=1; }

# ---------------------------------------------------------------------------
# 6. Verify (default on): chrony is active and reports reachable stratum-1s.
#    Failures are surfaced but do not unwind the apply.
# ---------------------------------------------------------------------------
verify_failed=$restart_failed
if [ "$CHR_VERIFY" -eq 1 ]; then
  state=$("$ONIONARMOR_CHR_SYSTEMCTL" is-active "$ONIONARMOR_CHR_SERVICE" 2>/dev/null || true)
  if [ "$state" = "active" ]; then
    info "verify: $ONIONARMOR_CHR_SERVICE active"
  else
    warn "verify: $ONIONARMOR_CHR_SERVICE is '$state' (expected active)"; verify_failed=1
  fi
  srcs=$("$ONIONARMOR_CHR_CHRONYC" -n sources 2>/dev/null || true)
  n=$(chr_count_reachable_stratum1 "$srcs")
  if [ "$n" -ge 2 ]; then
    info "verify: $n reachable stratum-1 sources"
  else
    warn "verify: only $n reachable stratum-1 source(s) (want >=2; sources may still be syncing)"
    verify_failed=1
  fi
fi

audit_log chr.apply.done "verify_failed=$verify_failed"

cat <<EOF

[chrony-pinning] applied.
  sources file : $sources
  conf file    : $conf
  timesyncd    : $([ "$CHR_MASK_TIMESYNCD" -eq 1 ] && echo masked || echo untouched)
  service      : $ONIONARMOR_CHR_SERVICE

Check status any time:  onionarmor audit  --module chrony-pinning
Undo the posture:       onionarmor revert --module chrony-pinning
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
