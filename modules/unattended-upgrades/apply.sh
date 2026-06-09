#!/usr/bin/env bash
# MODULE: Unattended upgrades — auto-install Debian/Ubuntu SECURITY updates daily, reboot at 03:00 only when required.
#
# apply.sh — turn on unattended security upgrades under the 1aeo fleet posture.
# Idempotent; supports --dry-run. Security-only origins (never -updates), daily
# update + upgrade, automatic reboot at 03:00 ONLY when an upgrade flags one.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

uu_parse_flags "$@"

f50=$(uu_50_path)
f20=$(uu_20_path)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered config, change nothing.
# ---------------------------------------------------------------------------
if [ "$UU_DRY_RUN" -eq 1 ]; then
  info "dry-run: unattended-upgrades (no host changes)"
  cat <<EOF

PLAN
  distro / codename -> $UU_DISTRO / $UU_CODENAME
  50 config         -> $f50
  20 config         -> $f20
  auto-reboot       -> $([ "$UU_REBOOT" -eq 1 ] && echo "yes at $UU_REBOOT_TIME (with-users=$([ "$UU_REBOOT_WITH_USERS" -eq 1 ] && echo yes || echo no))" || echo no)
  service           -> enable + start $ONIONARMOR_UU_SERVICE
  packages          -> ensure unattended-upgrades + apt-listchanges

--- $f50 ---
$(uu_render_50)

--- $f20 ---
$(uu_render_20)
EOF
  exit 0
fi

audit_log uu.apply.start "distro=$UU_DISTRO codename=$UU_CODENAME reboot=$UU_REBOOT time=$UU_REBOOT_TIME"

# ---------------------------------------------------------------------------
# 1. Ensure the tooling is installed (skip if already present).
# ---------------------------------------------------------------------------
need_pkgs=""
uu_pkg_installed unattended-upgrades || need_pkgs="$need_pkgs unattended-upgrades"
uu_pkg_installed apt-listchanges    || need_pkgs="$need_pkgs apt-listchanges"
if [ -n "$need_pkgs" ]; then
  info "installing:$need_pkgs"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_UU_APT" update \
    || audit_fail_die uu.apply.fail "stage=apt-update" "apt-get update failed"
  # shellcheck disable=SC2086  # intentional word-split of the package list
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_UU_APT" install -y --no-install-recommends $need_pkgs \
    || audit_fail_die uu.apply.fail "stage=apt-install" "apt-get install$need_pkgs failed"
fi

mkdir -p "$ONIONARMOR_UU_APT_CONFD" "$ONIONARMOR_UU_STATE_DIR" \
  || die "cannot create config/state dirs"

# ---------------------------------------------------------------------------
# 2. Write the two managed apt.conf.d files. Back up any pre-existing
#    (package-shipped) version ONCE so revert can restore the distro default.
#    Idempotent: skip the write when byte-identical.
# ---------------------------------------------------------------------------
uu_install_file() {
  # uu_install_file <path> <rendered> <audit-tag>
  local path=$1 rendered=$2 tag=$3 base backup tmp
  base=$(basename "$path")
  backup=$(uu_backup_path "$base")
  if [ ! -e "$backup" ] && [ -f "$path" ] && ! grep -q 'Managed by onionarmor' "$path" 2>/dev/null; then
    cp -p "$path" "$backup" || die "cannot back up $path -> $backup"
    audit_log uu.apply.backup "from=$path to=$backup"
    info "backed up distro default -> $backup"
  fi
  if [ -f "$path" ] && [ "$(cat "$path")" = "$rendered" ]; then
    info "config already current: $path"
    return 0
  fi
  tmp="$path.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$path" || { rm -f "$tmp"; die "cannot move $tmp -> $path"; }
  audit_log "$tag" "wrote=$path"
  info "wrote config: $path"
}

uu_install_file "$f50" "$(uu_render_50)" uu.apply.conf50
uu_install_file "$f20" "$(uu_render_20)" uu.apply.conf20

# Persist the apply-time flags now that the primary operation succeeded.
# Best-effort: a state-dir permission issue cannot abort the live posture.
uu_save_flags || warn "could not persist apply-time flags; audit will use defaults"

# ---------------------------------------------------------------------------
# 3. Enable + start the service so the posture is live.
# ---------------------------------------------------------------------------
enable_failed=0
"$ONIONARMOR_UU_SYSTEMCTL" unmask "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1 || true
if "$ONIONARMOR_UU_SYSTEMCTL" enable --now "$ONIONARMOR_UU_SERVICE" >/dev/null 2>&1; then
  info "enabled + started $ONIONARMOR_UU_SERVICE"
else
  warn "could not enable $ONIONARMOR_UU_SERVICE via systemctl"
  enable_failed=1
fi

# ---------------------------------------------------------------------------
# 4. Validate the rendered config with unattended-upgrades' own dry-run when
#    available (best-effort: a non-zero here is surfaced, not fatal).
# ---------------------------------------------------------------------------
audit_log uu.apply.done "enable_failed=$enable_failed"

cat <<EOF

[unattended-upgrades] applied.
  distro      : $UU_DISTRO ($UU_CODENAME)
  50 config   : $f50
  20 config   : $f20
  auto-reboot : $([ "$UU_REBOOT" -eq 1 ] && echo "at $UU_REBOOT_TIME (only when required)" || echo off)
  service     : $ONIONARMOR_UU_SERVICE

Check status any time:  onionarmor audit  --module unattended-upgrades
Undo the posture:       onionarmor revert --module unattended-upgrades
EOF

[ "$enable_failed" -eq 0 ] || { warn "apply finished but the service could not be enabled (see above)"; exit 2; }
