# shellcheck shell=bash
# SC2034: the colour vars + SH_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/systemd-hardening/lib.sh — shared helpers for the systemd-hardening
# module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite can drive the whole module against a
# sandbox of fixture unit files and a fake systemctl, never touching real
# systemd.

# --- locate + source the shared common.sh ---------------------------------
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_SH_SYSTEMCTL:=systemctl}"
: "${ONIONARMOR_SH_SLEEP:=sleep}"
: "${ONIONARMOR_SH_SHA256:=sha256sum}"

# --- overridable filesystem paths -----------------------------------------
# Where we write drop-ins (always /etc/systemd/system for admin overrides).
: "${ONIONARMOR_SH_DROPIN_ROOT:=/etc/systemd/system}"
# Where we look for unit FILES to decide a unit is installed.
: "${ONIONARMOR_SH_UNIT_DIRS:=/etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system}"
# Where enabled tor@ instances appear as wants-symlinks.
: "${ONIONARMOR_SH_WANTS_DIRS:=/etc/systemd/system/multi-user.target.wants /etc/systemd/system/tor.target.wants}"
: "${ONIONARMOR_SH_STATE_DIR:=/var/lib/onionarmor/systemd-hardening}"

# The managed drop-in filename (high number so it wins last-wins merges).
: "${ONIONARMOR_SH_DROPIN_NAME:=99-onionarmor-hardening.conf}"

# Restart settle: after restarting a unit we poll is-active for up to N seconds
# (interval S) before deciding it failed and auto-reverting that unit.
: "${ONIONARMOR_SH_RESTART_TIMEOUT:=30}"
: "${ONIONARMOR_SH_RESTART_INTERVAL:=1}"

# --- per-unit-class CapabilityBoundingSet (minimal) -----------------------
# Overridable so an operator can tune without editing the module. Empty string
# means CapabilityBoundingSet= (drop ALL capabilities).
: "${ONIONARMOR_SH_TOR_CAPS:=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE}"
: "${ONIONARMOR_SH_ONIONWARDEN_CAPS:=}"
: "${ONIONARMOR_SH_ONIONLEAK_COLLECTOR_CAPS:=CAP_NET_RAW CAP_NET_ADMIN}"
: "${ONIONARMOR_SH_ONIONLEAK_ANALYZER_CAPS:=}"

# --- per-unit-class ReadWritePaths (scoped) -------------------------------
# Conservative FHS defaults — confirm against the real units before fleet-wide
# rollout (see module README "Open questions"). Overridable per class.
: "${ONIONARMOR_SH_TOR_RWPATHS:=/var/lib/tor /var/lib/tor-instances /run/tor /run/tor-instances /var/log/tor}"
: "${ONIONARMOR_SH_ONIONWARDEN_RWPATHS:=/var/lib/onionwarden /run/onionwarden /var/log/onionwarden}"
: "${ONIONARMOR_SH_ONIONLEAK_COLLECTOR_RWPATHS:=/var/lib/onionleak /run/onionleak /var/log/onionleak}"
: "${ONIONARMOR_SH_ONIONLEAK_ANALYZER_RWPATHS:=/var/lib/onionleak /var/log/onionleak}"

# The candidate non-template units we manage when present.
OA_SH_STATIC_UNITS="onionwarden.service onionleak-collector.service onionleak-analyzer.service"

# The hardening directives applied to EVERY managed unit (order is stable so the
# rendered drop-in is byte-deterministic for idempotency).
OA_SH_COMMON_DIRECTIVES="NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native"

# --- status colours (green/yellow/red) ------------------------------------
if [ -t 2 ]; then
  OA_SH_GREEN=$'\033[32m'; OA_SH_YEL=$'\033[33m'; OA_SH_RED=$'\033[31m'; OA_SH_OFF=$'\033[0m'
else
  OA_SH_GREEN=""; OA_SH_YEL=""; OA_SH_RED=""; OA_SH_OFF=""
fi

# --- flag defaults --------------------------------------------------------
sh_set_defaults() {
  SH_UNITS_OVERRIDE=""   # explicit unit set (CSV); empty => autodetect
  SH_DRY_RUN=0
  SH_NO_RESTART=0        # write drop-ins but do not daemon-reload/restart
}

# sh_need_val <flag> <count>: die unless a value-taking flag was given an
# argument, guarding `shift 2` from a silent "shift count out of range" abort on
# a trailing valueless flag. Mirrors krp_need_val / bgp_need_val / dns_need_val.
sh_need_val() {
  [ "$2" -ge 2 ] || die "systemd-hardening: $1 requires a value (try --help)"
}

sh_parse_flags() {
  sh_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --units)      sh_need_val "$1" "$#"; SH_UNITS_OVERRIDE=$2; shift 2 ;;
      --units=*)    SH_UNITS_OVERRIDE=${1#--units=}; shift ;;
      --dry-run)    SH_DRY_RUN=1; shift ;;
      --no-restart) SH_NO_RESTART=1; shift ;;
      -h|--help)    sh_usage; exit 0 ;;
      *)            die "systemd-hardening: unknown option: $1 (try --help)" ;;
    esac
  done
}

sh_usage() {
  cat <<'EOF'
onionarmor apply --module systemd-hardening [options]   (also: audit, revert)

Apply a systemd sandbox drop-in (99-onionarmor-hardening.conf) to the relay's
service units — tor@*, onionwarden, onionleak-collector, onionleak-analyzer —
with NoNewPrivileges, ProtectSystem=strict, kernel/cgroup/namespace protections,
a minimal per-unit CapabilityBoundingSet and a scoped ReadWritePaths.

SAFETY: after restarting each unit, apply polls is-active for up to 30s; if the
unit does not come up, apply AUTO-REVERTS that unit's drop-in and restarts it,
so a too-tight ReadWritePaths can never leave a unit down.

OPTIONS
  --units <csv>   Harden exactly these units (comma-separated), skipping
                  autodetection. e.g. --units tor@0.service,onionwarden.service
  --no-restart    Write the drop-ins but do not daemon-reload / restart (you
                  restart later). Disables the auto-revert safety net.
  --dry-run       Print the plan + every rendered drop-in. Changes nothing.
  -h, --help      This help.
EOF
}

# sh_unit_file_exists <unit>: true if a unit file for <unit> is found in any of
# the search dirs. For an instance tor@N.service the template tor@.service
# counts as the backing file.
sh_unit_file_exists() {
  local unit=$1 d template
  # shellcheck disable=SC2086  # intentional word-split of the space-listed dirs
  for d in $ONIONARMOR_SH_UNIT_DIRS; do
    [ -e "$d/$unit" ] && return 0
  done
  case "$unit" in
    *@*.service)
      template="${unit%%@*}@.service"
      # shellcheck disable=SC2086  # intentional word-split of the dir list
      for d in $ONIONARMOR_SH_UNIT_DIRS; do
        [ -e "$d/$template" ] && return 0
      done
      ;;
  esac
  return 1
}

# sh_detect_tor_instances: print every enabled tor@<inst>.service found as a
# wants-symlink. Falls back to nothing (no template, or template but no enabled
# instance) — we only harden instances that actually exist.
sh_detect_tor_instances() {
  local d f base
  # shellcheck disable=SC2086  # intentional word-split of the space-listed dirs
  for d in $ONIONARMOR_SH_WANTS_DIRS; do
    [ -d "$d" ] || continue
    for f in "$d"/tor@*.service; do
      [ -e "$f" ] || continue
      base=$(basename "$f")
      printf '%s\n' "$base"
    done
  done | sort -u
}

# sh_detect_units: print the concrete unit set to harden, one per line. Honours
# --units when given; otherwise autodetects tor@ instances + the static units.
sh_detect_units() {
  if [ -n "$SH_UNITS_OVERRIDE" ]; then
    printf '%s\n' "$SH_UNITS_OVERRIDE" | tr ',' '\n' | sed '/^$/d'
    return 0
  fi
  sh_detect_tor_instances
  local u
  # shellcheck disable=SC2086  # intentional word-split of the static unit list
  for u in $OA_SH_STATIC_UNITS; do
    sh_unit_file_exists "$u" && printf '%s\n' "$u"
  done
  return 0
}

# sh_unit_class <unit>: map a concrete unit to its policy class.
sh_unit_class() {
  case "$1" in
    tor@*.service|tor.service)   printf 'tor\n' ;;
    onionwarden.service)         printf 'onionwarden\n' ;;
    onionleak-collector.service) printf 'onionleak-collector\n' ;;
    onionleak-analyzer.service)  printf 'onionleak-analyzer\n' ;;
    *)                           printf 'generic\n' ;;
  esac
}

# sh_caps_for_unit <unit>: echo the CapabilityBoundingSet value (may be empty).
sh_caps_for_unit() {
  case "$(sh_unit_class "$1")" in
    tor)                 printf '%s' "$ONIONARMOR_SH_TOR_CAPS" ;;
    onionwarden)         printf '%s' "$ONIONARMOR_SH_ONIONWARDEN_CAPS" ;;
    onionleak-collector) printf '%s' "$ONIONARMOR_SH_ONIONLEAK_COLLECTOR_CAPS" ;;
    onionleak-analyzer)  printf '%s' "$ONIONARMOR_SH_ONIONLEAK_ANALYZER_CAPS" ;;
    *)                   printf '' ;;
  esac
}

# sh_rwpaths_for_unit <unit>: echo the ReadWritePaths value (may be empty).
sh_rwpaths_for_unit() {
  case "$(sh_unit_class "$1")" in
    tor)                 printf '%s' "$ONIONARMOR_SH_TOR_RWPATHS" ;;
    onionwarden)         printf '%s' "$ONIONARMOR_SH_ONIONWARDEN_RWPATHS" ;;
    onionleak-collector) printf '%s' "$ONIONARMOR_SH_ONIONLEAK_COLLECTOR_RWPATHS" ;;
    onionleak-analyzer)  printf '%s' "$ONIONARMOR_SH_ONIONLEAK_ANALYZER_RWPATHS" ;;
    *)                   printf '' ;;
  esac
}

# sh_dropin_dir <unit> / sh_dropin_path <unit>
sh_dropin_dir()  { printf '%s/%s.d\n' "$ONIONARMOR_SH_DROPIN_ROOT" "$1"; }
sh_dropin_path() { printf '%s/%s.d/%s\n' "$ONIONARMOR_SH_DROPIN_ROOT" "$1" "$ONIONARMOR_SH_DROPIN_NAME"; }

# sh_render_dropin <unit>: emit the managed [Service] drop-in for <unit>.
sh_render_dropin() {
  local unit=$1 caps rwpaths
  caps=$(sh_caps_for_unit "$unit")
  rwpaths=$(sh_rwpaths_for_unit "$unit")
  printf '# Managed by onionarmor (module: systemd-hardening) — do not edit by hand.\n'
  printf '# Revert with: onionarmor revert --module systemd-hardening\n'
  printf '# Unit: %s (class: %s)\n' "$unit" "$(sh_unit_class "$unit")"
  printf '[Service]\n'
  printf '%s\n' "$OA_SH_COMMON_DIRECTIVES"
  # CapabilityBoundingSet is ALWAYS emitted: empty value = drop all caps.
  printf 'CapabilityBoundingSet=%s\n' "$caps"
  if [ -n "$rwpaths" ]; then
    printf 'ReadWritePaths=%s\n' "$rwpaths"
  fi
}

# sh_checksum <path> -> short digest for reporting, or "n/a".
sh_checksum() {
  local p=$1
  [ -f "$p" ] || { printf 'n/a\n'; return 0; }
  "$ONIONARMOR_SH_SHA256" "$p" 2>/dev/null | awk '{print substr($1,1,16)}' \
    || printf 'n/a\n'
}

# sh_is_managed_dropin <path>: true if the file is our managed drop-in.
sh_is_managed_dropin() {
  [ -f "$1" ] && grep -q 'Managed by onionarmor (module: systemd-hardening)' "$1" 2>/dev/null
}

# sh_unit_active <unit>: true if systemctl reports the unit active.
sh_unit_active() {
  [ "$("$ONIONARMOR_SH_SYSTEMCTL" is-active "$1" 2>/dev/null || true)" = "active" ]
}

# sh_wait_active <unit>: poll is-active up to RESTART_TIMEOUT seconds. Returns 0
# as soon as the unit is active, non-zero if it never becomes active in time.
sh_wait_active() {
  local unit=$1 waited=0
  if sh_unit_active "$unit"; then return 0; fi
  while [ "$waited" -lt "$ONIONARMOR_SH_RESTART_TIMEOUT" ]; do
    "$ONIONARMOR_SH_SLEEP" "$ONIONARMOR_SH_RESTART_INTERVAL" || true
    waited=$((waited + ONIONARMOR_SH_RESTART_INTERVAL))
    sh_unit_active "$unit" && return 0
  done
  return 1
}
