# shellcheck shell=bash
# SC2034: the colour vars + TCB_* flag defaults set here are consumed by the
# apply/audit/revert scripts that source this file, not within it.
# shellcheck disable=SC2034
#
# modules/tor-config-baseline/lib.sh — shared helpers for the
# tor-config-baseline module's apply / audit / revert actions.
#
# Sourced by apply.sh, audit.sh, revert.sh. Reuses the top-level lib/common.sh
# for info/warn/die/audit_log. EVERY external command and filesystem path is
# overridable via env so the bats suite drives the whole module against a
# sandbox with stub binaries (systemctl), never touching the real host or tor.
#
# WHAT THIS MODULE DOES
#   Applies a baseline set of safe torrc directives across every tor instance,
#   inside a clearly-delimited managed block appended to each torrc, WITHOUT
#   ever touching operator-domain directives (ContactInfo, MyFamily, ORPort, …).
#   The managed block pins SigningKeyLifetime, turns off the directory-request /
#   connection-direction / extra-info statistics, and adds loopback-only
#   MetricsPort/ControlPort defaults (only when the operator has not already
#   bound one to loopback). It is fully reversible: revert strips the block and
#   restores the pre-apply backup.

# --- locate + source the shared common.sh ---------------------------------
# apply/audit/revert are exec'd by bin/onionarmor with ONIONARMOR_PREFIX set,
# but they can also be run directly (e.g. from tests) — fall back to deriving
# the prefix from this file's location.
if [ -z "${ONIONARMOR_PREFIX:-}" ]; then
  ONIONARMOR_PREFIX=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  export ONIONARMOR_PREFIX
fi
# shellcheck source=../../lib/common.sh
. "$ONIONARMOR_PREFIX/lib/common.sh"

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_TCB_SYSTEMCTL:=systemctl}"

# --- overridable filesystem paths -----------------------------------------
# Per-instance torrc trees: <instances-dir>/<name>/torrc. When no instances dir
# exists, fall back to the single system torrc.
: "${ONIONARMOR_TCB_INSTANCES_DIR:=/etc/tor/instances}"
: "${ONIONARMOR_TCB_TORRC:=/etc/tor/torrc}"
: "${ONIONARMOR_TCB_STATE_DIR:=/var/lib/onionarmor/tor-config-baseline}"

# The systemd unit name for the single-torrc (non-instances) path.
: "${ONIONARMOR_TCB_SINGLE_UNIT:=tor}"

# --- managed block markers ------------------------------------------------
# These bracket the block we own. We NEVER edit anything outside them.
TCB_BEGIN_MARK="# >>> onionarmor tor-config-baseline (managed) >>>"
TCB_END_MARK="# <<< onionarmor tor-config-baseline (managed) <<<"

# Default loopback binds for the managed MetricsPort/ControlPort.
: "${ONIONARMOR_TCB_METRICSPORT:=127.0.0.1:auto}"
: "${ONIONARMOR_TCB_CONTROLPORT:=127.0.0.1:auto}"
: "${ONIONARMOR_TCB_COOKIE_AUTH_FILE:=/var/run/tor/control.authcookie}"
: "${ONIONARMOR_TCB_SIGNING_KEY_LIFETIME:=60 days}"

# Operator-domain directives this module must NEVER set or alter. Kept here so
# the renderer and the audit share one source of truth.
TCB_OPERATOR_DIRECTIVES="ContactInfo MyFamily FamilyId ExitRelay SocksPort ORPort DirPort Nickname Address"

# --- flag defaults --------------------------------------------------------
tcb_set_defaults() {
  TCB_CONFIRM_OMK=0     # --confirm-offline-master-key (gates OfflineMasterKey 1)
  TCB_DRY_RUN=0
  TCB_VERIFY=1
}

tcb_parse_flags() {
  tcb_set_defaults
  while [ $# -gt 0 ]; do
    case "$1" in
      --confirm-offline-master-key) TCB_CONFIRM_OMK=1; shift ;;
      --dry-run)                    TCB_DRY_RUN=1; shift ;;
      --verify)                     TCB_VERIFY=1; shift ;;
      --no-verify)                  TCB_VERIFY=0; shift ;;
      -h|--help)                    tcb_usage; exit 0 ;;
      *)                            die "tor-config-baseline: unknown option: $1 (try --help)" ;;
    esac
  done
}

tcb_usage() {
  cat <<'EOF'
onionarmor apply --module tor-config-baseline [options]   (also: audit, revert)

Apply a baseline set of safe torrc directives across every tor instance, inside
a clearly-delimited managed block, WITHOUT touching operator-domain directives
(ContactInfo, MyFamily, ORPort, Nickname, ...). The block pins
SigningKeyLifetime, turns off DirReq/ConnDirection/ExtraInfo statistics, and
adds loopback-only MetricsPort/ControlPort defaults only when the operator has
not already bound one to loopback. Fully reversible (revert strips the block and
restores the pre-apply backup).

OPTIONS
  --confirm-offline-master-key  Also emit `OfflineMasterKey 1`. ONLY pass this if
                                you have generated an offline master key — it
                                changes signing-key behaviour. Omitted by default.
  --dry-run                     Print, per instance, the rendered managed block
                                and which directives are added vs preserved.
                                Changes nothing; never reloads.
  --verify / --no-verify        Post-apply verification: the managed block is
                                present and well-formed (default: verify).
  -h, --help                    This help.
EOF
}

# --- paths ----------------------------------------------------------------
# tcb_backup_path <name>: the pre-apply backup path for instance <name> (the
# single-torrc path uses the synthetic name "tor").
tcb_backup_path() {
  printf '%s/%s.torrc.bak\n' "$ONIONARMOR_TCB_STATE_DIR" "$1"
}

# --- instance discovery ---------------------------------------------------
# tcb_instances: print "<name> <torrc-path>" for every tor instance to manage,
# one per line. Prefers the per-instance tree when it has any */torrc; otherwise
# falls back to the single system torrc under the synthetic name "tor".
tcb_instances() {
  local d f name found=0
  d=$ONIONARMOR_TCB_INSTANCES_DIR
  if [ -d "$d" ]; then
    for f in "$d"/*/torrc; do
      [ -e "$f" ] || continue
      name=${f%/torrc}; name=${name##*/}
      printf '%s %s\n' "$name" "$f"
      found=1
    done
  fi
  if [ "$found" -eq 0 ]; then
    [ -f "$ONIONARMOR_TCB_TORRC" ] && printf '%s %s\n' "$ONIONARMOR_TCB_SINGLE_UNIT" "$ONIONARMOR_TCB_TORRC"
  fi
  return 0
}

# tcb_reload_target <name>: the systemd unit to reload for instance <name>. The
# single-torrc path reloads the bare unit; instances reload tor@<name>.
tcb_reload_target() {
  if [ "$1" = "$ONIONARMOR_TCB_SINGLE_UNIT" ] && [ ! -d "$ONIONARMOR_TCB_INSTANCES_DIR" ]; then
    printf '%s\n' "$ONIONARMOR_TCB_SINGLE_UNIT"
  else
    printf 'tor@%s\n' "$1"
  fi
}

# --- managed-block helpers ------------------------------------------------
# tcb_strip_block: read a torrc on stdin, print it with any managed block (and a
# single trailing blank-line separator we may have added before it) removed.
tcb_strip_block() {
  awk -v b="$TCB_BEGIN_MARK" -v e="$TCB_END_MARK" '
    $0 == b { inblk = 1; next }
    inblk   { if ($0 == e) inblk = 0; next }
    { print }
  '
}

# tcb_outside_block: read a torrc on stdin, print only the lines OUTSIDE the
# managed block — i.e. the operator-owned content. Used to inspect what the
# operator has already declared without seeing our own managed directives.
tcb_outside_block() {
  tcb_strip_block
}

# tcb_has_loopback_port <directive> <torrc-file>: return 0 if the operator (i.e.
# OUTSIDE the managed block) has already declared <directive> bound to a loopback
# address (127.* or [::1]). Used to preserve an existing loopback MetricsPort /
# ControlPort.
tcb_has_loopback_port() {
  local directive=$1 file=$2
  [ -f "$file" ] || return 1
  tcb_outside_block < "$file" | awk -v d="$directive" '
    { line = $0; sub(/#.*/, "", line)
      nf = split(line, F, /[ \t]+/)
      i = 1; while (i <= nf && F[i] == "") i++
      if (tolower(F[i]) != tolower(d)) next
      spec = F[i+1]
      if (spec ~ /^127\./ || spec ~ /^\[::1\]:/ || spec == "[::1]") { found = 1 }
    }
    END { exit (found ? 0 : 1) }
  '
}

# tcb_has_nonloopback_port <directive> <torrc-file>: return 0 if the operator has
# declared <directive> bound to a NON-loopback address (a real public/LAN bind we
# must never override). "auto", a bare port, or a unix socket are NOT treated as
# non-loopback here (bare ports/auto bind loopback by tor default).
tcb_has_nonloopback_port() {
  local directive=$1 file=$2
  [ -f "$file" ] || return 1
  tcb_outside_block < "$file" | awk -v d="$directive" '
    { line = $0; sub(/#.*/, "", line)
      nf = split(line, F, /[ \t]+/)
      i = 1; while (i <= nf && F[i] == "") i++
      if (tolower(F[i]) != tolower(d)) next
      spec = F[i+1]
      if (spec == "" || spec == "auto") next
      if (spec ~ /^127\./ || spec ~ /^\[::1\]/) next
      if (spec ~ /^unix:/) next
      if (spec ~ /^[0-9]+$/) next        # bare port -> tor binds loopback
      if (spec ~ /^auto$/) next
      found = 1
    }
    END { exit (found ? 0 : 1) }
  '
}

# tcb_operator_has <directive> <torrc-file>: return 0 if the operator declared
# <directive> at all (outside the managed block), regardless of value.
tcb_operator_has() {
  local directive=$1 file=$2
  [ -f "$file" ] || return 1
  tcb_outside_block < "$file" | awk -v d="$directive" '
    { line = $0; sub(/#.*/, "", line)
      nf = split(line, F, /[ \t]+/)
      i = 1; while (i <= nf && F[i] == "") i++
      if (tolower(F[i]) == tolower(d)) found = 1
    }
    END { exit (found ? 0 : 1) }
  '
}

# tcb_render_block <torrc-file>: render the managed block (markers included) for
# the given torrc, honouring the preserve-if-loopback logic for
# MetricsPort/ControlPort and the CookieAuth / OfflineMasterKey rules. Prints the
# whole block to stdout.
tcb_render_block() {
  local file=$1 controlport_in_effect=0

  printf '%s\n' "$TCB_BEGIN_MARK"
  printf '# Managed by onionarmor (module: tor-config-baseline) — do not edit by hand.\n'
  printf '# Revert with: onionarmor revert --module tor-config-baseline\n'

  # Pinned signing-key lifetime + statistics opt-outs (always set).
  printf 'SigningKeyLifetime %s\n' "$ONIONARMOR_TCB_SIGNING_KEY_LIFETIME"
  printf 'DirReqStatistics 0\n'
  printf 'ConnDirectionStatistics 0\n'
  printf 'ExtraInfoStatistics 0\n'

  # MetricsPort: only add a loopback default when the operator has not already
  # bound one to loopback. Never override a non-loopback operator bind.
  if tcb_has_loopback_port MetricsPort "$file"; then
    : # operator already has a loopback MetricsPort — preserve it, add nothing.
  elif tcb_has_nonloopback_port MetricsPort "$file"; then
    : # non-loopback operator bind — warned elsewhere; never override.
  else
    printf 'MetricsPort %s\n' "$ONIONARMOR_TCB_METRICSPORT"
  fi

  # ControlPort: same preserve-if-loopback logic.
  if tcb_has_loopback_port ControlPort "$file"; then
    controlport_in_effect=1
  elif tcb_has_nonloopback_port ControlPort "$file"; then
    : # non-loopback operator bind — warned elsewhere; never override.
  else
    printf 'ControlPort %s\n' "$ONIONARMOR_TCB_CONTROLPORT"
    controlport_in_effect=1
  fi

  # CookieAuth: if a ControlPort is in effect (managed or pre-existing) and the
  # operator has neither HashedControlPassword nor CookieAuthentication 1, add a
  # cookie-auth pair so the control port is not left unauthenticated.
  if [ "$controlport_in_effect" -eq 1 ]; then
    if ! tcb_operator_has HashedControlPassword "$file" \
       && ! tcb_has_cookieauth "$file"; then
      printf 'CookieAuthentication 1\n'
      printf 'CookieAuthFile %s\n' "$ONIONARMOR_TCB_COOKIE_AUTH_FILE"
    fi
  fi

  # OfflineMasterKey: only when explicitly confirmed (it assumes the operator
  # generated an offline master key and changes signing-key behaviour).
  if [ "$TCB_CONFIRM_OMK" -eq 1 ]; then
    printf 'OfflineMasterKey 1\n'
  fi

  printf '%s\n' "$TCB_END_MARK"
}

# tcb_has_cookieauth <torrc-file>: return 0 if the operator already enabled
# CookieAuthentication 1 (outside the managed block).
tcb_has_cookieauth() {
  local file=$1
  [ -f "$file" ] || return 1
  tcb_outside_block < "$file" | awk '
    { line = $0; sub(/#.*/, "", line)
      nf = split(line, F, /[ \t]+/)
      i = 1; while (i <= nf && F[i] == "") i++
      if (tolower(F[i]) == "cookieauthentication" && F[i+1] == "1") found = 1
    }
    END { exit (found ? 0 : 1) }
  '
}

# tcb_compose <torrc-file>: print the full intended torrc content for <file> —
# the operator content (block stripped) followed by a freshly rendered managed
# block. This is what apply writes and what idempotency compares against.
tcb_compose() {
  local file=$1 body block
  body=$(tcb_strip_block < "$file")
  block=$(tcb_render_block "$file")
  # Drop trailing blank lines from the operator body, then re-separate the block
  # with exactly one blank line, so re-running is byte-stable.
  body=$(printf '%s\n' "$body" | awk '
    { lines[NR] = $0 }
    END {
      last = NR
      while (last > 0 && lines[last] == "") last--
      for (i = 1; i <= last; i++) print lines[i]
    }
  ')
  if [ -n "$body" ]; then
    printf '%s\n\n%s\n' "$body" "$block"
  else
    printf '%s\n' "$block"
  fi
}

# tcb_block_present <torrc-file>: return 0 if a well-formed managed block (begin
# and end markers, begin before end) is present in the file.
tcb_block_present() {
  local file=$1
  [ -f "$file" ] || return 1
  awk -v b="$TCB_BEGIN_MARK" -v e="$TCB_END_MARK" '
    $0 == b { seen_b = 1 }
    $0 == e && seen_b { ok = 1 }
    END { exit (ok ? 0 : 1) }
  ' "$file"
}
