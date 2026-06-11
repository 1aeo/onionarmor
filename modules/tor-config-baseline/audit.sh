#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the tor-config-baseline posture.
# Read-only; never changes host state. Exits non-zero only if a check is red
# (this module's findings are advisory — missing directives are yellow, since a
# torrc the operator hand-tuned is theirs; a non-loopback Metrics/ControlPort is
# yellow because it is operator domain we will not move).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

tcb_parse_flags "$@"

info "tor-config-baseline audit"
printf '\n'

instances=$(tcb_instances)
if [ -z "$instances" ]; then
  oa_status_check yellow "tor instances" "none found in $ONIONARMOR_TCB_INSTANCES_DIR/*/torrc or $ONIONARMOR_TCB_TORRC"
  oa_status_summary "tor baseline directives missing on one or more instances"
fi

# tcb_block_has <directive> <file>: 0 if the managed block in <file> sets it.
tcb_block_has() {
  local directive=$1 file=$2
  [ -f "$file" ] || return 1
  awk -v b="$TCB_BEGIN_MARK" -v e="$TCB_END_MARK" -v d="$directive" '
    $0 == b { inblk = 1; next }
    $0 == e { inblk = 0; next }
    inblk {
      nf = split($0, F, /[ \t]+/)
      i = 1; while (i <= nf && F[i] == "") i++
      if (tolower(F[i]) == tolower(d)) found = 1
    }
    END { exit (found ? 0 : 1) }
  ' "$file"
}

while IFS=' ' read -r name file; do
  [ -n "$name" ] || continue

  # Pinned/stats directives: green if the managed block sets them.
  for d in SigningKeyLifetime DirReqStatistics ConnDirectionStatistics ExtraInfoStatistics; do
    if tcb_block_has "$d" "$file"; then
      oa_status_check green "$name $d" "set in managed block"
    else
      oa_status_check yellow "$name $d" "missing — run: onionarmor apply --module tor-config-baseline"
    fi
  done

  # MetricsPort / ControlPort: green if the managed block sets it OR the operator
  # already has a loopback equivalent; yellow on a non-loopback operator bind
  # (advisory — operator domain, we never move it) or if missing entirely.
  for d in MetricsPort ControlPort; do
    if tcb_block_has "$d" "$file"; then
      oa_status_check green "$name $d" "loopback default in managed block"
    elif tcb_has_loopback_port "$d" "$file"; then
      oa_status_check green "$name $d" "operator loopback bind preserved"
    elif tcb_has_nonloopback_port "$d" "$file"; then
      oa_status_check yellow "$name $d" "operator NON-loopback bind — left as-is (operator domain)"
    else
      oa_status_check yellow "$name $d" "missing — run apply to add a loopback default"
    fi
  done

  # CookieAuthentication: green if the block enabled it or the operator already
  # has cookie auth / a hashed control password; otherwise informational yellow
  # only when a ControlPort is actually in effect.
  if tcb_block_has CookieAuthentication "$file" || tcb_has_cookieauth "$file" \
     || tcb_operator_has HashedControlPassword "$file"; then
    oa_status_check green "$name ControlPort auth" "cookie auth / hashed password in effect"
  elif tcb_block_has ControlPort "$file" || tcb_has_loopback_port ControlPort "$file"; then
    oa_status_check yellow "$name ControlPort auth" "ControlPort in effect with no cookie/hashed auth — run apply"
  else
    oa_status_check green "$name ControlPort auth" "no ControlPort in effect (nothing to authenticate)"
  fi

  # OfflineMasterKey: yellow/info when absent (it is opt-in via --confirm-...).
  if tcb_block_has OfflineMasterKey "$file"; then
    oa_status_check green "$name OfflineMasterKey" "enabled in managed block"
  else
    oa_status_check yellow "$name OfflineMasterKey" "absent — opt-in only (apply --confirm-offline-master-key)"
  fi
done <<EOF
$instances
EOF

oa_status_summary "tor baseline directives missing on one or more instances"
