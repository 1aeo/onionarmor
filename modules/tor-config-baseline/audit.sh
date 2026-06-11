#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the tor-config-baseline posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Per instance: each enforced setting present+correct (green) or wrong/missing
# (red); a localhost Metrics/Control listener present (green) or absent (red);
# an unauthenticated ControlPort (red); the preserved operator lines intact
# (informational). A pending auto-revert latch is a yellow caution.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

tcb_parse_flags "$@"

info "tor-config-baseline audit"
printf '\n'

instances=$(tcb_instances)
if [ -z "$instances" ]; then
  oa_status_check red "instances" "no torrc found under $ONIONARMOR_TCB_INSTANCES_DIR/*/torrc or at $ONIONARMOR_TCB_TORRC"
  oa_status_summary "no tor instances discovered"
fi

while IFS=$'\t' read -r inst torrc; do
  [ -n "$inst" ] || continue
  printf 'instance: tor@%s (%s)\n' "$inst" "$torrc"

  # Plain enforced settings.
  printf '%s\n' "$TCB_ENFORCED" | while read -r key val; do
    [ -n "$key" ] || continue
    if tcb_setting_ok "$torrc" "$key" "$val"; then
      oa_status_check green "$inst/$key" "= $val"
    elif tcb_has_directive "$torrc" "$key"; then
      oa_status_check red "$inst/$key" "present but != '$val' — re-apply"
    else
      oa_status_check red "$inst/$key" "missing (expected '$val') — re-apply"
    fi
  done

  # Loopback Metrics / Control listeners.
  if tcb_has_localhost_listener "$torrc" MetricsPort; then
    oa_status_check green "$inst/MetricsPort" "localhost listener present"
  else
    oa_status_check red "$inst/MetricsPort" "no localhost MetricsPort — re-apply"
  fi
  if tcb_has_localhost_listener "$torrc" ControlPort; then
    oa_status_check green "$inst/ControlPort" "localhost listener present"
  else
    oa_status_check red "$inst/ControlPort" "no localhost ControlPort — re-apply"
  fi

  # ControlPort auth.
  if tcb_controlport_unauthed "$torrc"; then
    oa_status_check red "$inst/ControlPort-auth" "ControlPort set with NO CookieAuthentication / HashedControlPassword — re-apply"
  else
    oa_status_check green "$inst/ControlPort-auth" "authenticated (or no ControlPort)"
  fi

  # Preserved operator lines — informational (green when present, silent when not).
  for d in ContactInfo MyFamily FamilyId ExitRelay SocksPort; do
    if tcb_has_directive "$torrc" "$d"; then
      oa_status_check green "$inst/$d" "present (preserved, never modified)"
    fi
  done

  printf '\n'
done <<EOF
$instances
EOF

# Pending auto-revert latch -> yellow caution.
if oa_latch_is_armed "$TCB_MODULE"; then
  oa_status_check yellow "safety-latch" "an auto-revert latch is still armed — confirm tor is healthy then run: $(oa_latch_cancel_cmd "$TCB_MODULE")"
fi

oa_status_summary "one or more RED checks — the tor-config-baseline posture is incomplete or drifted"
