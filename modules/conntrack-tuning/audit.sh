#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the conntrack-tuning posture.
# Read-only; never changes host state. Exits non-zero if ANY check is red.
#
# Outcomes, mapped onto the shared green/yellow/red reporter:
#   n/a          nf_conntrack not loaded (no tailscale / stateful nftables) —
#                the table-full failure mode cannot occur. One info line, exit 0.
#   pass  green  live value meets the target / drop-in is present and valid.
#   warn  yellow utilization past the early-warning band, OR "unscoreable":
#                missing evidence (a live key unreadable, or a threshold override
#                that is not a positive integer). Per the repo convention we
#                surface unscoreable as a WARNING — never a silent pass and never
#                a hard FAIL, since we genuinely cannot score it. Exit 0.
#   fail  red    an undersized ceiling / over-long timeout, or a missing
#                persistence drop-in. Exit 1.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ct_parse_flags "$@"

info "conntrack-tuning audit"
printf '\n'

# --- detection: skip gracefully when the tracker is not loaded ------------
# Without nf_conntrack in the kernel there is no table to fill, so none of the
# checks below apply. Report n/a and exit 0 rather than scoring N inapplicable
# lines (this is the common case on the non-tailscale hosts).
if ! ct_module_loaded; then
  info "audit: n/a — nf_conntrack not loaded (no tailscale / stateful nftables); table-full risk does not apply"
  exit 0
fi

# A threshold OVERRIDE that is not a positive integer leaves the numeric checks
# with no defined pass/fail boundary. We cannot score them — but a bad operator
# env var must not crash the audit (set -e on the arithmetic) or be reported as
# a hard failure. Flag it and render those checks as yellow "unscoreable" below;
# the file-presence checks still score normally.
thresholds_ok=1
for _t in "$ONIONARMOR_CT_MIN_MAX" "$ONIONARMOR_CT_MAX_TCP_ESTABLISHED" "$ONIONARMOR_CT_UTIL_WARN_PCT"; do
  ct_is_uint "$_t" && [ "$_t" -gt 0 ] || thresholds_ok=0
done

dropin=$(ct_sysctl_dropin_path)
modprobe=$(ct_modprobe_dropin_path)

# --- (1) nf_conntrack_max >= target --------------------------------------
maxv=$(ct_sysctl_runtime "$CT_KEY_MAX")
if [ "$thresholds_ok" -eq 0 ]; then
  oa_status_check yellow "nf_conntrack_max" "unscoreable — a target threshold is not a positive integer (ONIONARMOR_CT_MIN_MAX='$ONIONARMOR_CT_MIN_MAX')"
elif ! ct_is_uint "$maxv" || [ "$maxv" -eq 0 ]; then
  # Tracker is loaded (marker present) but the ceiling is unreadable/zero — no
  # evidence to score against. Unscoreable, not a silent pass.
  oa_status_check yellow "nf_conntrack_max" "unscoreable — cannot read a usable $CT_KEY_MAX (got '${maxv:-<empty>}')"
elif [ "$maxv" -ge "$ONIONARMOR_CT_MIN_MAX" ]; then
  oa_status_check green "nf_conntrack_max" "$maxv >= $ONIONARMOR_CT_MIN_MAX target"
else
  oa_status_check red "nf_conntrack_max" "$maxv < $ONIONARMOR_CT_MIN_MAX target — table can pin full under load (run: onionarmor apply --module conntrack-tuning)"
fi

# --- (2) nf_conntrack_tcp_timeout_established <= target -------------------
tcpv=$(ct_sysctl_runtime "$CT_KEY_TCP_ESTABLISHED")
if [ "$thresholds_ok" -eq 0 ]; then
  oa_status_check yellow "tcp_timeout_established" "unscoreable — a target threshold is not a positive integer (ONIONARMOR_CT_MAX_TCP_ESTABLISHED='$ONIONARMOR_CT_MAX_TCP_ESTABLISHED')"
elif ! ct_is_uint "$tcpv"; then
  oa_status_check yellow "tcp_timeout_established" "unscoreable — cannot read a numeric $CT_KEY_TCP_ESTABLISHED (got '${tcpv:-<empty>}')"
elif [ "$tcpv" -le "$ONIONARMOR_CT_MAX_TCP_ESTABLISHED" ]; then
  oa_status_check green "tcp_timeout_established" "${tcpv}s <= ${ONIONARMOR_CT_MAX_TCP_ESTABLISHED}s target"
else
  oa_status_check red "tcp_timeout_established" "${tcpv}s > ${ONIONARMOR_CT_MAX_TCP_ESTABLISHED}s — stale flows hold table slots far too long"
fi

# --- (3) utilization: count/max < warn band ------------------------------
# Early-warning band, scored as a WARNING (yellow), not a failure: a correctly
# sized host can still trend hot, and we want that surfaced before it becomes an
# outage. Integer math only (count*100 vs max*pct) — no floats.
countv=$(ct_sysctl_runtime "$CT_KEY_COUNT")
if [ "$thresholds_ok" -eq 0 ]; then
  oa_status_check yellow "utilization" "unscoreable — the warn-band threshold is not a positive integer (ONIONARMOR_CT_UTIL_WARN_PCT='$ONIONARMOR_CT_UTIL_WARN_PCT')"
elif ! ct_is_uint "$maxv" || [ "$maxv" -eq 0 ]; then
  oa_status_check yellow "utilization" "unscoreable — cannot compute utilization: $CT_KEY_MAX is '${maxv:-<empty>}'"
elif ! ct_is_uint "$countv"; then
  oa_status_check yellow "utilization" "unscoreable — cannot read a numeric $CT_KEY_COUNT (got '${countv:-<empty>}')"
else
  pct=$(( countv * 100 / maxv ))
  if [ "$(( countv * 100 ))" -lt "$(( maxv * ONIONARMOR_CT_UTIL_WARN_PCT ))" ]; then
    oa_status_check green "utilization" "${countv}/${maxv} = ${pct}% (< ${ONIONARMOR_CT_UTIL_WARN_PCT}% warn band)"
  else
    oa_status_check yellow "utilization" "${countv}/${maxv} = ${pct}% (>= ${ONIONARMOR_CT_UTIL_WARN_PCT}% warn band) — trending toward table-full"
  fi
fi

# --- (4) sysctl persistence drop-in present with both keys ----------------
if ct_sysctl_dropin_has_keys; then
  oa_status_check green "sysctl drop-in" "$dropin declares both net.netfilter.* lines"
elif [ -f "$dropin" ]; then
  oa_status_check red "sysctl drop-in" "$dropin exists but is missing a managed net.netfilter.* line — persistence incomplete"
else
  oa_status_check red "sysctl drop-in" "$dropin missing — tuning is not persisted across reboot (run: onionarmor apply --module conntrack-tuning)"
fi

# --- (5) modprobe hashsize drop-in present --------------------------------
if ct_modprobe_has_option; then
  oa_status_check green "modprobe hashsize" "$modprobe sets options nf_conntrack hashsize=..."
else
  oa_status_check red "modprobe hashsize" "$modprobe missing the 'options nf_conntrack hashsize=...' line — hash table not resized on module load"
fi

oa_status_summary "one or more RED checks — conntrack tuning is missing, drifted, or undersized"
