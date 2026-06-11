#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the ssh-hardening posture. Read-only;
# never changes host state. Exits non-zero if ANY check is red.
#
# Checks:
#   (a) the managed drop-in is present and matches the rendered posture,
#   (b) weak DSA + ECDSA host keys are absent (red if present),
#   (c) the RSA host key is >= the minimum bit strength (yellow if undeterminable),
#   (d) a pending auto-revert latch is still armed (yellow — confirm then cancel).

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

sshd_parse_flags "$@"

info "ssh-hardening audit"
printf '\n'

dropin=$(sshd_dropin_path)
rendered=$(sshd_render_dropin)

# --- (a) drop-in present + matches the rendered posture -------------------
if [ ! -f "$dropin" ]; then
  oa_status_check red "drop-in present" "$dropin missing — run: onionarmor apply --module ssh-hardening"
elif [ "$(cat "$dropin")" = "$rendered" ]; then
  oa_status_check green "drop-in present" "$dropin (matches Mozilla posture)"
else
  oa_status_check red "drop-in present" "$dropin DRIFTED from posture — re-apply"
fi

# --- (b) weak DSA + ECDSA host keys absent --------------------------------
weak_present=""
for stem in ssh_host_dsa_key ssh_host_ecdsa_key; do
  if [ -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/$stem" ] || [ -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/$stem.pub" ]; then
    weak_present="$weak_present $stem"
  fi
done
if [ -n "$weak_present" ]; then
  oa_status_check red "weak host keys absent" "present:$weak_present — re-apply to prune"
else
  oa_status_check green "weak host keys absent" "no DSA/ECDSA host keys in $ONIONARMOR_SSHD_HOSTKEY_DIR"
fi

# --- (c) RSA host key >= minimum strength ---------------------------------
rsa_key="$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_rsa_key"
if [ ! -f "$rsa_key" ]; then
  oa_status_check yellow "RSA host key strength" "no RSA host key at $rsa_key (ed25519-only is fine)"
else
  bits=$(sshd_rsa_bits "$rsa_key")
  case "$bits" in
    (*[!0-9]*|"")
      oa_status_check yellow "RSA host key strength" "could not determine bits for $rsa_key" ;;
    (*)
      if [ "$bits" -ge "$ONIONARMOR_SSHD_RSA_MIN_BITS" ]; then
        oa_status_check green "RSA host key strength" "$bits bits (>= $ONIONARMOR_SSHD_RSA_MIN_BITS)"
      else
        oa_status_check red "RSA host key strength" "$bits bits (< $ONIONARMOR_SSHD_RSA_MIN_BITS) — re-apply to regenerate"
      fi ;;
  esac
fi

# --- (d) pending auto-revert latch ----------------------------------------
if oa_latch_is_armed "$SSHD_LATCH_MODULE"; then
  oa_status_check yellow "safety latch" "auto-revert pending — confirm access then cancel: $(oa_latch_cancel_cmd "$SSHD_LATCH_MODULE")"
else
  oa_status_check green "safety latch" "none pending (no auto-revert armed)"
fi

oa_status_summary "one or more RED checks — ssh-hardening posture is broken or drifted"
