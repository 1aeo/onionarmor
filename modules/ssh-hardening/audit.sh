#!/usr/bin/env bash
# audit.sh — green/yellow/red status of the ssh-hardening posture. Read-only;
# never changes host state. Exits non-zero if any check is red.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

ssh_parse_flags "$@"

dropin=$(ssh_dropin_path)
info "ssh-hardening audit"
printf '\n'

# --- 1. drop-in present ----------------------------------------------------
if [ ! -f "$dropin" ]; then
  oa_status_check yellow "drop-in present" "not applied yet ($dropin missing)"
  oa_status_summary "ssh-hardening not applied"
fi
oa_status_check green "drop-in present" "$dropin"

# --- 2. key directives are the hardened values -----------------------------
# Compare each managed directive to the live drop-in. A drifted/removed
# directive is red (someone weakened the posture).
content=$(cat "$dropin" 2>/dev/null || true)
while IFS= read -r line; do
  [ -n "$line" ] || continue
  key=${line%% *}
  if printf '%s\n' "$content" | grep -qiE "^[[:space:]]*${key}[[:space:]]"; then
    have=$(printf '%s\n' "$content" | grep -iE "^[[:space:]]*${key}[[:space:]]" | head -1 | sed 's/^[[:space:]]*//')
    if [ "$have" = "$line" ]; then
      oa_status_check green "$key" "ok"
    else
      oa_status_check red "$key" "drifted: '$have' (want '$line')"
    fi
  else
    oa_status_check red "$key" "missing from drop-in"
  fi
done <<EOF
$(ssh_hardening_directives)
EOF

# --- 3. AllowUsers scoping -------------------------------------------------
if printf '%s\n' "$content" | grep -qiE '^[[:space:]]*AllowUsers[[:space:]]'; then
  who=$(printf '%s\n' "$content" | grep -iE '^[[:space:]]*AllowUsers[[:space:]]' | head -1 | sed 's/^[[:space:]]*AllowUsers[[:space:]]*//')
  oa_status_check green "AllowUsers" "scoped to: $who"
else
  oa_status_check yellow "AllowUsers" "not set — every account may attempt login (pass --allow-user on apply)"
fi

# --- 4. config validity ----------------------------------------------------
if ssh_config_test >/dev/null 2>&1; then
  oa_status_check green "sshd -t" "configuration is valid"
else
  oa_status_check red "sshd -t" "sshd rejects the current configuration"
fi

# --- 5. weak host keys -----------------------------------------------------
weak=$(ssh_weak_hostkeys | tr '\n' ' ' | sed 's/ *$//')
if [ -n "$weak" ]; then
  oa_status_check yellow "weak host keys" "still present: $weak (apply removes these)"
else
  oa_status_check green "weak host keys" "no DSA/ECDSA host keys"
fi

# --- 6. RSA host-key strength ---------------------------------------------
rsa_bits=$(ssh_rsa_bits)
if [ -z "$rsa_bits" ]; then
  oa_status_check green "RSA host key" "no RSA host key present"
elif [ "$rsa_bits" -ge "$ONIONARMOR_SSH_RSA_MIN_BITS" ]; then
  oa_status_check green "RSA host key" "$rsa_bits-bit (>= $ONIONARMOR_SSH_RSA_MIN_BITS)"
else
  oa_status_check yellow "RSA host key" "$rsa_bits-bit (< $ONIONARMOR_SSH_RSA_MIN_BITS — apply regrows it)"
fi

# --- 7. pending safety latch ----------------------------------------------
job=$(ssh_latch_pending)
if [ -n "$job" ]; then
  oa_status_check yellow "safety latch" "at job $job still PENDING — confirm your session then: atrm $job"
else
  oa_status_check green "safety latch" "no pending auto-restore job"
fi

oa_status_summary "ssh-hardening posture is broken (a hardened directive drifted or sshd -t fails)"
