#!/usr/bin/env bats
# ssh-hardening apply.sh — drop-in render, idempotency, safety latch, sshd -t
# validation gating, host-key pruning + RSA regeneration.

load test_helper

dropin_has() { grep -qx "$1" "$DROPIN"; }

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: writes the drop-in with the full Mozilla directive set" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  dropin_has "PermitRootLogin no"
  dropin_has "PasswordAuthentication no"
  dropin_has "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
  dropin_has "MaxAuthTries 3"
  dropin_has "ClientAliveInterval 300"
  dropin_has "X11Forwarding no"
  dropin_has "AllowAgentForwarding no"
  dropin_has "GatewayPorts no"
  dropin_has "PermitTunnel no"
  dropin_has "UsePAM yes"
  grep -q "KexAlgorithms curve25519-sha256," "$DROPIN"
  grep -q "Ciphers chacha20-poly1305@openssh.com," "$DROPIN"
  grep -q "MACs hmac-sha2-256-etm@openssh.com," "$DROPIN"
  [[ "$output" == *"applied."* ]]
}

@test "apply: validates with sshd -t and reloads sshd" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"sshd -t passed"* ]]
  grep -q "reload ssh" "$SYSTEMCTL_LOG"
}

@test "apply: arms the safety latch (jobid recorded, restore staged, cancel cmd printed)" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -s "$AT_QUEUE" ]
  job="$(cat "$AT_QUEUE")"
  [ "$(latch_jobid)" = "$job" ]
  [ -f "$LATCH_DIR/restore.sh" ]
  [[ "$output" == *"SSH SAFETY LATCH ARMED"* ]]
  [[ "$output" == *"atrm $job"* ]]
  [[ "$output" == *"--cancel-safety-latch"* ]]
}

@test "apply: staged restore.sh restores the prior config and reloads" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  # The restore script removes our drop-in (none pre-existed) then validates+reloads.
  : > "$SYSTEMCTL_LOG"
  run sh "$LATCH_DIR/restore.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$DROPIN" ]
  grep -q "reload ssh" "$SYSTEMCTL_LOG"
}

@test "apply: idempotent — second run rewrites nothing + stacks no second latch" {
  bash "$APPLY" >/dev/null
  first_job="$(cat "$AT_QUEUE")"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  # No new at job appended.
  [ "$(latch_jobid)" = "$first_job" ]
  [ "$(wc -l < "$AT_QUEUE" | tr -d ' ')" -eq 1 ]
}

@test "apply --dry-run: prints plan, writes nothing, never reloads, arms no latch" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: ssh-hardening"* ]]
  [[ "$output" == *"PermitRootLogin no"* ]]
  [ ! -e "$DROPIN" ]
  [ ! -s "$AT_QUEUE" ]
  [ ! -f "$SYSTEMCTL_LOG" ] || [ ! -s "$SYSTEMCTL_LOG" ]
}

@test "apply --no-safety-latch: arms nothing but still applies + reloads" {
  run bash "$APPLY" --no-safety-latch
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  [ ! -s "$AT_QUEUE" ]
  [ ! -f "$LATCH_DIR/jobid" ]
  [[ "$output" == *"console access"* ]]
  grep -q "reload ssh" "$SYSTEMCTL_LOG"
}

@test "apply --cancel-safety-latch: cancels a pending latch and exits 0" {
  bash "$APPLY" >/dev/null
  [ -s "$AT_QUEUE" ]
  run bash "$APPLY" --cancel-safety-latch
  [ "$status" -eq 0 ]
  [[ "$output" == *"cancelled"* ]]
  [ ! -f "$LATCH_DIR/jobid" ]
  [ ! -s "$AT_QUEUE" ]
}

@test "apply: a FAILED sshd -t removes the drop-in, cancels the latch, exits nonzero, NO reload" {
  SSHD_T_RC=1 run bash "$APPLY"
  [ "$status" -ne 0 ]
  [ ! -e "$DROPIN" ]
  [ ! -f "$LATCH_DIR/jobid" ]
  [ ! -s "$AT_QUEUE" ]
  [ ! -s "$SYSTEMCTL_LOG" ]
  [[ "$output" == *"rejected"* ]]
}

@test "apply: a FAILED sshd -t restores a pre-existing drop-in backup" {
  printf 'PreExisting yes\n' > "$DROPIN"
  SSHD_T_RC=1 run bash "$APPLY"
  [ "$status" -ne 0 ]
  # The pre-existing content is restored, not left as our (rejected) hardened set.
  grep -q "PreExisting yes" "$DROPIN"
}

@test "apply: removes DSA and ECDSA host keys" {
  seed_hostkey ssh_host_dsa_key
  seed_hostkey ssh_host_ecdsa_key
  seed_hostkey ssh_host_ed25519_key
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_dsa_key" ]
  [ ! -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_dsa_key.pub" ]
  [ ! -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_ecdsa_key" ]
  [ ! -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_ecdsa_key.pub" ]
  # ed25519 must be left alone.
  [ -e "$ONIONARMOR_SSHD_HOSTKEY_DIR/ssh_host_ed25519_key" ]
}

@test "apply: RSA host key < 4096 bits triggers regeneration" {
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=2048 run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'generate.*-t rsa.*-b 4096' "$KEYGEN_LOG"
  [[ "$output" == *"regenerated RSA host key"* ]]
}

@test "apply: RSA host key >= 4096 bits is NOT regenerated" {
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=4096 run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -s "$KEYGEN_LOG" ]
}

@test "apply: latch arming failure (atd down) aborts without writing the drop-in" {
  # Point the at command at a stub that always fails to schedule.
  cat > "$STUB/at-fail" <<'EOF'
#!/bin/sh
cat >/dev/null
echo "Can't open /var/run/atd.pid to signal atd. No atd running?" >&2
exit 1
EOF
  chmod +x "$STUB/at-fail"
  ONIONARMOR_AT_CMD="$STUB/at-fail" run bash "$APPLY"
  [ "$status" -ne 0 ]
  [ ! -e "$DROPIN" ]
  [ ! -s "$SYSTEMCTL_LOG" ]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'sshd.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sshd.apply.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'sshd.apply.done' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'latch.arm' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: unknown option is rejected" {
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "apply: --latch-minutes must be numeric" {
  run bash "$APPLY" --latch-minutes abc
  [ "$status" -ne 0 ]
  [[ "$output" == *"numeric"* ]]
}
