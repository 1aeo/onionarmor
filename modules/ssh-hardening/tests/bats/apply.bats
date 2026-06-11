#!/usr/bin/env bats
# ssh-hardening apply.sh — drop-in rendering, AllowUsers scoping, host-key
# surgery, the 5-minute safety latch, sshd -t gating, dry-run, idempotency.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: writes the hardened directives to the drop-in" {
  seed_login operator
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  dropin_has '^PermitRootLogin no$'
  dropin_has '^PasswordAuthentication no$'
  dropin_has '^KbdInteractiveAuthentication no$'
  dropin_has '^KexAlgorithms curve25519-sha256@libssh.org'
  dropin_has '^Ciphers chacha20-poly1305@openssh.com'
  dropin_has '^MACs hmac-sha2-512-etm@openssh.com'
  dropin_has '^MaxAuthTries 3$'
}

@test "apply: AllowUsers is scoped to logged-in users" {
  seed_login operator deploybot
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -qE '^AllowUsers (deploybot operator|operator deploybot)$' "$DROPIN"
}

@test "apply: AllowUsers omitted (with a warning) when no users are detected" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  ! grep -qi '^AllowUsers' "$DROPIN"
  [[ "$output" == *"AllowUsers OMITTED"* ]]
}

@test "apply: --allow-user adds an explicit account to AllowUsers" {
  run bash "$APPLY" --allow-user operator
  [ "$status" -eq 0 ]
  grep -qE '^AllowUsers operator$' "$DROPIN"
}

@test "apply: removes weak DSA/ECDSA host keys and backs them up" {
  seed_login operator
  seed_weak_hostkeys
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_dsa_key" ]
  [ ! -e "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_ecdsa_key" ]
  [ -f "$ONIONARMOR_SSH_STATE_DIR/hostkeys.bak/ssh_host_dsa_key" ]
}

@test "apply: regrows a sub-4096-bit RSA host key" {
  seed_login operator
  seed_rsa 2048
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ "$(cat "$RSA_BITS_FILE")" = "4096" ]
  [ -f "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_rsa_key" ]
}

@test "apply: --no-host-keys leaves host keys untouched" {
  seed_login operator
  seed_weak_hostkeys
  seed_rsa 2048
  run bash "$APPLY" --no-host-keys
  [ "$status" -eq 0 ]
  [ -e "$ONIONARMOR_SSH_HOSTKEY_DIR/ssh_host_dsa_key" ]
  [ "$(cat "$RSA_BITS_FILE")" = "2048" ]
}

@test "apply: schedules the 5-minute safety latch" {
  seed_login operator
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"SSH SAFETY LATCH ACTIVE"* ]]
  [[ "$output" == *"atrm"* ]]
  # A pending at-job exists and the state file records it.
  [ -s "$ATQ_FILE" ]
  [ -f "$ONIONARMOR_SSH_STATE_DIR/safety-latch.job" ]
}

@test "apply: --no-safety-latch schedules no auto-restore" {
  seed_login operator
  run bash "$APPLY" --no-safety-latch
  [ "$status" -eq 0 ]
  [[ "$output" == *"no auto-restore scheduled"* ]]
  [ ! -s "$ATQ_FILE" ]
}

@test "apply: a config that fails sshd -t is rolled back and not reloaded" {
  seed_login operator
  force_sshd_invalid
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"sshd -t"* ]]
  # Prior state restored: no managed drop-in left behind, sshd never reloaded.
  [ ! -e "$DROPIN" ]
  [ ! -s "$SYSTEMCTL_LOG" ]
}

@test "apply: --dry-run prints the plan and changes nothing" {
  seed_login operator
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: ssh-hardening"* ]]
  [[ "$output" == *"PermitRootLogin no"* ]]
  [ ! -e "$DROPIN" ]
  [ ! -s "$ATQ_FILE" ]
}

@test "apply: idempotent — second run reports already applied" {
  seed_login operator
  seed_weak_hostkeys
  seed_rsa 2048
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already applied"* ]]
}

@test "apply: ONIONARMOR_SKIP_RELOAD=yes writes the drop-in but does not reload" {
  seed_login operator
  ONIONARMOR_SKIP_RELOAD=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  [ ! -s "$SYSTEMCTL_LOG" ]
}

@test "apply: writes audit-log entries" {
  seed_login operator
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'ssh.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ssh.apply.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'ssh.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
