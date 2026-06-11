#!/usr/bin/env bats
# ssh-hardening audit.sh — RED before apply / GREEN after / yellow when a latch
# is pending or host keys are weak. Read-only.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: RED before apply (drop-in missing) exits nonzero" {
  run bash "$AUDIT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing"* ]]
  [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: GREEN after apply once the latch is cancelled" {
  # A >=4096-bit RSA host key present so the RSA check is green too (not yellow).
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=4096 bash "$APPLY" >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  SSHD_RSA_BITS=4096 run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all green"* ]]
}

@test "audit: yellow (still exits 0) while an auto-revert latch is pending" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"auto-revert pending"* ]]
}

@test "audit: RED if a DSA/ECDSA host key is present" {
  bash "$APPLY" >/dev/null
  bash "$APPLY" --cancel-safety-latch >/dev/null
  seed_hostkey ssh_host_ecdsa_key
  run bash "$AUDIT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"weak host keys absent"* ]]
}

@test "audit: RED if the RSA host key is under 4096 bits" {
  bash "$APPLY" --no-safety-latch >/dev/null
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=2048 run bash "$AUDIT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"RSA host key strength"* ]]
}

@test "audit: yellow when RSA strength cannot be determined" {
  bash "$APPLY" --no-safety-latch >/dev/null
  seed_hostkey ssh_host_rsa_key
  SSHD_RSA_BITS=unknown run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"could not determine"* ]]
}

@test "audit: read-only — does not create or remove the drop-in" {
  run bash "$AUDIT"
  [ ! -e "$DROPIN" ]
}
