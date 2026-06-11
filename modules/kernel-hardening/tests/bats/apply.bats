#!/usr/bin/env bats
# kernel-hardening apply.sh — drop-in render, idempotence, dry-run, reload,
# verification, and audit logging.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: writes the drop-in with all 15 KSPP keys" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  # Exactly 15 managed "key = value" lines.
  [ "$(desired_keys | grep -c .)" -eq 15 ]
  # Spot-check a few keys from across the set, in the required order/values.
  grep -q '^kernel.dmesg_restrict = 1$' "$DROPIN"
  grep -q '^kernel.kptr_restrict = 2$' "$DROPIN"
  grep -q '^net.ipv4.tcp_syncookies = 1$' "$DROPIN"
  grep -q '^net.ipv6.conf.all.accept_source_route = 0$' "$DROPIN"
  grep -q '^net.ipv4.conf.all.log_martians = 1$' "$DROPIN"
  # Managed header + revert hint + source line present.
  grep -q 'Managed by onionarmor (module: kernel-hardening)' "$DROPIN"
  grep -q 'Revert with: onionarmor revert --module kernel-hardening' "$DROPIN"
  grep -q 'kspp.github.io/Recommended_Settings' "$DROPIN"
}

@test "apply: loads the keys so live == desired after --system" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q -- '--system' "$STUB_SYSCTL_LOG"
  while read -r key want; do
    [ "$("$ONIONARMOR_SYSCTL_CMD" -n "$key")" = "$want" ]
  done < <(desired_keys)
  [[ "$output" == *"applied."* ]]
}

@test "apply: idempotent — second run says 'already current'" {
  bash "$APPLY" >/dev/null
  : > "$STUB_SYSCTL_LOG"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  # Nothing reloaded the second time.
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "apply: --dry-run writes nothing and never calls --system" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: kernel-hardening"* ]]
  [[ "$output" == *"kernel.dmesg_restrict"* ]]
  [[ "$output" == *"CURRENT"* ]]
  [ ! -e "$DROPIN" ]
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
}

@test "apply: --no-verify with a failing --system exits 2" {
  KH_SYSCTL_SYSTEM_RC=1 run bash "$APPLY" --no-verify
  [ "$status" -eq 2 ]
  # The drop-in was still written before the reload.
  [ -f "$DROPIN" ]
}

@test "apply: a noisy --system exit does NOT fail apply when verify matches" {
  # Verify is authoritative: --system exits nonzero but the keys still loaded.
  KH_SYSCTL_SYSTEM_RC=1 run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"applied."* ]]
  [ "$("$ONIONARMOR_SYSCTL_CMD" -n kernel.dmesg_restrict)" = "1" ]
}

@test "apply: ONIONARMOR_SKIP_RELOAD skips --system" {
  ONIONARMOR_SKIP_RELOAD=yes run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$DROPIN" ]
  ! grep -q -- '--system' "$STUB_SYSCTL_LOG"
  [[ "$output" == *"skipping sysctl --system"* ]]
}

@test "apply: backs up an existing drop-in before overwriting" {
  mkdir -p "$ONIONARMOR_SYSCTL_DIR"
  printf '# stale hand-written drop-in\nkernel.dmesg_restrict = 0\n' > "$DROPIN"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  backup="$ONIONARMOR_KH_STATE_DIR/backup.conf"
  [ -f "$backup" ]
  grep -q 'stale hand-written drop-in' "$backup"
  # The drop-in is now the managed KSPP content.
  grep -q '^kernel.dmesg_restrict = 1$' "$DROPIN"
}

@test "apply: unknown option dies cleanly" {
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'kh.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'kh.apply.dropin' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'kh.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
