#!/usr/bin/env bats

load test_helper

@test "apply-lockdown: appends lockdown=integrity when absent" {
  cat > "$ONIONARMOR_GRUB_FILE" <<'EOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX=""
EOF
  run "$ONIONARMOR_BIN" apply-lockdown --no-reboot
  [ "$status" -eq 0 ]
  grep -q 'GRUB_CMDLINE_LINUX_DEFAULT="quiet lockdown=integrity"' "$ONIONARMOR_GRUB_FILE"
  grep -q "lockdown.done" "$ONIONARMOR_AUDIT_LOG"
}

@test "apply-lockdown: rewrites pre-existing lockdown=confidentiality" {
  cat > "$ONIONARMOR_GRUB_FILE" <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="quiet lockdown=confidentiality"
EOF
  run "$ONIONARMOR_BIN" apply-lockdown --no-reboot
  [ "$status" -eq 0 ]
  grep -q 'GRUB_CMDLINE_LINUX_DEFAULT="quiet lockdown=integrity"' "$ONIONARMOR_GRUB_FILE"
}

@test "apply-lockdown: idempotent — running twice is a no-op modification" {
  cat > "$ONIONARMOR_GRUB_FILE" <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
EOF
  "$ONIONARMOR_BIN" apply-lockdown --no-reboot >/dev/null 2>&1
  first=$(md5sum "$ONIONARMOR_GRUB_FILE" | awk '{print $1}')
  "$ONIONARMOR_BIN" apply-lockdown --no-reboot >/dev/null 2>&1
  second=$(md5sum "$ONIONARMOR_GRUB_FILE" | awk '{print $1}')
  [ "$first" = "$second" ]
}

@test "apply-lockdown: prints REBOOT REQUIRED when --no-reboot not given" {
  cat > "$ONIONARMOR_GRUB_FILE" <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
EOF
  run "$ONIONARMOR_BIN" apply-lockdown
  [ "$status" -eq 0 ]
  [[ "$output" == *"REBOOT REQUIRED"* ]]
}
