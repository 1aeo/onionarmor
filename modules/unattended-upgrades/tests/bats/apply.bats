#!/usr/bin/env bats
# unattended-upgrades apply.sh — behaviour, idempotency, distro handling.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: prints plan + config, changes nothing" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: unattended-upgrades"* ]]
  [[ "$output" == *"Origins-Pattern"* ]]
  [[ "$output" == *'APT::Periodic::Unattended-Upgrade "1"'* ]]
  [ ! -e "$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades" ]
  [ ! -e "$ONIONARMOR_UU_APT_CONFD/20auto-upgrades" ]
}

@test "apply: writes both config files, enables the service" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  f20="$ONIONARMOR_UU_APT_CONFD/20auto-upgrades"
  [ -f "$f50" ]
  [ -f "$f20" ]
  grep -q 'Managed by onionarmor' "$f50"
  grep -q 'label=Debian-Security' "$f50"
  grep -q 'Automatic-Reboot "true"' "$f50"
  grep -q 'Automatic-Reboot-Time "03:00"' "$f50"
  grep -q '^APT::Periodic::Update-Package-Lists "1";' "$f20"
  grep -q '^APT::Periodic::Unattended-Upgrade "1";' "$f20"
  # service got enabled + started
  grep -q 'enable unattended-upgrades.service now=1' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/unattended-upgrades.service")" = "enabled" ]
  [[ "$output" == *"applied."* ]]
}

@test "apply: installs tooling when missing, marks it installed" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'install -y --no-install-recommends.*unattended-upgrades' "$STUB/apt-get.log"
  grep -q 'apt-listchanges' "$STUB/apt-get.log"
  [ -e "$SB/pkgs/unattended-upgrades" ]
  [ -e "$SB/pkgs/apt-listchanges" ]
}

@test "apply: skips install when tooling already present" {
  mark_installed unattended-upgrades
  mark_installed apt-listchanges
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -e "$STUB/apt-get.log" ]
}

@test "apply: security-only — no -updates origin is emitted" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  ! grep -qE '\-updates' "$f50"
}

@test "apply: idempotent — second run rewrites nothing" {
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
}

@test "apply: backs up a pre-existing distro default once" {
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  printf '// distro default\nUnattended-Upgrade::Foo "bar";\n' > "$f50"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  bkp="$ONIONARMOR_UU_STATE_DIR/50unattended-upgrades.orig"
  [ -f "$bkp" ]
  grep -q 'distro default' "$bkp"
  # second apply does not re-back-up over the saved default
  printf 'tamper\n' >> "$bkp"
  bash "$APPLY" >/dev/null
  grep -q 'tamper' "$bkp"
}

@test "apply --distro Ubuntu --codename noble: emits Ubuntu origins" {
  FAKE_DISTRO="Ubuntu" FAKE_CODENAME="noble" run bash "$APPLY"
  [ "$status" -eq 0 ]
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  grep -q 'origin=Ubuntu,archive=${distro_codename}-security' "$f50"
  grep -q 'UbuntuESM' "$f50"
  ! grep -q 'Debian-Security' "$f50"
}

@test "apply --no-reboot: disables automatic reboot" {
  run bash "$APPLY" --no-reboot
  [ "$status" -eq 0 ]
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  grep -q 'Automatic-Reboot "false"' "$f50"
}

@test "apply --reboot-time 04:30: honours the override" {
  run bash "$APPLY" --reboot-time 04:30
  [ "$status" -eq 0 ]
  f50="$ONIONARMOR_UU_APT_CONFD/50unattended-upgrades"
  grep -q 'Automatic-Reboot-Time "04:30"' "$f50"
}

@test "apply: rejects a malformed --reboot-time" {
  run bash "$APPLY" --reboot-time 25:99
  [ "$status" -ne 0 ]
  [[ "$output" == *"HH:MM"* ]]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'uu.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'uu.apply.conf50' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'uu.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: exit 2 when the service cannot be enabled" {
  # Make the systemctl stub fail on enable.
  cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = "enable" ] && exit 1
exit 0
EOF
  chmod +x "$STUB/systemctl"
  run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"could not be enabled"* ]]
}
