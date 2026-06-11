#!/usr/bin/env bats
# mac-profile-install apply.sh — distro detection, install + enforce per family,
# idempotency, dry-run.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply: Debian os-release -> AppArmor path installs packages + enforces tor" {
  seed_os_release_debian
  seed_apparmor_profile
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'apt-get install .*apparmor' "$INSTALL_LOG"
  grep -q 'apparmor-profiles' "$INSTALL_LOG"
  grep -q 'apparmor-utils' "$INSTALL_LOG"
  grep -q "aa-enforce .*usr.bin.tor" "$ACTION_LOG"
  [[ "$output" == *"applied."* ]]
  [ "$(cat "$AA_TOR_STATE")" = "enforce" ]
}

@test "apply: Ubuntu os-release also resolves to the AppArmor path" {
  seed_os_release_ubuntu
  seed_apparmor_profile
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'apt-get install .*apparmor' "$INSTALL_LOG"
  ! grep -q 'dnf install' "$INSTALL_LOG"
}

@test "apply: Debian with no tor profile installs packages but enforces nothing" {
  seed_os_release_debian
  # no profile seeded
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'apt-get install .*apparmor' "$INSTALL_LOG"
  [ ! -s "$ACTION_LOG" ]
  [[ "$output" == *"absent"* ]]
}

@test "apply: RHEL os-release -> SELinux path installs policycoreutils + enforcing + setenforce 1" {
  seed_os_release_rhel
  seed_selinux_config permissive
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'dnf install .*policycoreutils' "$INSTALL_LOG"
  grep -q 'selinux-policy-targeted' "$INSTALL_LOG"
  [ "$(config_selinux_mode)" = "enforcing" ]
  grep -q 'setenforce 1' "$ACTION_LOG"
  [ "$(cat "$SE_RUNMODE")" = "enforcing" ]
}

@test "apply: --distro debian forces the AppArmor path regardless of os-release" {
  seed_os_release_rhel       # host LOOKS like RHEL ...
  seed_apparmor_profile
  run bash "$APPLY" --distro debian   # ... but we force debian
  [ "$status" -eq 0 ]
  grep -q 'apt-get install' "$INSTALL_LOG"
  ! grep -q 'dnf install' "$INSTALL_LOG"
}

@test "apply: --distro rhel forces the SELinux path regardless of os-release" {
  seed_os_release_debian
  seed_selinux_config permissive
  run bash "$APPLY" --distro rhel
  [ "$status" -eq 0 ]
  grep -q 'dnf install' "$INSTALL_LOG"
  ! grep -q 'apt-get install' "$INSTALL_LOG"
}

@test "apply: undetectable distro with no --distro dies with guidance" {
  printf 'ID=plan9\n' > "$ONIONARMOR_MAC_OS_RELEASE"
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"unsupported/undetected distro"* ]]
}

@test "apply --dry-run (debian): prints plan, installs nothing, enforces nothing" {
  seed_os_release_debian
  seed_apparmor_profile
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: mac-profile-install"* ]]
  [[ "$output" == *"AppArmor"* ]]
  [ ! -s "$INSTALL_LOG" ]
  [ ! -s "$ACTION_LOG" ]
}

@test "apply --dry-run (rhel): prints plan, installs nothing, never setenforces" {
  seed_os_release_rhel
  seed_selinux_config disabled
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"SELinux"* ]]
  [ ! -s "$INSTALL_LOG" ]
  [ ! -s "$ACTION_LOG" ]
  [ "$(config_selinux_mode)" = "disabled" ]   # config untouched
}

@test "apply (debian): idempotent — already enforcing says 'already applied'" {
  seed_os_release_debian
  seed_apparmor_profile
  set_aa_tor_state enforce       # tor already enforcing
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already applied"* ]]
  [ ! -s "$INSTALL_LOG" ]         # no install attempted
}

@test "apply (rhel): idempotent — running+config enforcing says 'already applied'" {
  seed_os_release_rhel
  seed_selinux_config enforcing
  set_se_runmode enforcing
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already applied"* ]]
  [ ! -s "$INSTALL_LOG" ]
}

@test "apply: writes audit-log entries (debian)" {
  seed_os_release_debian
  seed_apparmor_profile
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'mac.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.install' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.enforce' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'mac.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply: unknown option is rejected" {
  seed_os_release_debian
  run bash "$APPLY" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "apply: --distro without a value is rejected" {
  run bash "$APPLY" --distro
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires a value"* ]]
}
