# Common bats helpers: set up a sandbox + env so onionarmor never touches
# the real /etc or /var/log. Sourced by every *.bats file.

setup() {
  ONIONARMOR_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  export ONIONARMOR_ROOT
  ONIONARMOR_BIN="$ONIONARMOR_ROOT/bin/onionarmor"
  export ONIONARMOR_BIN

  SANDBOX="$(mktemp -d)"
  export SANDBOX

  export ONIONARMOR_ROLES_DIR="$ONIONARMOR_ROOT/roles"
  export ONIONARMOR_ETC_DIR="$SANDBOX/etc/onionarmor"
  export ONIONARMOR_SYSCTL_DIR="$SANDBOX/etc/sysctl.d"
  export ONIONARMOR_AUDIT_LOG="$SANDBOX/var/log/onionarmor/audit.log"
  export ONIONARMOR_SYSCTL_CMD="$ONIONARMOR_ROOT/tests/fixtures/fake-sysctl"
  export ONIONARMOR_GRUB_FILE="$SANDBOX/etc/default/grub"
  export ONIONARMOR_UPDATE_GRUB_CMD="true"
  export ONIONARMOR_SKIP_UPDATE_GRUB="yes"
  export ONIONARMOR_OPERATOR="bats-test"
  export FAKE_SYSCTL_STATE="$SANDBOX/sysctl-state"

  mkdir -p "$ONIONARMOR_ETC_DIR" "$ONIONARMOR_SYSCTL_DIR" \
           "$(dirname "$ONIONARMOR_AUDIT_LOG")" "$(dirname "$ONIONARMOR_GRUB_FILE")"
  cp "$ONIONARMOR_ROOT/tests/fixtures/relay-c-baseline.state" "$FAKE_SYSCTL_STATE"
}

teardown() {
  if [ -n "${SANDBOX:-}" ] && [ -d "$SANDBOX" ]; then rm -rf "$SANDBOX"; fi
}

declare_host_role() {
  local role=$1
  printf 'role=%s\n' "$role" > "$ONIONARMOR_ETC_DIR/role.conf"
}
