#!/usr/bin/env bats

load test_helper

@test "diff: surfaces the 10-below-recommended drifts of a fresh Debian-13 baseline" {
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [ "$status" -eq 0 ]
  # The 10 sysctls a fresh Debian-13 install lacks vs the tor-relay role
  echo "$output" | grep -q "kernel.kptr_restrict.*1 *2 *DRIFT"
  echo "$output" | grep -q "kernel.kexec_load_disabled.*0 *1 *DRIFT"
  echo "$output" | grep -q "fs.protected_fifos.*1 *2 *DRIFT"
  echo "$output" | grep -q "net.ipv4.conf.all.accept_redirects.*1 *0 *DRIFT"
  echo "$output" | grep -q "net.ipv4.conf.default.accept_redirects.*1 *0 *DRIFT"
  echo "$output" | grep -q "net.ipv4.conf.all.send_redirects.*1 *0 *DRIFT"
  echo "$output" | grep -q "net.ipv4.conf.default.send_redirects.*1 *0 *DRIFT"
  echo "$output" | grep -q "net.ipv4.conf.all.log_martians.*0 *1 *DRIFT"
  echo "$output" | grep -q "net.ipv6.conf.all.accept_redirects.*1 *0 *DRIFT"
  echo "$output" | grep -q "net.ipv6.conf.default.accept_redirects.*1 *0 *DRIFT"
  [[ "$output" == *"10/25 sysctls drift"* ]]
}

@test "diff: shows ok for already-hardened sysctls" {
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [ "$status" -eq 0 ]
  # Already-hardened — not in the 10 drift set.
  echo "$output" | grep -q "kernel.dmesg_restrict.*1 *1 *ok"
  echo "$output" | grep -q "kernel.randomize_va_space.*2 *2 *ok"
  echo "$output" | grep -q "fs.protected_hardlinks.*1 *1 *ok"
  echo "$output" | grep -q "net.ipv4.tcp_syncookies.*1 *1 *ok"
}

@test "diff: does not write to /etc" {
  before=$(find "$ONIONARMOR_SYSCTL_DIR" -type f 2>/dev/null | wc -l)
  "$ONIONARMOR_BIN" diff --role tor-relay >/dev/null
  after=$(find "$ONIONARMOR_SYSCTL_DIR" -type f 2>/dev/null | wc -l)
  [ "$before" = "$after" ]
}

@test "diff: marks missing keys" {
  # Remove a key from baseline state to simulate a kernel without that knob.
  grep -v 'kernel.kptr_restrict' "$FAKE_SYSCTL_STATE" > "$SANDBOX/tmp.state"
  mv "$SANDBOX/tmp.state" "$FAKE_SYSCTL_STATE"
  run "$ONIONARMOR_BIN" diff --role tor-relay
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "kernel.kptr_restrict.* ? .* missing"
}
