#!/usr/bin/env bats

load test_helper

@test "list: requires --role" {
  run "$ONIONARMOR_BIN" list
  [ "$status" -ne 0 ]
  [[ "$output" == *"--role"* ]]
}

@test "list: rejects unknown role" {
  run "$ONIONARMOR_BIN" list --role does-not-exist
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "list: tor-relay yields 25 sysctl entries" {
  run "$ONIONARMOR_BIN" list --role tor-relay
  [ "$status" -eq 0 ]
  [[ "$output" == *"25 sysctl entries"* ]]
  [[ "$output" == *"kernel.kptr_restrict"* ]]
  [[ "$output" == *"net.ipv6.conf.all.accept_redirects"* ]]
}

@test "list: eval-host keeps kexec_load_disabled=0 (role exception)" {
  run "$ONIONARMOR_BIN" list --role eval-host
  [ "$status" -eq 0 ]
  [[ "$output" =~ kernel\.kexec_load_disabled[[:space:]]+0 ]]
}

@test "list: receiver locks kexec_load_disabled=1" {
  run "$ONIONARMOR_BIN" list --role receiver
  [ "$status" -eq 0 ]
  [[ "$output" =~ kernel\.kexec_load_disabled[[:space:]]+1 ]]
}

@test "list: does not write to /etc" {
  before=$(find "$ONIONARMOR_SYSCTL_DIR" -type f 2>/dev/null | wc -l)
  "$ONIONARMOR_BIN" list --role tor-relay >/dev/null
  after=$(find "$ONIONARMOR_SYSCTL_DIR" -type f 2>/dev/null | wc -l)
  [ "$before" = "$after" ]
}
