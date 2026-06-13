#!/usr/bin/env bats
# `onionarmor diff --module <name>` routing in bin/onionarmor. Exercises the CLI
# dispatch (not the module internals — those have their own diff.bats suites).
# Read-only by construction; these never write to the host.

setup() {
  ONIONARMOR_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  export ONIONARMOR_ROOT
  BIN="$ONIONARMOR_ROOT/bin/onionarmor"
  export BIN
}

@test "diff --module kernel-hardening: routes to the module preview" {
  run "$BIN" diff --module kernel-hardening
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel-hardening diff"* ]]
  [[ "$output" == *"WOULD-BE"* ]]
  [[ "$output" == *"Preview only"* ]]
}

@test "diff --module=kernel-hardening (=form): routes to the module preview" {
  run "$BIN" diff --module=kernel-hardening
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel-hardening diff"* ]]
}

@test "diff --module kernel-reserved-ports: routes and passes flags through" {
  run "$BIN" diff --module kernel-reserved-ports --reserved-range 9050-9090
  [ "$status" -eq 0 ]
  [[ "$output" == *"net.ipv4.ip_local_reserved_ports"* ]]
  [[ "$output" == *"9050-9090"* ]]
}

@test "diff --module ssh-hardening: runtime-derived module reports no preview" {
  run "$BIN" diff --module ssh-hardening
  [ "$status" -eq 0 ]
  [[ "$output" == *"runtime branches; preview not available"* ]]
}

@test "diff --module: unknown module is rejected" {
  run "$BIN" diff --module no-such-module
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown module"* ]]
}

@test "help: documents the diff --module subcommand" {
  run "$BIN" help
  [ "$status" -eq 0 ]
  [[ "$output" == *"diff"*"--module <name>"* ]]
}
