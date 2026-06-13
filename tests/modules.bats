#!/usr/bin/env bats
# Module dispatch in bin/onionarmor: list-modules + apply/audit/revert --module
# routing and the error paths. Exercises the CLI itself (not the module
# internals — those have their own suites under modules/<name>/tests/bats/).

setup() {
  ONIONARMOR_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  export ONIONARMOR_ROOT
  BIN="$ONIONARMOR_ROOT/bin/onionarmor"
  export BIN
}

@test "list-modules: discovers dns-posture with its description" {
  run "$BIN" list-modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"dns-posture"* ]]
  [[ "$output" == *"DoT resolver"* ]]
}

@test "list-modules: discovers kernel-reserved-ports with its description" {
  run "$BIN" list-modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel-reserved-ports"* ]]
  [[ "$output" == *"ephemeral source-port pool"* ]]
}

@test "apply --module kernel-reserved-ports --dry-run: routes to the module" {
  run "$BIN" apply --module kernel-reserved-ports --reserved-range 9050-9090 --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: kernel-reserved-ports"* ]]
  [[ "$output" == *"net.ipv4.ip_local_reserved_ports = 9050-9090"* ]]
}

@test "list-modules: discovers bgp-hardening with its description" {
  run "$BIN" list-modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"bgp-hardening"* ]]
  [[ "$output" == *"bgpd listener"* ]]
}

@test "apply --module bgp-hardening --dry-run: routes to the module" {
  # Host-independent: explicit peer + opt-in firewall, no bind-fix so /etc/frr
  # is never read; dry-run mutates nothing.
  run "$BIN" apply --module bgp-hardening --dry-run --no-bind-fix --enable-firewall --peer-ip 192.0.2.1
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: bgp-hardening"* ]]
  [[ "$output" == *"192.0.2.1"* ]]
}

@test "help: documents the module subcommands" {
  run "$BIN" help
  [ "$status" -eq 0 ]
  [[ "$output" == *"list-modules"* ]]
  [[ "$output" == *"--module <name>"* ]]
}

@test "apply --module dns-posture --dry-run: routes to the module" {
  run "$BIN" apply --module dns-posture --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: dns-posture"* ]]
  [[ "$output" == *"forward-addr: 1.1.1.1@853#cloudflare-dns.com"* ]]
}

@test "apply --module=dns-posture (=form) --dry-run: routes to the module" {
  run "$BIN" apply --module=dns-posture --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: dns-posture"* ]]
}

@test "apply --module <name>: passes module flags through" {
  run "$BIN" apply --module dns-posture --dry-run --upstreams '1.1.1.1@853#cloudflare-dns.com'
  [ "$status" -eq 0 ]
  [[ "$output" == *"forward-addr: 1.1.1.1@853#cloudflare-dns.com"* ]]
  ! [[ "$output" == *"dns.quad9.net"* ]]
}

@test "apply --module: unknown module is rejected" {
  run "$BIN" apply --module no-such-module
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown module"* ]]
}

@test "audit --module: unknown module is rejected" {
  run "$BIN" audit --module no-such-module
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown module"* ]]
}

@test "revert without --module: errors and points at rollback" {
  run "$BIN" revert
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires --module"* ]]
  [[ "$output" == *"rollback --role"* ]]
}

@test "module name with a slash is rejected (no path traversal)" {
  run "$BIN" apply --module ../evil
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid module name"* ]]
}

@test "bare audit (no --module) still prints the audit log, not a module" {
  run "$BIN" audit
  [ "$status" -eq 0 ]
  # The audit-log dump path prints a TIMESTAMP header or the empty-log notice,
  # never the module's green/yellow/red output.
  ! [[ "$output" == *"dns-posture audit"* ]]
}

# ---------------------------------------------------------------------------
# `revert --module <X> --dry-run` dispatch — the operator-facing preview path
# that mirrors `apply --module <X> --dry-run` above. (The module scripts have
# their own per-module dry-run suites; these assert the bin/onionarmor dispatch
# wiring and the apply/revert dry-run *symmetry* end-to-end.)
# ---------------------------------------------------------------------------
@test "revert --module kernel-hardening --dry-run: routes to the module and previews" {
  run "$BIN" revert --module kernel-hardening --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: kernel-hardening"* ]]
  [[ "$output" == *"would:"* ]]
}

@test "revert --module=dns-posture (=form) --dry-run: routes to the module" {
  run "$BIN" revert --module=dns-posture --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: dns-posture"* ]]
  [[ "$output" == *"would:"* ]]
}

@test "apply & revert --module --dry-run dispatch write nothing to disk" {
  d="$(mktemp -d)"
  ONIONARMOR_SYSCTL_DIR="$d/sysctl.d" ONIONARMOR_KH_STATE_DIR="$d/state" \
  ONIONARMOR_AUDIT_LOG="$d/audit.log" ONIONARMOR_SYSCTL_CMD=true \
    run "$BIN" apply --module kernel-hardening --dry-run
  [ "$status" -eq 0 ]
  ONIONARMOR_SYSCTL_DIR="$d/sysctl.d" ONIONARMOR_KH_STATE_DIR="$d/state" \
  ONIONARMOR_AUDIT_LOG="$d/audit.log" ONIONARMOR_SYSCTL_CMD=true \
    run "$BIN" revert --module kernel-hardening --dry-run
  [ "$status" -eq 0 ]
  # Neither dry-run created the managed sysctl dir / drop-in, the module state
  # dir (where a backup drop-in would land), or an audit log.
  [ ! -e "$d/sysctl.d" ]
  [ ! -e "$d/state" ]
  [ ! -e "$d/audit.log" ]
  rm -rf "$d"
}
