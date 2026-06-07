#!/usr/bin/env bats
# bin/check-own-roa-status — the operator-level "are MY ROAs valid?" helper.
# Offline: the RPKI lookup is stubbed via ONIONARMOR_ROA_FETCH_CMD.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../../../.." && pwd)"
  HELPER="$REPO_ROOT/bin/check-own-roa-status"
  export HELPER
  SB="$(mktemp -d)"; export SB
  # Stub validator: every prefix VALID unless its name is in $SB/invalid.
  cat > "$SB/fetch" <<'EOF'
#!/bin/sh
# args: <asn> <prefix> -> prints valid|invalid|unknown
if [ -f "$SB/invalid" ] && grep -qF "$2" "$SB/invalid"; then echo invalid; else echo valid; fi
EOF
  chmod +x "$SB/fetch"
  export ONIONARMOR_ROA_FETCH_CMD="$SB/fetch"
}

teardown() { [ -n "${SB:-}" ] && rm -rf "$SB"; }

@test "check-own-roa-status: syntax check (bash -n)" {
  run bash -n "$HELPER"
  [ "$status" -eq 0 ]
}

@test "check-own-roa-status: --help exits 0" {
  run bash "$HELPER" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"RPKI validity of YOUR announced prefixes"* ]]
}

@test "check-own-roa-status: default fleet set is all VALID -> exit 0" {
  run bash "$HELPER"
  [ "$status" -eq 0 ]
  # All four 1aeo /24s checked and VALID.
  [[ "$output" == *"192.0.2.0/24"* ]]
  [[ "$output" == *"192.0.2.0/24"* ]]
  [[ "$output" == *"192.0.2.0/24"* ]]
  [[ "$output" == *"192.0.2.0/24"* ]]
  [[ "$output" == *"all 4 announced prefix(es) are RPKI-VALID"* ]]
}

@test "check-own-roa-status: an INVALID prefix -> exit 1" {
  printf '192.0.2.0/24\n' > "$SB/invalid"
  run bash "$HELPER"
  [ "$status" -eq 1 ]
  [[ "$output" == *"192.0.2.0/24"*"INVALID"* ]]
  [[ "$output" == *"RPKI-INVALID"* ]]
}

@test "check-own-roa-status: custom --asn/--prefix is honoured" {
  run bash "$HELPER" --asn 64500 --prefix 203.0.113.0/24
  [ "$status" -eq 0 ]
  [[ "$output" == *"AS64500"* ]]
  [[ "$output" == *"203.0.113.0/24"* ]]
  ! [[ "$output" == *"192.0.2.0/24"* ]]
}
