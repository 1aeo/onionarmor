#!/usr/bin/env bats
# `onionarmor version` (and --version / -v / -V) prints a baked-in version,
# read from the committed VERSION file with a git-describe fallback.

load test_helper

@test "version: 'version' subcommand prints onionarmor <version>" {
  run "$ONIONARMOR_BIN" version
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^onionarmor\ .+ ]]
}

@test "version: --version / -v / -V are aliases of 'version'" {
  run "$ONIONARMOR_BIN" version
  [ "$status" -eq 0 ]
  local v="$output"
  run "$ONIONARMOR_BIN" --version
  [ "$status" -eq 0 ]
  [ "$output" = "$v" ]
  run "$ONIONARMOR_BIN" -v
  [ "$status" -eq 0 ]
  [ "$output" = "$v" ]
  run "$ONIONARMOR_BIN" -V
  [ "$status" -eq 0 ]
  [ "$output" = "$v" ]
}

@test "version: reads the baked-in VERSION file" {
  printf '9.9.9-test\n' > "$SANDBOX/VERSION"
  ONIONARMOR_VERSION_FILE="$SANDBOX/VERSION" run "$ONIONARMOR_BIN" version
  [ "$status" -eq 0 ]
  [ "$output" = "onionarmor 9.9.9-test" ]
}

@test "version: falls back to a non-empty string when no VERSION file is present" {
  # No VERSION file -> git describe (in a checkout) or "unknown"; never empty,
  # and never an "unknown command" error.
  ONIONARMOR_VERSION_FILE="$SANDBOX/does-not-exist" run "$ONIONARMOR_BIN" version
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^onionarmor\ .+ ]]
  [ "$output" != "onionarmor " ]
}

@test "version: the repo ships a non-empty VERSION file" {
  [ -r "$ONIONARMOR_ROOT/VERSION" ]
  [ -n "$(tr -d '[:space:]' < "$ONIONARMOR_ROOT/VERSION")" ]
}
