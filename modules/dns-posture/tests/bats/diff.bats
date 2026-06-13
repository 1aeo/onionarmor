#!/usr/bin/env bats
# dns-posture diff.sh — read-only preview. Renders the would-be unbound snippet
# and resolv.conf, compares each to what is on disk, and writes nothing.

load test_helper

DIFF() { bash "$MOD_ROOT/diff.sh" "$@"; }

@test "diff: syntax check (bash -n)" {
  run bash -n "$MOD_ROOT/diff.sh"
  [ "$status" -eq 0 ]
}

@test "diff: snippet absent → would create; resolv differs → would rewrite; no writes" {
  # Sandbox starts with an empty conf.d and a systemd-resolved resolv.conf.
  local snippet; snippet="$(cd "$MOD_ROOT" && . ./lib.sh && dns_snippet_path)"
  local before; before="$(cat "$ONIONARMOR_DNS_RESOLV_CONF")"

  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"unbound snippet"*"would create"* ]]
  [[ "$output" == *"resolv.conf"*"would rewrite"* ]]

  # Nothing written: snippet still absent, resolv.conf byte-for-byte unchanged.
  [ ! -e "$snippet" ]
  [ "$(cat "$ONIONARMOR_DNS_RESOLV_CONF")" = "$before" ]
}

@test "diff: when on-disk files already match the render → (no change)" {
  # Materialise exactly what apply would write, then diff must see no drift.
  ( cd "$MOD_ROOT" && . ./lib.sh
    dns_render_snippet > "$(dns_snippet_path)"
    dns_render_resolv_conf > "$ONIONARMOR_DNS_RESOLV_CONF" )
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"unbound snippet"*"(no change)"* ]]
  [[ "$output" == *"resolv.conf"*"(no change)"* ]]
}
