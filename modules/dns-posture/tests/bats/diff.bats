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

@test "diff: a symlinked snippet whose target matches reads (no change)" {
  # apply writes the snippet via oa_write_if_changed, which follows symlinks and
  # compares target bytes — so a symlinked snippet pointing at identical content
  # is NOT a change, unlike resolv.conf (which apply replaces outright).
  local snippet; snippet="$(cd "$MOD_ROOT" && . ./lib.sh && dns_snippet_path)"
  # Render with the same default flags diff uses (dns_parse_flags sets them),
  # so the symlink target is byte-identical to diff's would-be snippet.
  ( cd "$MOD_ROOT" && . ./lib.sh && dns_parse_flags && dns_render_snippet > "$SB/snippet-target" )
  ln -s "$SB/snippet-target" "$snippet"
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"unbound snippet"*"(no change)"* ]]
  [ -L "$snippet" ]   # untouched
}

@test "diff: a symlinked resolv.conf is always a replace (never spurious no-change)" {
  # Point resolv.conf at the systemd stub via a symlink whose target content
  # happens to equal the render — apply still replaces the link, so the preview
  # must say so rather than reading (no change).
  ( cd "$MOD_ROOT" && . ./lib.sh
    dns_render_resolv_conf > "$SB/stub-resolv.conf" )
  rm -f "$ONIONARMOR_DNS_RESOLV_CONF"
  ln -s "$SB/stub-resolv.conf" "$ONIONARMOR_DNS_RESOLV_CONF"
  run DIFF
  [ "$status" -eq 0 ]
  [[ "$output" == *"resolv.conf"*"would replace symlink"* ]]
  # Still a read-only preview: the symlink is untouched.
  [ -L "$ONIONARMOR_DNS_RESOLV_CONF" ]
}
