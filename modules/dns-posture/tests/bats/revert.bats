#!/usr/bin/env bats
# dns-posture revert.sh — restore prior state + verify resolution.

load test_helper

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "revert: restores resolv.conf, removes snippet, unmasks resolved" {
  bash "$APPLY" >/dev/null
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  [ -f "$snip" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # Original resolv.conf content is back.
  grep -q 'nameserver 127.0.0.53' "$ONIONARMOR_DNS_RESOLV_CONF"
  ! grep -q 'Managed by onionarmor' "$ONIONARMOR_DNS_RESOLV_CONF"
  # Snippet gone, unbound left installed (we don't assert removal of unbound).
  [ ! -e "$snip" ]
  # systemd-resolved unmasked + started.
  grep -q 'unmask systemd-resolved' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/systemd-resolved")" = "enabled" ]
  [ "$(cat "$STUB_STATE/active/systemd-resolved")" = "active" ]
  [[ "$output" == *"reverted."* ]]
}

@test "revert: round-trips with apply (apply -> revert -> original restored)" {
  original=$(cat "$ONIONARMOR_DNS_RESOLV_CONF")
  bash "$APPLY" >/dev/null
  [ "$(cat "$ONIONARMOR_DNS_RESOLV_CONF")" != "$original" ]
  bash "$REVERT" >/dev/null
  [ "$(cat "$ONIONARMOR_DNS_RESOLV_CONF")" = "$original" ]
}

@test "revert: clears the immutable bit before restoring" {
  bash "$APPLY" --immutable-resolv >/dev/null
  : > "$STUB/chattr.log"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q '\-i' "$STUB/chattr.log"
}

@test "revert: fails loudly when name resolution is still broken" {
  bash "$APPLY" >/dev/null
  FAKE_GETENT_RC=2 run bash "$REVERT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"name resolution failed"* ]]
}

@test "revert: writes audit-log entries" {
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'dns.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'dns.revert.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "revert: warns but succeeds when no backup exists" {
  # Remove our snippet path expectation: apply first to create state, then
  # delete the backup to simulate a partial/foreign prior state.
  bash "$APPLY" >/dev/null
  rm -f "$ONIONARMOR_DNS_STATE_DIR/resolv.conf.bak"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no resolv.conf backup"* ]]
}

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Establish an applied posture so a real revert would have work to do.
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
