#!/usr/bin/env bats
# dns-posture audit.sh — green/yellow/red checks + exit codes.

load test_helper

@test "audit: syntax check (bash -n)" {
  run bash -n "$AUDIT"
  [ "$status" -eq 0 ]
}

@test "audit: all green after a clean apply" {
  bash "$APPLY" >/dev/null
  run bash "$AUDIT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"unbound active"* ]]
  [[ "$output" == *"single trust anchor"* ]]
  [[ "$output" == *"resolv.conf pinned"* ]]
  [[ "$output" == *"systemd-resolved masked"* ]]
  [[ "$output" == *"forwarders DoT-only"* ]]
  [[ "$output" == *"DNSSEC ad flag"* ]]
  [[ "$output" == *"all green"* ]]
  # No red markers.
  ! [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: RED + exit 1 on a duplicate trust anchor (the regression bug)" {
  bash "$APPLY" >/dev/null
  # Drop a second anchor file beside our snippet to simulate the bug.
  seed_anchor_conf "zz-extra-anchor.conf"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"DUPLICATE anchor"* ]]
  [[ "$output" == *"[FAIL]"* ]]
}

@test "audit: RED + exit 1 when unbound is not active" {
  bash "$APPLY" >/dev/null
  printf 'inactive\n' > "$STUB_STATE/active/unbound"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"unbound is 'inactive'"* ]]
}

@test "audit: RED when resolv.conf is a symlink (not a real file)" {
  bash "$APPLY" >/dev/null
  rm -f "$ONIONARMOR_DNS_RESOLV_CONF"
  ln -s /run/systemd/resolve/stub-resolv.conf "$ONIONARMOR_DNS_RESOLV_CONF"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"is a symlink"* ]]
}

@test "audit: RED when systemd-resolved is still active" {
  bash "$APPLY" >/dev/null
  printf 'enabled\n' > "$STUB_STATE/enabled/systemd-resolved"
  printf 'active\n'  > "$STUB_STATE/active/systemd-resolved"
  run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"still active"* ]]
}

@test "audit: RED on a plaintext :53 forwarder (Do53 leak)" {
  # --no-verify lets the bad config land; audit is what must catch the leak.
  bash "$APPLY" --no-verify --upstreams '8.8.8.8@53#dns.google' >/dev/null
  run bash "$AUDIT" --upstreams '8.8.8.8@53#dns.google'
  [ "$status" -eq 1 ]
  [[ "$output" == *"plaintext :53 forwarder"* ]]
}

@test "audit: RED when DNSSEC ad flag is missing" {
  bash "$APPLY" >/dev/null
  FAKE_DIG_AD=0 run bash "$AUDIT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no ad flag"* ]]
}

@test "audit: read-only — does not modify host state" {
  bash "$APPLY" >/dev/null
  snap_before=$(cat "$ONIONARMOR_DNS_RESOLV_CONF")
  : > "$STUB_STATE/systemctl.log"
  run bash "$AUDIT"
  snap_after=$(cat "$ONIONARMOR_DNS_RESOLV_CONF")
  [ "$snap_before" = "$snap_after" ]
  # Only is-active / is-enabled queries — no state-changing verbs.
  ! grep -qE '^(mask|unmask|disable|enable|start|stop|restart|reload) ' "$STUB_STATE/systemctl.log"
}

@test "audit --no-dnssec: ad-flag check is a warning, not a failure" {
  bash "$APPLY" --no-dnssec >/dev/null
  run bash "$AUDIT" --no-dnssec
  [ "$status" -eq 0 ]
  [[ "$output" == *"DNSSEC disabled"* ]]
}
