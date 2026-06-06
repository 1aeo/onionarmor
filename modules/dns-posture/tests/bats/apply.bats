#!/usr/bin/env bats
# dns-posture apply.sh — behaviour + the duplicate-anchor regression.

load test_helper

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "apply --dry-run: prints plan + config, changes nothing" {
  run bash "$APPLY" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: dns-posture"* ]]
  [[ "$output" == *"forward-addr: 1.1.1.1@853#cloudflare-dns.com"* ]]
  [[ "$output" == *"nameserver 127.0.0.1"* ]]
  # No snippet, no backup, no resolv rewrite.
  [ ! -e "$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf" ]
  [ ! -e "$ONIONARMOR_DNS_STATE_DIR/resolv.conf.bak" ]
  grep -q 'nameserver 127.0.0.53' "$ONIONARMOR_DNS_RESOLV_CONF"
}

@test "apply: writes snippet, pins resolv.conf, masks resolved, verifies" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  [ -f "$snip" ]
  grep -q 'forward-tls-upstream: yes' "$snip"
  grep -q 'forward-addr: 9.9.9.9@853#dns.quad9.net' "$snip"
  grep -q 'num-threads: 4' "$snip"
  # resolv.conf is now a real file pointing at the local resolver.
  [ -f "$ONIONARMOR_DNS_RESOLV_CONF" ]
  [ ! -L "$ONIONARMOR_DNS_RESOLV_CONF" ]
  grep -q '^nameserver 127.0.0.1$' "$ONIONARMOR_DNS_RESOLV_CONF"
  # Original was backed up.
  [ -f "$ONIONARMOR_DNS_STATE_DIR/resolv.conf.bak" ]
  grep -q 'nameserver 127.0.0.53' "$ONIONARMOR_DNS_STATE_DIR/resolv.conf.bak"
  # systemd-resolved got masked.
  grep -q 'mask systemd-resolved' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/enabled/systemd-resolved")" = "masked" ]
  [[ "$output" == *"applied."* ]]
}

@test "apply: bootstraps the DNSSEC anchor with unbound ownership" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_DNS_ANCHOR_FILE" ]
  [ "$(cat "$ONIONARMOR_DNS_ANCHOR_FILE.fakeowner")" = "unbound:unbound" ]
}

@test "apply: with no stock anchor file, declares exactly one anchor itself" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  [ "$(grep -cE '^[[:space:]]*auto-trust-anchor-file' "$snip")" -eq 1 ]
  n=$(grep -rhE '^[[:space:]]*auto-trust-anchor-file' "$ONIONARMOR_DNS_UNBOUND_CONFD" | wc -l | tr -d ' ')
  [ "$n" -eq 1 ]
}

@test "apply: defers to the stock anchor file (no duplicate declaration)" {
  seed_anchor_conf "root-auto-trust-anchor-file.conf"
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  # Our snippet must NOT add a second anchor line.
  ! grep -qE '^[[:space:]]*auto-trust-anchor-file' "$snip"
  # Total across conf.d stays exactly 1 -> unbound-checkconf passes.
  n=$(grep -rhE '^[[:space:]]*auto-trust-anchor-file' "$ONIONARMOR_DNS_UNBOUND_CONFD" | wc -l | tr -d ' ')
  [ "$n" -eq 1 ]
  run bash "$STUB/unbound-checkconf"
  [ "$status" -eq 0 ]
}

@test "apply: REGRESSION refuses a pre-existing duplicate anchor (no restart)" {
  # Two stock-style anchor files already on the host -> apply must abort
  # before (re)starting unbound rather than ship a crashing config.
  seed_anchor_conf "root-auto-trust-anchor-file.conf"
  seed_anchor_conf "zz-extra-anchor.conf"
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"auto-trust-anchor-file declarations"* ]]
  # unbound must not have been restarted into the broken config.
  ! grep -q 'restart unbound' "$STUB_STATE/systemctl.log"
}

@test "apply: produced config passes unbound-checkconf (default path)" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  run bash "$STUB/unbound-checkconf"
  [ "$status" -eq 0 ]
}

@test "apply: idempotent — second run rewrites nothing" {
  bash "$APPLY" >/dev/null
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  [[ "$output" == *"already pinned"* ]]
  # Backup is taken once, not overwritten.
  [ "$(ls "$ONIONARMOR_DNS_STATE_DIR"/resolv.conf.bak* 2>/dev/null | wc -l | tr -d ' ')" -eq 1 ]
}

@test "apply --no-mask-resolved: leaves systemd-resolved alone" {
  run bash "$APPLY" --no-mask-resolved
  [ "$status" -eq 0 ]
  [ "$(cat "$STUB_STATE/enabled/systemd-resolved")" = "enabled" ]
  ! grep -q 'mask systemd-resolved' "$STUB_STATE/systemctl.log"
}

@test "apply --no-dnssec: disables validator, skips anchor, no anchor line" {
  run bash "$APPLY" --no-dnssec
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  grep -q 'module-config: "iterator"' "$snip"
  ! grep -qE '^[[:space:]]*auto-trust-anchor-file' "$snip"
  [ ! -e "$ONIONARMOR_DNS_ANCHOR_FILE" ]
}

@test "apply --upstreams: custom Cloudflare-only set is rendered" {
  run bash "$APPLY" --upstreams '1.1.1.1@853#cloudflare-dns.com,1.0.0.1@853#cloudflare-dns.com'
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  [ "$(grep -cE '^[[:space:]]*forward-addr:' "$snip")" -eq 2 ]
  grep -q 'forward-addr: 1.1.1.1@853#cloudflare-dns.com' "$snip"
  ! grep -q 'dns.quad9.net' "$snip"
}

@test "apply --listen 0.0.0.0 --num-threads 2: honours overrides" {
  run bash "$APPLY" --listen 0.0.0.0 --num-threads 2
  [ "$status" -eq 0 ]
  snip="$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf"
  grep -q 'interface: 0.0.0.0' "$snip"
  grep -q 'num-threads: 2' "$snip"
  # LAN listener still stubs resolv.conf at loopback.
  grep -q '^nameserver 127.0.0.1$' "$ONIONARMOR_DNS_RESOLV_CONF"
}

@test "apply --immutable-resolv: invokes chattr +i" {
  run bash "$APPLY" --immutable-resolv
  [ "$status" -eq 0 ]
  grep -q '+i' "$STUB/chattr.log"
}

@test "apply: malformed --upstreams entry is rejected" {
  run bash "$APPLY" --upstreams 'just-an-ip'
  [ "$status" -ne 0 ]
  [[ "$output" == *"malformed upstream"* ]]
}

@test "apply --no-bootstrap-anchor: fails clearly when anchor missing" {
  run bash "$APPLY" --no-bootstrap-anchor
  [ "$status" -ne 0 ]
  [[ "$output" == *"anchor"* ]]
  [ ! -e "$ONIONARMOR_DNS_UNBOUND_CONFD/99-onionarmor-dns-posture.conf" ]
}

@test "apply: wrong anchor ownership is rejected" {
  # Pre-create the anchor with no owner sidecar -> stat reports root:root.
  mkdir -p "$(dirname "$ONIONARMOR_DNS_ANCHOR_FILE")"
  printf 'preexisting\n' > "$ONIONARMOR_DNS_ANCHOR_FILE"
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"expected 'unbound:unbound'"* ]]
}

@test "apply: writes audit-log entries" {
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'dns.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'dns.apply.snippet' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'dns.apply.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "apply --verify: fails (exit 2) when DNSSEC ad flag is absent" {
  FAKE_DIG_AD=0 run bash "$APPLY"
  [ "$status" -eq 2 ]
  [[ "$output" == *"ad flag NOT seen"* ]]
}
