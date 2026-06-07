#!/usr/bin/env bats
# bgp-hardening revert.sh — restore daemons, drop firewall, disable validator.

load test_helper

daemons_options() {
  sed -n 's/^[[:space:]]*bgpd_options[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$ONIONARMOR_BGP_DAEMONS"
}

@test "revert: syntax check (bash -n)" {
  run bash -n "$REVERT"
  [ "$status" -eq 0 ]
}

@test "test_revert_restores_daemons_file" {
  seed_frr 1.2.3.4 192.0.2.1
  before="$(daemons_options)"           # original, no -l
  bash "$APPLY" >/dev/null
  [[ "$(daemons_options)" == *"-l 1.2.3.4"* ]]   # apply added the bind
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # daemons restored to its pre-apply content.
  [ "$(daemons_options)" = "$before" ]
  ! [[ "$(daemons_options)" == *"-l "* ]]
}

@test "revert: removes the managed nft table" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-firewall >/dev/null
  [ -s "$NFT_STORE" ]
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  # table gone -> list exits non-zero / empty.
  ! "$ONIONARMOR_BGP_NFT" list table inet onionarmor_bgp >/dev/null 2>&1
}

@test "revert: disables routinator but leaves it installed" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-rpki >/dev/null
  [ -x "$ONIONARMOR_BGP_ROUTINATOR" ]               # installed by apply --enable-rpki
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'disable routinator now=1' "$STUB_STATE/systemctl.log"
  [ "$(cat "$STUB_STATE/active/routinator")" = "inactive" ]
  # Still installed (not purged).
  [ -x "$ONIONARMOR_BGP_ROUTINATOR" ]
}

@test "revert: does not touch routinator when RPKI was never enabled" {
  # Default apply never enabled the validator -> revert must not disable it.
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  ! grep -q 'disable routinator' "$STUB_STATE/systemctl.log"
}

@test "revert: removes the FRR rpki route-map + marker" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-rpki >/dev/null
  [ -e "$ONIONARMOR_BGP_STATE_DIR/rpki.applied" ]
  : > "$STUB_VTYSH_LOG"
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'no route-map ONIONARMOR-RPKI-IN' "$STUB_VTYSH_LOG"
  [ ! -e "$ONIONARMOR_BGP_STATE_DIR/rpki.applied" ]
}

@test "revert: no backup present is a clean no-op warning" {
  seed_frr 1.2.3.4 192.0.2.1   # apply never ran -> no backup
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no daemons backup"* ]]
}

@test "revert: writes audit-log entries" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" >/dev/null
  run bash "$REVERT"
  [ "$status" -eq 0 ]
  grep -q 'bgp.revert.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'bgp.revert.daemons' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'bgp.revert.done' "$ONIONARMOR_AUDIT_LOG"
}
