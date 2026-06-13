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

@test "revert: keeps the firewall.peers marker when the nft delete fails" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-firewall >/dev/null
  marker="$ONIONARMOR_BGP_STATE_DIR/firewall.peers"
  [ -f "$marker" ]
  FAKE_NFT_DELETE_RC=1 run bash "$REVERT"
  [ "$status" -eq 0 ]
  # Delete failed -> ownership marker retained so a re-run retries.
  [ -f "$marker" ]
  [[ "$output" == *"keeping firewall.peers marker"* ]]
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
  # A no-op revert must not touch the live routing stack (no restart/reload).
  [ ! -f "$STUB_STATE/systemctl.log" ] || ! grep -qE 'reload frr|restart frr' "$STUB_STATE/systemctl.log"
  [[ "$output" == *"no changes made"* ]]
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

@test "revert --dry-run: previews the plan and changes nothing on disk" {
  # Seed a real FRR config + apply with the firewall so the revert plan is
  # non-empty (daemons backup, firewall.peers marker, rpki/route-map markers
  # all present) — i.e. a state where a live revert WOULD mutate.
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-firewall
  [ "$status" -eq 0 ]
  # Sanity: the apply actually established owned state for revert to act on.
  [ -f "$ONIONARMOR_BGP_STATE_DIR/firewall.peers" ]
  _oa_snap() { ( cd "$SB" && find . -type f -exec cksum {} + 2>/dev/null | sort ); }
  before="$(_oa_snap)"
  run bash "$REVERT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *"would:"* ]]
  # The non-empty plan must mention concrete owned actions, not a no-op.
  [[ "$output" == *"delete nft table"* ]]
  after="$(_oa_snap)"
  [ "$before" = "$after" ]
}
