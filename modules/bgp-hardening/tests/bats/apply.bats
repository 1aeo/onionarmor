#!/usr/bin/env bats
# bgp-hardening apply.sh — listener bind (default), opt-in firewall/RPKI/GTSM,
# idempotency, and dry-run.

load test_helper

# Current bgpd_options value from the managed daemons file.
daemons_options() {
  sed -n 's/^[[:space:]]*bgpd_options[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$ONIONARMOR_BGP_DAEMONS"
}

@test "apply: syntax check (bash -n)" {
  run bash -n "$APPLY"
  [ "$status" -eq 0 ]
}

@test "test_apply_sets_listener_bind" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [[ "$(daemons_options)" == *"-l 1.2.3.4"* ]]
  # A bgpd_options (-l) change requires a restart, not a reload, to take effect.
  grep -q 'restart frr' "$STUB_STATE/systemctl.log"
  # ss now reports the specific-IP listener.
  "$ONIONARMOR_BGP_SS" -ltnH | grep -q '1.2.3.4:179'
}

@test "test_apply_does_not_install_rpki_by_default" {
  # RPKI is opt-in: a default apply must NOT install/enable the validator.
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -s "$STUB_APT_LOG" ]                               # no apt install
  [ ! -e "$ONIONARMOR_BGP_STATE_DIR/rpki.applied" ]      # no FRR rpki config
  ! grep -q 'enable.*routinator' "$STUB_STATE/systemctl.log"
  ! grep -q 'ONIONARMOR-RPKI-IN' "$STUB_VTYSH_LOG"
}

@test "test_apply_installs_rpki_when_flagged" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-rpki
  [ "$status" -eq 0 ]
  grep -q 'install' "$STUB_APT_LOG"                      # routinator installed
  [ -e "$ONIONARMOR_BGP_STATE_DIR/rpki.applied" ]        # FRR rpki configured
  grep -q 'ONIONARMOR-RPKI-IN' "$STUB_VTYSH_LOG"
}

@test "test_apply_does_not_install_firewall_by_default" {
  # Firewall is opt-in (--enable-firewall): a default apply leaves :179 alone.
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  [ ! -s "$NFT_STORE" ]
}

@test "test_apply_auto_detects_peer_from_neighbor" {
  seed_frr 10.0.0.9 203.0.113.7
  run bash "$APPLY" --enable-firewall
  [ "$status" -eq 0 ]
  # The neighbor IP was auto-detected and placed in the firewall accept set.
  "$ONIONARMOR_BGP_NFT" list table inet onionarmor_bgp | grep -q '203.0.113.7'
  [[ "$output" == *"203.0.113.7"* ]]
}

@test "test_apply_installs_firewall_rule" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-firewall
  [ "$status" -eq 0 ]
  rules="$("$ONIONARMOR_BGP_NFT" list table inet onionarmor_bgp)"
  [[ "$rules" == *"tcp dport 179 ip saddr { 192.0.2.1 } accept"* ]]
  [[ "$rules" == *"tcp dport 179 drop"* ]]
}

@test "apply: --enable-firewall --peer-ip overrides auto-detect (comma + repeat)" {
  seed_frr 1.2.3.4 10.10.10.10
  run bash "$APPLY" --enable-firewall --peer-ip 192.0.2.1,198.51.100.1 --peer-ip 198.51.100.2
  [ "$status" -eq 0 ]
  rules="$("$ONIONARMOR_BGP_NFT" list table inet onionarmor_bgp)"
  [[ "$rules" == *"192.0.2.1"* ]]
  [[ "$rules" == *"198.51.100.1"* ]]
  [[ "$rules" == *"198.51.100.2"* ]]
  # The auto-detected neighbor must NOT appear (explicit override wins).
  ! [[ "$rules" == *"10.10.10.10"* ]]
}

@test "apply --enable-rpki: keeps the full feed — never emits DEFAULT_ONLY_IN" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-rpki
  [ "$status" -eq 0 ]
  ! grep -q 'DEFAULT_ONLY_IN' "$STUB_VTYSH_LOG"
  # RPKI route-map is the deny-invalid/permit-rest kind, applied via vtysh.
  grep -q 'ONIONARMOR-RPKI-IN' "$STUB_VTYSH_LOG"
}

@test "test_apply_idempotent" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-firewall --enable-rpki >/dev/null
  : > "$STUB_STATE/systemctl.log"   # forget the first run's restart/reload
  run bash "$APPLY" --enable-firewall --enable-rpki
  [ "$status" -eq 0 ]
  [[ "$output" == *"already current"* ]]
  [[ "$output" == *"already configured"* || "$output" == *"already running"* ]]
  # Nothing FRR-affecting changed -> no second restart/reload.
  ! grep -qE 'restart frr|reload frr' "$STUB_STATE/systemctl.log"
}

@test "test_apply_dry_run_no_state_change" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-firewall --enable-rpki --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: bgp-hardening"* ]]
  # daemons untouched (no -l), no nft table, FRR not restarted/reloaded.
  ! [[ "$(daemons_options)" == *"-l "* ]]
  [ ! -s "$NFT_STORE" ]
  [ ! -f "$STUB_STATE/systemctl.log" ] || ! grep -qE 'restart frr|reload frr' "$STUB_STATE/systemctl.log"
}

@test "test_rpki_validator_install_idempotent" {
  seed_frr 1.2.3.4 192.0.2.1
  bash "$APPLY" --enable-rpki >/dev/null
  bash "$APPLY" --enable-rpki >/dev/null
  # routinator was apt-installed exactly once (second run saw it active).
  [ "$(grep -c 'install' "$STUB_APT_LOG")" -eq 1 ]
}

@test "test_enable_gtsm_sets_ttl_security" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-gtsm --gtsm-hops 3
  [ "$status" -eq 0 ]
  grep -q 'neighbor 192.0.2.1 ttl-security hops 3' "$STUB_VTYSH_LOG"
  # ttl-security must be applied under `router bgp`, not as a bare neighbor line.
  grep -q 'router bgp' "$STUB_VTYSH_LOG"
}

@test "apply: --enable-gtsm without --gtsm-hops is rejected" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --enable-gtsm
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires --gtsm-hops"* ]]
}

@test "apply: dies when no bind IP can be determined" {
  # frr.conf without a router-id, and no --bind-ip.
  mkdir -p "$(dirname "$ONIONARMOR_BGP_FRR_CONF")"
  printf 'router bgp 65010\n neighbor 192.0.2.1 remote-as 64500\n' > "$ONIONARMOR_BGP_FRR_CONF"
  seed_daemons ""
  run bash "$APPLY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not determine the listener bind IP"* ]]
}

@test "apply: --no-bind-fix --enable-firewall manages only the firewall" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY" --no-bind-fix --enable-firewall
  [ "$status" -eq 0 ]
  # daemons untouched, firewall present, no routinator install.
  ! [[ "$(daemons_options)" == *"-l "* ]]
  [ -s "$NFT_STORE" ]
  [ ! -s "$STUB_APT_LOG" ]
}

@test "apply --enable-rpki: a routinator install failure fails the apply (not fail-open)" {
  # Negative path: if the operator opted into RPKI and the validator can't even
  # be installed, apply must error rather than report success.
  seed_frr 1.2.3.4 192.0.2.1
  FAKE_APT_RC=100 run bash "$APPLY" --enable-rpki
  [ "$status" -ne 0 ]
  [[ "$output" == *"apt-get install routinator failed"* ]]
}

@test "test_README_documents_stub_AS_caveat" {
  # Sanity-check that the doc still carries the stub-AS RPKI caveat.
  grep -q 'When NOT to use RPKI' "$MOD_ROOT/README.md"
  grep -q 'single-homed stub AS' "$MOD_ROOT/README.md"
  grep -q 'no ip forwarding' "$MOD_ROOT/README.md"
  grep -q 'Use `--enable-rpki` only if your topology genuinely benefits' "$MOD_ROOT/README.md"
}

@test "apply: writes audit-log entries" {
  seed_frr 1.2.3.4 192.0.2.1
  run bash "$APPLY"
  [ "$status" -eq 0 ]
  grep -q 'bgp.apply.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'bgp.apply.bind' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'bgp.apply.done' "$ONIONARMOR_AUDIT_LOG"
}
