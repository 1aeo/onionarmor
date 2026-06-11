#!/usr/bin/env bats
# remediate --from-audit — map an onionauditor scan to modules + apply ordering.

load test_helper

FIXTURE() { printf '%s/tests/fixtures/auditor-scan-sample.json' "$ONIONARMOR_ROOT"; }

@test "remediate: --from-audit is required" {
  run "$ONIONARMOR_BIN" remediate
  [ "$status" -ne 0 ]
  [[ "$output" == *"--from-audit"* ]]
}

@test "remediate: rejects invalid JSON" {
  bad="$SANDBOX/bad.json"; printf 'not json' > "$bad"
  run "$ONIONARMOR_BIN" remediate --from-audit "$bad"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not valid JSON"* ]]
}

@test "remediate: dry-run prints a plan mapping categories to modules" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel-hardening"* ]]
  [[ "$output" == *"account-hygiene"* ]]
  [[ "$output" == *"firewall-default-deny"* ]]
  [[ "$output" == *"ssh-hardening"* ]]
  [[ "$output" == *"tor-config-baseline"* ]]
  [[ "$output" == *"package-minimization"* ]]
  [[ "$output" == *"DRY RUN"* ]]
}

@test "remediate: dry-run is the default (no host changes implied)" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"DRY RUN"* ]]
}

@test "remediate: cites the onionauditor finding ids per module" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ssh-hardness:permit-root-login"* ]]
  [[ "$output" == *"firewall:default-deny"* ]]
  [[ "$output" == *"accounts:cloudinit-sudo"* ]]
}

@test "remediate: ssh-hardening is flagged to apply LAST" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"applied LAST"* ]]
}

@test "remediate: pass/skip findings are ignored" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  # The passing ssh ciphers finding and the skipped tor-data-dirs finding must
  # not be cited as something to remediate.
  ! [[ "$output" == *"ssh-hardness:ciphers"* ]]
  ! [[ "$output" == *"tor-data-dirs:perms"* ]]
}

@test "remediate: categories with no module are reported as unmapped" {
  run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"unmapped categories"* ]]
  [[ "$output" == *"service-inventory"* ]]
}

@test "remediate: reads the scan from stdin with -" {
  run bash -c "'$ONIONARMOR_BIN' remediate --from-audit - < '$(FIXTURE)'"
  [ "$status" -eq 0 ]
  [[ "$output" == *"PLAN"* ]]
}

@test "remediate: --apply runs modules in dependency order (kernel first, ssh last)" {
  order="$SANDBOX/order.log"; : > "$order"
  ONIONARMOR_REMEDIATE_NOOP=yes ONIONARMOR_REMEDIATE_ORDER_LOG="$order" \
    run "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)" --apply
  [ "$status" -eq 0 ]
  # First applied module is kernel-hardening; last is ssh-hardening.
  [ "$(head -1 "$order")" = "kernel-hardening" ]
  [ "$(tail -1 "$order")" = "ssh-hardening" ]
  # firewall-default-deny is applied before ssh-hardening.
  fw=$(grep -n '^firewall-default-deny$' "$order" | cut -d: -f1)
  ssh=$(grep -n '^ssh-hardening$' "$order" | cut -d: -f1)
  [ "$fw" -lt "$ssh" ]
}

@test "remediate: --apply records audit-log entries" {
  order="$SANDBOX/order.log"; : > "$order"
  ONIONARMOR_REMEDIATE_NOOP=yes ONIONARMOR_REMEDIATE_ORDER_LOG="$order" \
    "$ONIONARMOR_BIN" remediate --from-audit "$(FIXTURE)" --apply >/dev/null
  grep -q 'remediate.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'remediate.apply' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'remediate.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "remediate: no findings -> nothing to remediate" {
  empty="$SANDBOX/empty.json"
  printf '{"host":"h","profile":"relay-mid","grade":"A","aggregate":99,"findings":[]}' > "$empty"
  run "$ONIONARMOR_BIN" remediate --from-audit "$empty"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remediate"* ]]
}
