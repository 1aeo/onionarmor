#!/usr/bin/env bats
# bin/onionarmor remediate — map an onionauditor scorecard to modules, plan in
# the safe order, and (with --apply) drive each module via a stubbed runner.

setup() {
  ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  export ONIONARMOR_BIN="$ROOT/bin/onionarmor"
  export FIXTURE="$ROOT/tests/fixtures/onionauditor-scorecard.json"

  SB="$(mktemp -d)"; export SB
  export ONIONARMOR_AUDIT_LOG="$SB/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"

  # A sandbox modules dir where every module the fixture maps to is a valid
  # (empty) module, so module_is_valid passes and nothing is skipped for being
  # "not installed" — lets the --apply tests assert pure ordering + safety logic.
  export ONIONARMOR_MODULES_DIR="$SB/modules"
  for m in kernel-hardening firewall-default-deny service-inventory \
           mac-profile-install package-minimization chrony-pinning \
           account-hygiene tor-config-baseline ssh-hardening; do
    mkdir -p "$ONIONARMOR_MODULES_DIR/$m"
    for a in apply audit revert; do
      printf '#!/usr/bin/env bash\n:\n' > "$ONIONARMOR_MODULES_DIR/$m/$a.sh"
    done
  done

  # Runner stub: record the order modules are applied; fail any module named in
  # $FAIL_MODULES (space-separated).
  export RUN_LOG="$SB/run.log"; : > "$RUN_LOG"
  cat > "$SB/runner" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "${RUN_LOG:?}"
case " ${FAIL_MODULES:-} " in *" $1 "*) exit 7 ;; esac
exit 0
EOF
  chmod +x "$SB/runner"
  export ONIONARMOR_REMEDIATE_RUNNER="$SB/runner"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

@test "remediate: requires --from-audit" {
  run bash "$ONIONARMOR_BIN" remediate
  [ "$status" -ne 0 ]
  [[ "$output" == *"--from-audit"* ]]
}

@test "remediate: missing scorecard file errors clearly" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$SB/nope.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found or unreadable"* ]]
}

@test "remediate: dry-run groups findings by module and excludes passes" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE"
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel-hardening"* ]]
  [[ "$output" == *"ssh-hardening"* ]]
  [[ "$output" == *"DRY-RUN"* ]]
  # pass-status findings must NOT appear.
  ! [[ "$output" == *"protocol-2"* ]]
  ! [[ "$output" == *"randomize_va_space"* ]]
}

@test "remediate: header carries host/profile/grade from the scorecard" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE"
  [[ "$output" == *"host=relay01.example.invalid"* ]]
  [[ "$output" == *"grade=F"* ]]
}

@test "remediate: honours a structured remediation.module override" {
  # The time-ntp finding carries remediation.module=chrony-pinning (not the
  # category map) and must be grouped under chrony-pinning.
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE"
  [[ "$output" == *"chrony-pinning"* ]]
}

@test "remediate: kernel-hardening is planned before ssh-hardening; ssh marked LAST" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE"
  kern_line=$(printf '%s\n' "$output" | grep -n 'kernel-hardening' | head -1 | cut -d: -f1)
  ssh_line=$(printf '%s\n' "$output" | grep -n 'ssh-hardening' | head -1 | cut -d: -f1)
  [ "$kern_line" -lt "$ssh_line" ]
  [[ "$output" == *"[APPLIED LAST]"* ]]
}

@test "remediate --apply: runs modules via the runner in the planned order, ssh last" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE" --apply
  [ "$status" -eq 0 ]
  # kernel-hardening is first applied, ssh-hardening is last applied.
  [ "$(head -1 "$RUN_LOG")" = "kernel-hardening" ]
  [ "$(tail -1 "$RUN_LOG")" = "ssh-hardening" ]
  # firewall before service-inventory.
  fw=$(grep -n '^firewall-default-deny$' "$RUN_LOG" | cut -d: -f1)
  si=$(grep -n '^service-inventory$' "$RUN_LOG" | cut -d: -f1)
  [ "$fw" -lt "$si" ]
  [[ "$output" == *"ran="* ]]
}

@test "remediate --apply: a prior module failure SKIPS ssh-hardening (no lockout risk)" {
  FAIL_MODULES="firewall-default-deny" run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE" --apply
  [ "$status" -eq 2 ]
  # ssh-hardening must NOT have been run.
  ! grep -qx 'ssh-hardening' "$RUN_LOG"
  [[ "$output" == *"refusing SSH risk"* ]]
  [[ "$output" == *"failed=1"* ]]
}

@test "remediate --apply: skips modules that are not installed" {
  # Remove ssh-hardening from the sandbox so it is 'not installed'.
  rm -rf "$ONIONARMOR_MODULES_DIR/ssh-hardening"
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE" --apply
  [ "$status" -eq 0 ]
  ! grep -qx 'ssh-hardening' "$RUN_LOG"
  [[ "$output" == *"not installed"* ]]
}

@test "remediate --apply: writes audit-log entries" {
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE" --apply
  [ "$status" -eq 0 ]
  grep -q 'remediate.start' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'remediate.module' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'remediate.done' "$ONIONARMOR_AUDIT_LOG"
}

@test "remediate: no actionable findings -> nothing to remediate" {
  printf '{"host":"h","profile":"p","grade":"A","generated":"t","findings":[{"category":"ssh-hardness","name":"ok","status":"pass","severity":"info","detail":"ok","remediation":"none"}]}\n' > "$SB/clean.json"
  run bash "$ONIONARMOR_BIN" remediate --from-audit "$SB/clean.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing to remediate"* ]]
}

@test "remediate: missing jq is reported clearly" {
  ONIONARMOR_JQ_CMD="definitely-not-jq-xyz" run bash "$ONIONARMOR_BIN" remediate --from-audit "$FIXTURE"
  [ "$status" -ne 0 ]
  [[ "$output" == *"install jq"* ]]
}
