#!/usr/bin/env bats
# Unit tests for lib/safety_latch.sh — the shared 5-minute `at`-job dead-man's
# switch used by the medium-risk modules (ssh-hardening, account-hygiene,
# tor-config-baseline). Stubs `at`/`atrm` so nothing is ever really scheduled.

setup() {
  ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  export ONIONARMOR_PREFIX="$ROOT"
  SB="$(mktemp -d)"; export SB
  STUB="$SB/stubs"; mkdir -p "$STUB"

  export ONIONARMOR_AUDIT_LOG="$SB/audit.log"
  export ONIONARMOR_OPERATOR="bats-test"
  export ONIONARMOR_LATCH_STATE_DIR="$SB/var/lib/onionarmor/latch"
  export ONIONARMOR_LATCH_TIMEOUT_MIN=5
  export AT_QUEUE="$SB/at-queue"; : > "$AT_QUEUE"
  export AT_COUNTER="$SB/at-counter"; printf '0\n' > "$AT_COUNTER"
  export AT_LAST_STDIN="$SB/at-stdin"

  # at: enqueue a job id, save the piped command, print "job N at ..." to stderr.
  cat > "$STUB/at" <<'EOF'
#!/bin/sh
cat > "${AT_LAST_STDIN:?}"
n=$(cat "${AT_COUNTER:?}" 2>/dev/null || echo 0); n=$((n + 1))
printf '%s\n' "$n" > "$AT_COUNTER"
printf '%s\n' "$n" >> "${AT_QUEUE:?}"
echo "job $n at Mon Jun  8 03:00:00 2026" >&2
exit 0
EOF
  cat > "$STUB/atrm" <<'EOF'
#!/bin/sh
q="${AT_QUEUE:?}"; tmp="$q.tmp"
grep -vx "$1" "$q" > "$tmp" 2>/dev/null || :
mv "$tmp" "$q"
exit 0
EOF
  chmod +x "$STUB"/*
  export ONIONARMOR_AT_CMD="$STUB/at"
  export ONIONARMOR_ATRM_CMD="$STUB/atrm"

  # Source the libs under test.
  # shellcheck source=../lib/common.sh
  . "$ROOT/lib/common.sh"
  # shellcheck source=../lib/safety_latch.sh
  . "$ROOT/lib/safety_latch.sh"
}

teardown() {
  if [ -n "${SB:-}" ] && [ -d "$SB" ]; then rm -rf "$SB"; fi
}

@test "latch: arm schedules an at-job and records the job id" {
  printf '#!/bin/sh\necho restored\n' > "$SB/restore.sh"
  run oa_latch_arm demo "$SB/restore.sh"
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_LATCH_STATE_DIR/demo/jobid" ]
  [ "$(cat "$ONIONARMOR_LATCH_STATE_DIR/demo/jobid")" = "1" ]
  # The restore script was staged into the state dir.
  [ -x "$ONIONARMOR_LATCH_STATE_DIR/demo/restore.sh" ]
  # The at job was handed the staged restore script path on stdin.
  grep -q "demo/restore.sh" "$AT_LAST_STDIN"
}

@test "latch: is-armed reflects arm then cancel" {
  printf '#!/bin/sh\n:\n' > "$SB/restore.sh"
  oa_latch_arm demo "$SB/restore.sh"
  run oa_latch_is_armed demo; [ "$status" -eq 0 ]
  run oa_latch_cancel demo; [ "$status" -eq 0 ]
  run oa_latch_is_armed demo; [ "$status" -ne 0 ]
  # state dir removed and at job dequeued
  [ ! -d "$ONIONARMOR_LATCH_STATE_DIR/demo" ]
  ! grep -qx 1 "$AT_QUEUE"
}

@test "latch: cancel with no armed latch warns and returns nonzero" {
  run oa_latch_cancel demo
  [ "$status" -ne 0 ]
  [[ "$output" == *"no armed safety latch"* ]]
}

@test "latch: arm honours a custom timeout argument" {
  printf '#!/bin/sh\n:\n' > "$SB/restore.sh"
  run oa_latch_arm demo "$SB/restore.sh" 10
  [ "$status" -eq 0 ]
  [ "$(cat "$ONIONARMOR_LATCH_STATE_DIR/demo/timeout")" = "10" ]
}

@test "latch: arm fails (nonzero) when the restore script is missing" {
  run oa_latch_arm demo "$SB/nope.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"restore script not found"* ]]
}

@test "latch: arm fails when at scheduling fails (atd down)" {
  # A real restore file so the not-found check passes first, then `at` (here a
  # command that always fails) cannot schedule it.
  printf '#!/bin/sh\n:\n' > "$SB/restore.sh"
  ONIONARMOR_AT_CMD="false" run oa_latch_arm demo "$SB/restore.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not schedule the safety latch"* ]]
}

@test "latch: arm + cancel write audit-log lines" {
  printf '#!/bin/sh\n:\n' > "$SB/restore.sh"
  oa_latch_arm demo "$SB/restore.sh"
  oa_latch_cancel demo
  grep -q 'latch.arm' "$ONIONARMOR_AUDIT_LOG"
  grep -q 'latch.cancel' "$ONIONARMOR_AUDIT_LOG"
}
