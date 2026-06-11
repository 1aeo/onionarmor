# shellcheck shell=bash
# SC2034: OA_LATCH_JOBID is set here for consumers that source this file (the
# medium-risk modules), not used within it.
# shellcheck disable=SC2034
#
# lib/safety_latch.sh — a 5-minute `at`-job "dead-man's switch" for risky
# postures that can lock the operator out of the host (SSH ciphers, account
# lockout, tor control-port auth).
#
# THE PATTERN
#   1. The module renders a *restore script* that undoes the change it is about
#      to make (remove our drop-in / restore the prior file, then reload the
#      affected service).
#   2. oa_latch_arm schedules that restore script to run in N minutes via `at`.
#   3. The module applies the change and prints the CANCEL command.
#   4. The operator confirms they still have access, then cancels the latch. If
#      they do NOT cancel within N minutes, atd fires the restore script and the
#      host reverts to its pre-apply state — a bad change can never strand the
#      operator.
#
# This mirrors the auto-revert safety net in systemd-hardening, but for changes
# whose breakage only shows up on the *next* login rather than on service
# restart, so polling is not enough — only a wall-clock timer protects you.
#
# EVERY command + path is env-overridable so the bats suite drives the whole
# mechanism against stub `at`/`atrm` binaries, never scheduling a real job.

# --- overridable external commands ----------------------------------------
: "${ONIONARMOR_AT_CMD:=at}"
: "${ONIONARMOR_ATRM_CMD:=atrm}"

# --- tunables -------------------------------------------------------------
# How long the operator has to confirm + cancel before the auto-revert fires.
: "${ONIONARMOR_LATCH_TIMEOUT_MIN:=5}"
: "${ONIONARMOR_LATCH_STATE_DIR:=/var/lib/onionarmor/latch}"

# Set by oa_latch_arm so the caller can print the job id / cancel command.
OA_LATCH_JOBID=""

# oa_latch_dir <module> -> per-module latch state directory.
oa_latch_dir() {
  printf '%s/%s\n' "$ONIONARMOR_LATCH_STATE_DIR" "$1"
}

# oa_latch_is_armed <module>: true if a latch is currently scheduled.
oa_latch_is_armed() {
  [ -f "$(oa_latch_dir "$1")/jobid" ]
}

# oa_latch_arm <module> <restore-script-path> [timeout-min]
#
# Copy the restore script into the module's latch state dir, schedule it to run
# in <timeout-min> minutes via `at`, and persist the resulting job id. Sets
# OA_LATCH_JOBID on success. Returns non-zero (warning the reason) if scheduling
# fails — the caller MUST treat that as fatal and abort the apply, because a
# risky change with no auto-revert is exactly what the latch exists to prevent.
oa_latch_arm() {
  local module=$1 restore=$2 timeout=${3:-$ONIONARMOR_LATCH_TIMEOUT_MIN}
  [ -n "$module" ] || { warn "oa_latch_arm: module name required"; return 1; }
  [ -f "$restore" ] || { warn "oa_latch_arm: restore script not found: $restore"; return 1; }

  local dir; dir=$(oa_latch_dir "$module")
  mkdir -p "$dir" || { warn "oa_latch_arm: cannot create latch state dir $dir"; return 1; }

  # Canonicalise the restore script inside the state dir so cancel/fire have a
  # stable path even if the caller's temp copy is gone.
  local target="$dir/restore.sh"
  if [ "$restore" != "$target" ]; then
    cp "$restore" "$target" || { warn "oa_latch_arm: cannot stage restore script -> $target"; return 1; }
  fi
  chmod +x "$target" 2>/dev/null || true

  # Schedule. `at` prints "job <N> at <when>" on stderr; capture both streams.
  local out jobid
  if ! out=$(printf '%s\n' "$target" | "$ONIONARMOR_AT_CMD" now + "$timeout" minutes 2>&1); then
    warn "oa_latch_arm: could not schedule the safety latch via '$ONIONARMOR_AT_CMD' (is atd installed and running? 'apt install at && systemctl enable --now atd')"
    return 1
  fi
  jobid=$(printf '%s\n' "$out" | sed -n 's/.*job[[:space:]]\{1,\}\([0-9][0-9]*\).*/\1/p' | head -1)
  if [ -z "$jobid" ]; then
    warn "oa_latch_arm: scheduled the latch but could not parse the job id from: $out"
    # We still wrote a job; record a placeholder so cancel can at least clean up.
    jobid="?"
  fi
  printf '%s\n' "$jobid" > "$dir/jobid" || { warn "oa_latch_arm: cannot persist job id to $dir/jobid"; return 1; }
  printf '%s\n' "$timeout" > "$dir/timeout" 2>/dev/null || true
  OA_LATCH_JOBID=$jobid
  audit_log latch.arm "module=$module jobid=$jobid timeout=${timeout}m restore=$target"
  return 0
}

# oa_latch_cancel <module>: remove the scheduled auto-revert and clear state.
# Returns 0 if a latch was cancelled, 1 if none was armed.
oa_latch_cancel() {
  local module=$1 dir jobid
  dir=$(oa_latch_dir "$module")
  if [ ! -f "$dir/jobid" ]; then
    warn "no armed safety latch for module '$module'"
    return 1
  fi
  jobid=$(cat "$dir/jobid" 2>/dev/null || true)
  if [ -n "$jobid" ] && [ "$jobid" != "?" ]; then
    "$ONIONARMOR_ATRM_CMD" "$jobid" >/dev/null 2>&1 \
      || warn "atrm $jobid returned nonzero (the job may have already fired or been removed)"
  fi
  rm -rf "$dir" || warn "could not remove latch state dir $dir"
  audit_log latch.cancel "module=$module jobid=$jobid"
  info "safety latch cancelled for $module (auto-revert disarmed)"
  return 0
}

# oa_latch_cancel_cmd <module>: the operator-facing command that disarms the
# latch, for printing after an apply.
oa_latch_cancel_cmd() {
  printf 'onionarmor apply --module %s --cancel-safety-latch\n' "$1"
}
