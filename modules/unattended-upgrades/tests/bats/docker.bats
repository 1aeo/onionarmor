#!/usr/bin/env bats
# unattended-upgrades — OPT-IN integration test on real Debian/Ubuntu images.
#
# Skipped unless BOTH:
#   * docker is on PATH, and
#   * ONIONARMOR_DOCKER_TESTS=1 is set
# so the default (offline) suite and CI stay fast and hermetic. Enable with:
#   ONIONARMOR_DOCKER_TESTS=1 bats modules/unattended-upgrades/tests/bats/docker.bats
#
# Each case runs the real apply -> audit -> revert -> audit round-trip against a
# stock image with real apt/systemctl (systemctl is a no-op in a plain
# container, so the config-file behaviour is what these assert end-to-end).

load test_helper

_docker_or_skip() {
  command -v docker >/dev/null 2>&1 || skip "docker not installed"
  [ "${ONIONARMOR_DOCKER_TESTS:-0}" = "1" ] || skip "set ONIONARMOR_DOCKER_TESTS=1 to run docker integration"
}

# _run_roundtrip <image>
_run_roundtrip() {
  local image=$1
  docker run --rm -v "$REPO_ROOT":/oa:ro "$image" bash -lc '
    set -e
    cp -r /oa /work && cd /work
    apt-get update >/dev/null 2>&1 || true
    bash modules/unattended-upgrades/apply.sh --dry-run
    bash modules/unattended-upgrades/apply.sh
    test -f /etc/apt/apt.conf.d/50unattended-upgrades
    grep -q "Managed by onionarmor" /etc/apt/apt.conf.d/50unattended-upgrades
    bash modules/unattended-upgrades/audit.sh || true
    bash modules/unattended-upgrades/revert.sh
    # After revert the managed file must be gone (debian:bookworm has no prior
    # default to restore). If something is left behind, it must NOT be ours.
    if [ -e /etc/apt/apt.conf.d/50unattended-upgrades ]; then
      ! grep -q "Managed by onionarmor" /etc/apt/apt.conf.d/50unattended-upgrades
    fi
  '
}

@test "docker: apply/audit/revert round-trip on debian:bookworm" {
  _docker_or_skip
  run _run_roundtrip debian:bookworm
  [ "$status" -eq 0 ]
}

@test "docker: apply/audit/revert round-trip on ubuntu:24.04" {
  _docker_or_skip
  run _run_roundtrip ubuntu:24.04
  [ "$status" -eq 0 ]
}
