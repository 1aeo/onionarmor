#!/usr/bin/env bats
# firewall-default-deny — OPT-IN integration test on a real debian:bookworm.
#
# Skipped unless BOTH docker is on PATH and ONIONARMOR_DOCKER_TESTS=1, so the
# default offline suite and CI stay fast and hermetic. Enable with:
#   ONIONARMOR_DOCKER_TESTS=1 bats modules/firewall-default-deny/tests/bats/docker.bats
#
# Runs against real ufw. `ufw enable` needs NET_ADMIN and a working iptables
# backend, so this exercises install-detection + dry-run + the inactive audit
# path end-to-end (a full enable/disable cycle needs --cap-add=NET_ADMIN and is
# left to a privileged CI lane).

load test_helper

_docker_or_skip() {
  command -v docker >/dev/null 2>&1 || skip "docker not installed"
  [ "${ONIONARMOR_DOCKER_TESTS:-0}" = "1" ] || skip "set ONIONARMOR_DOCKER_TESTS=1 to run docker integration"
}

@test "docker: ufw detected, dry-run renders, audit runs on debian:bookworm" {
  _docker_or_skip
  run docker run --rm -v "$REPO_ROOT":/oa:ro debian:bookworm bash -lc '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends ufw at iproute2 >/dev/null 2>&1
    cp -r /oa /work && cd /work
    bash modules/firewall-default-deny/apply.sh --dry-run
    # audit before enabling: ufw inactive -> exits 1, which is expected here
    bash modules/firewall-default-deny/audit.sh || true
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: firewall-default-deny"* ]]
  [[ "$output" == *"allow 22/tcp"* ]]
}
