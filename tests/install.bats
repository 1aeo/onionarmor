#!/usr/bin/env bats
# Regression tests for the root-level install.sh — the curl|sudo bash
# installer that bootstraps onionarmor on a Debian / Ubuntu host.
#
# apt-get, git, and dpkg-query are mocked via stub binaries on PATH so the
# suite is fully offline and never touches the real package manager, /opt,
# /usr/local/sbin, or /etc. We deliberately do NOT `load test_helper` here:
# that helper wires up the sysctl-apply sandbox, which is orthogonal to the
# installer and would clobber the env knobs the installer reads.

REPO_ROOT_FROM_FILE() { cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd; }

# Build a stub binary at $STUB_DIR/<name> that records its invocation in
# $STUB_DIR/<name>.log and exits with $exit_code (default 0). An optional
# $body is injected before the exit.
_stub() {
  local name="$1" exit_code="${2:-0}" body="${3:-}"
  local script="${STUB_DIR}/${name}"
  {
    printf '#!/bin/sh\n'
    printf 'printf "%%s\\n" "$*" >> "%s/%s.log"\n' "$STUB_DIR" "$name"
    printf '%s\n' "$body"
    printf 'exit %s\n' "$exit_code"
  } > "$script"
  chmod +x "$script"
}

# Render an /etc/os-release fixture inside $OA_TMP and echo its path.
_make_os_release() {
  local id="$1" id_like="${2:-}"
  local path="${OA_TMP}/os-release"
  {
    printf 'ID=%s\n' "$id"
    [ -n "$id_like" ] && printf 'ID_LIKE=%s\n' "$id_like"
    printf 'PRETTY_NAME="%s test fixture"\n' "$id"
  } > "$path"
  printf '%s\n' "$path"
}

setup() {
  REPO_ROOT="$(REPO_ROOT_FROM_FILE)"
  export REPO_ROOT
  INSTALLER="${REPO_ROOT}/install.sh"
  export INSTALLER

  # Self-managed sandbox dir. We do NOT use $BATS_TEST_TMPDIR because the
  # bats packaged on ubuntu-22.04 (1.2.x) predates it (added in bats 1.4),
  # which would leave it empty and try to mkdir /stubs. mktemp -d is the
  # portable approach the repo's other suites already use.
  OA_TMP="$(mktemp -d)"
  export OA_TMP

  STUB_DIR="${OA_TMP}/stubs"
  mkdir -p "$STUB_DIR"

  # By default every required package reports installed -> apt is skipped.
  # Tests wanting the "needs apt" path override dpkg-query to exit 1.
  _stub dpkg-query 0 'echo "install ok installed"'
  _stub apt-get 0

  # A git stub that fakes `clone --quiet --branch <ref> <url> <dest>` by
  # creating <dest>/.git and symlinking the real bin/ tree into <dest>/bin so
  # the post-clone executability + verify checks pass. fetch/checkout/reset
  # are recorded no-ops.
  cat > "${STUB_DIR}/git" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "${STUB_DIR}/git.log"
if [ "\$1" = "clone" ]; then
  for a in "\$@"; do dest="\$a"; done
  mkdir -p "\$dest/.git"
  ln -sfn "${REPO_ROOT}/bin" "\$dest/bin"
  ln -sfn "${REPO_ROOT}/lib" "\$dest/lib"
  ln -sfn "${REPO_ROOT}/roles" "\$dest/roles"
fi
exit 0
EOF
  chmod +x "${STUB_DIR}/git"

  export PATH="${STUB_DIR}:$PATH"

  # Defaults every test reuses; individual tests override as needed.
  export INSTALL_PREFIX="${OA_TMP}/opt-onionarmor"
  export SYMLINK_PATH="${OA_TMP}/bin/onionarmor"
  export ONIONARMOR_ETC_DIR="${OA_TMP}/etc/onionarmor"
  export OS_RELEASE_FILE="$(_make_os_release debian)"
  export APT="${STUB_DIR}/apt-get"
  export GIT="${STUB_DIR}/git"
  # The bats host may be macOS bash 3.2; pin the floor low so the happy path
  # runs everywhere. A dedicated test raises it to assert the refusal.
  export ONIONARMOR_INSTALL_MIN_BASH=3
  # Deterministic, new-enough kernel regardless of the host running bats.
  export ONIONARMOR_KERNEL_RELEASE="6.1.0-generic"
  # bats runs unprivileged (incl. GitHub Actions); skip the root gate except
  # in the one test that asserts it.
  export ONIONARMOR_INSTALL_ALLOW_NONROOT=1
}

teardown() {
  if [ -n "${OA_TMP:-}" ] && [ -d "$OA_TMP" ]; then rm -rf "$OA_TMP"; fi
}

# --------------------------------------------------------------------------
# File / syntax hygiene
# --------------------------------------------------------------------------

@test "install.sh: file exists and is executable" {
  [ -f "$INSTALLER" ]
  [ -x "$INSTALLER" ]
}

@test "install.sh: passes bash -n syntax check" {
  run bash -n "$INSTALLER"
  [ "$status" -eq 0 ]
}

@test "install.sh: documents the curl one-liner in its header" {
  run grep -q 'raw.githubusercontent.com/1aeo/onionarmor/main/install.sh' "$INSTALLER"
  [ "$status" -eq 0 ]
}

# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------

@test "install.sh: clean Debian host -> exit 0, deps-present path skips apt" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"detected: debian test fixture"* ]]
  [[ "$output" == *"all required apt packages already installed"* ]]
  [ ! -f "${STUB_DIR}/apt-get.log" ]
}

@test "install.sh: clones into INSTALL_PREFIX and leaves an executable CLI" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  grep -q '^clone' "${STUB_DIR}/git.log"
  [ -d "$INSTALL_PREFIX/.git" ]
  [ -x "$INSTALL_PREFIX/bin/onionarmor" ]
}

@test "install.sh: symlinks the CLI onto PATH at SYMLINK_PATH" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ -L "$SYMLINK_PATH" ]
  [ "$(readlink "$SYMLINK_PATH")" = "$INSTALL_PREFIX/bin/onionarmor" ]
  [[ "$output" == *"linked $SYMLINK_PATH"* ]]
}

@test "install.sh: creates the host config dir" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ -d "$ONIONARMOR_ETC_DIR" ]
}

@test "install.sh: verifies the installed CLI actually runs" {
  # Real bin/ is symlinked in by the git stub, so `onionarmor help` runs for
  # real. A broken install would make the verify gate fail.
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
}

@test "install.sh: SKIP_VERIFY bypasses the post-install run gate" {
  export ONIONARMOR_INSTALL_SKIP_VERIFY=1
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
}

# --------------------------------------------------------------------------
# OS gate
# --------------------------------------------------------------------------

@test "install.sh: Ubuntu (ID=ubuntu, ID_LIKE=debian) is accepted" {
  export OS_RELEASE_FILE="$(_make_os_release ubuntu debian)"
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"detected: ubuntu test fixture"* ]]
}

@test "install.sh: a debian-derivative via ID_LIKE=ubuntu is accepted" {
  export OS_RELEASE_FILE="$(_make_os_release linuxmint ubuntu)"
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
}

@test "install.sh: non-Debian distro (fedora) is rejected" {
  export OS_RELEASE_FILE="$(_make_os_release fedora)"
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"unsupported distro"* ]]
}

@test "install.sh: missing /etc/os-release is rejected" {
  export OS_RELEASE_FILE="${OA_TMP}/does-not-exist"
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"Debian / Ubuntu only"* ]]
}

# --------------------------------------------------------------------------
# Root gate
# --------------------------------------------------------------------------

@test "install.sh: refuses to run as non-root with a clear sudo hint" {
  unset ONIONARMOR_INSTALL_ALLOW_NONROOT
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must run as root"* ]]
  [[ "$output" == *"sudo"* ]]
  # Refusal must happen before any clone / symlink side effects.
  [ ! -e "$INSTALL_PREFIX/.git" ]
  [ ! -L "$SYMLINK_PATH" ]
}

# --------------------------------------------------------------------------
# bash version gate
# --------------------------------------------------------------------------

@test "install.sh: refuses when bash is older than the required major" {
  export ONIONARMOR_INSTALL_MIN_BASH=99
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"bash >= 99 required"* ]]
}

# --------------------------------------------------------------------------
# kernel version gate
# --------------------------------------------------------------------------

@test "install.sh: rejects a kernel older than the sysctl-key minimum" {
  export ONIONARMOR_KERNEL_RELEASE="4.19.0-generic"
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"older than 5.2"* ]]
  [[ "$output" == *"unprivileged_bpf_disabled"* ]]
}

@test "install.sh: accepts a kernel exactly at the minimum" {
  export ONIONARMOR_KERNEL_RELEASE="5.2.0-generic"
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"kernel: 5.2.0-generic"* ]]
}

@test "install.sh: rejects an unparseable kernel version" {
  export ONIONARMOR_KERNEL_RELEASE="not-a-version"
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not parse kernel version"* ]]
}

# --------------------------------------------------------------------------
# apt path
# --------------------------------------------------------------------------

@test "install.sh: a missing package triggers apt update + install" {
  _stub dpkg-query 1 'echo "unknown ok not-installed"'
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"installing apt packages"* ]]
  [ -f "${STUB_DIR}/apt-get.log" ]
  grep -q '^update$' "${STUB_DIR}/apt-get.log"
  grep -q 'install -y --no-install-recommends .*procps' "${STUB_DIR}/apt-get.log"
  grep -q 'install -y --no-install-recommends .*mawk' "${STUB_DIR}/apt-get.log"
  grep -q 'install -y --no-install-recommends .*coreutils' "${STUB_DIR}/apt-get.log"
}

@test "install.sh: apt-get update failure is reported, not a bare crash" {
  _stub dpkg-query 1 'echo "unknown"'
  # apt-get fails on `update` (its first positional arg).
  _stub apt-get 0 'case "$1" in update) exit 1 ;; esac'
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"apt-get update failed"* ]]
}

@test "install.sh: apt-get install failure is reported clearly" {
  _stub dpkg-query 1 'echo "unknown"'
  _stub apt-get 0 'case "$1" in install) exit 1 ;; esac'
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"apt-get install failed"* ]]
}

# --------------------------------------------------------------------------
# Idempotency / partial-state
# --------------------------------------------------------------------------

@test "install.sh: idempotent — second run updates the checkout, no clone" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  grep -q '^clone' "${STUB_DIR}/git.log"

  : > "${STUB_DIR}/git.log"
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"updating existing checkout"* ]]
  grep -q ' fetch ' "${STUB_DIR}/git.log"
  grep -q ' checkout ' "${STUB_DIR}/git.log"
  grep -q ' reset ' "${STUB_DIR}/git.log"
  ! grep -q '^clone' "${STUB_DIR}/git.log"
}

@test "install.sh: idempotent — symlink survives a second run" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ -L "$SYMLINK_PATH" ]
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ -L "$SYMLINK_PATH" ]
  [ "$(readlink "$SYMLINK_PATH")" = "$INSTALL_PREFIX/bin/onionarmor" ]
}

@test "install.sh: refuses to clobber a non-git non-empty INSTALL_PREFIX" {
  mkdir -p "$INSTALL_PREFIX"
  : > "$INSTALL_PREFIX/some-existing-file"
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to clobber"* ]]
}

@test "install.sh: handles partial prior state (empty INSTALL_PREFIX dir)" {
  mkdir -p "$INSTALL_PREFIX"   # exists but empty -> clone proceeds
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  grep -q '^clone' "${STUB_DIR}/git.log"
  [ -d "$INSTALL_PREFIX/.git" ]
}

@test "install.sh: refuses to overwrite a real file sitting at SYMLINK_PATH" {
  mkdir -p "$(dirname "$SYMLINK_PATH")"
  : > "$SYMLINK_PATH"   # a regular file, not a symlink
  run bash "$INSTALLER"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a symlink"* ]]
}

# --------------------------------------------------------------------------
# Safety model: never auto-apply, never touch GRUB lockdown
# --------------------------------------------------------------------------

@test "install.sh: does NOT write a host role.conf by default (invite-only)" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_ETC_DIR/role.conf" ]
  [[ "$output" == *"No role applied"* ]]
}

@test "install.sh: never stages GRUB kernel lockdown" {
  export ONIONARMOR_GRUB_FILE="${OA_TMP}/grub"   # installer must ignore this
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ ! -e "$ONIONARMOR_GRUB_FILE" ]
  [[ "$output" == *"did NOT apply kernel lockdown"* ]]
  # The installer must never *invoke* the lockdown subcommand. The only
  # mentions of "apply-lockdown" allowed in the script are comments and the
  # next-steps summary, never a `"$CLI" apply-lockdown` call.
  ! grep -Eq '"\$CLI"[[:space:]]+apply-lockdown' "$INSTALLER"
}

@test "install.sh: summary points the operator at role declaration + apply" {
  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"role=tor-relay"* ]]
  [[ "$output" == *"onionarmor diff --role tor-relay"* ]]
  [[ "$output" == *"onionarmor apply --role tor-relay --first-run"* ]]
  [[ "$output" == *"tor-relay, eval-host, receiver"* ]]
}

# --------------------------------------------------------------------------
# Opt-in apply (explicit, still never touches lockdown)
# --------------------------------------------------------------------------

@test "install.sh: ONIONARMOR_INSTALL_ROLE declares the role and applies it" {
  # Point the real CLI's apply machinery at the sandbox + fake sysctl so the
  # opt-in apply writes managed files here, not into the host's /etc.
  export ONIONARMOR_INSTALL_ROLE="tor-relay"
  export ONIONARMOR_ROLES_DIR="${REPO_ROOT}/roles"
  export ONIONARMOR_SYSCTL_DIR="${OA_TMP}/sysctl.d"
  export ONIONARMOR_SYSCTL_CMD="${REPO_ROOT}/tests/fixtures/fake-sysctl"
  export ONIONARMOR_AUDIT_LOG="${OA_TMP}/audit.log"
  export ONIONARMOR_SKIP_RELOAD=yes
  export FAKE_SYSCTL_STATE="${OA_TMP}/sysctl-state"
  mkdir -p "$ONIONARMOR_SYSCTL_DIR"
  cp "${REPO_ROOT}/tests/fixtures/debian13-relay-baseline.state" "$FAKE_SYSCTL_STATE"

  run bash "$INSTALLER"
  [ "$status" -eq 0 ]
  [ -f "$ONIONARMOR_ETC_DIR/role.conf" ]
  grep -q '^role=tor-relay$' "$ONIONARMOR_ETC_DIR/role.conf"
  [ -f "$ONIONARMOR_SYSCTL_DIR/99-onionarmor-tor-relay.conf" ]
  [[ "$output" == *"Applied role 'tor-relay'"* ]]
}
