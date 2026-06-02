#!/usr/bin/env bash
# install.sh — one-shot installer for onionarmor on Debian / Ubuntu.
#
#   curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh | sudo bash
#
# Does, in order:
#   1. Refuse to run as non-root (we need to write /opt + /usr/local/sbin).
#   2. Validate the bash version (the CLI relies on bash arrays + `set -u`).
#   3. Sanity-check we're on Debian / Ubuntu.
#   4. Validate the running kernel is new enough for the role sysctl keys
#      (kernel.unprivileged_bpf_disabled=2 needs >= 5.2).
#   5. apt-get install any missing prerequisite tools.
#   6. git clone (or update) the repo into $INSTALL_PREFIX (/opt/onionarmor).
#   7. Symlink bin/onionarmor onto PATH at $SYMLINK_PATH.
#   8. Verify the CLI runs, then print a summary + next steps.
#
# This installer is deliberately CONSERVATIVE — it matches onionarmor's
# safety model:
#   * It NEVER applies a role posture on its own. Applying sysctls requires a
#     deliberate host-role declaration (/etc/onionarmor/role.conf) plus a
#     first-run confirmation; the installer only invites the operator to do
#     that (unless they explicitly opt in via $ONIONARMOR_INSTALL_ROLE).
#   * It NEVER stages GRUB kernel lockdown. That stays gated behind the
#     explicit `onionarmor apply-lockdown` subcommand, which itself never
#     auto-reboots.
#
# Safe to pipe through `curl ... | sudo bash` and safe to re-run; every step
# is idempotent. The installed tool originates no outbound connection itself.
#
# Env hooks (operators rarely need these; the bats suite uses them):
#   INSTALL_PREFIX                      install root (default /opt/onionarmor)
#   SYMLINK_PATH                        CLI symlink (default /usr/local/sbin/onionarmor)
#   ONIONARMOR_REPO_URL                 override the git remote
#   ONIONARMOR_REPO_REF                 branch / tag to check out (default main)
#   ONIONARMOR_ETC_DIR                  host config dir (default /etc/onionarmor)
#   APT                                 apt-get binary (default apt-get; tests stub this)
#   GIT                                 git binary (default git; tests stub this)
#   OS_RELEASE_FILE                     /etc/os-release path (tests point at a fixture)
#   ONIONARMOR_KERNEL_RELEASE           override `uname -r` (tests set this)
#   ONIONARMOR_INSTALL_MIN_BASH         minimum bash major version (default 4)
#   ONIONARMOR_INSTALL_MIN_KERNEL       minimum kernel major.minor (default 5.2)
#   ONIONARMOR_INSTALL_ALLOW_NONROOT=1  skip the root check (tests set this)
#   ONIONARMOR_INSTALL_SKIP_VERIFY=1    skip the post-install `onionarmor help` gate
#   ONIONARMOR_INSTALL_ROLE=<role>      opt in: declare host role + apply it now

set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/onionarmor}"
SYMLINK_PATH="${SYMLINK_PATH:-/usr/local/sbin/onionarmor}"
ONIONARMOR_REPO_URL="${ONIONARMOR_REPO_URL:-https://github.com/1aeo/onionarmor.git}"
ONIONARMOR_REPO_REF="${ONIONARMOR_REPO_REF:-main}"
ONIONARMOR_ETC_DIR="${ONIONARMOR_ETC_DIR:-/etc/onionarmor}"
APT="${APT:-apt-get}"
GIT="${GIT:-git}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
ONIONARMOR_INSTALL_MIN_BASH="${ONIONARMOR_INSTALL_MIN_BASH:-4}"
ONIONARMOR_INSTALL_MIN_KERNEL="${ONIONARMOR_INSTALL_MIN_KERNEL:-5.2}"

# Prerequisite packages the CLI needs at runtime. `sysctl` lives in procps;
# `awk` in mawk; `ln`/`install` in coreutils. We install the whole set in one
# apt transaction when any of them is missing.
REQUIRED_APT_PACKAGES=(
  git
  mawk
  procps
  coreutils
  sed
  ca-certificates
)

say()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] warning: %s\n' "$*" >&2; }
die()  { printf '[install] error: %s\n' "$*" >&2; exit 1; }

# ---- 1. root check ------------------------------------------------------
# We write to /opt and /usr/local/sbin and (optionally) apt-install packages,
# so root is required. Tests set ONIONARMOR_INSTALL_ALLOW_NONROOT=1.
if [ "${ONIONARMOR_INSTALL_ALLOW_NONROOT:-0}" != "1" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    die "must run as root — re-run with sudo:
  curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh | sudo bash"
  fi
fi

# ---- 2. bash version check ---------------------------------------------
# The CLI uses bash arrays and `set -u`; bail early with a clear message
# rather than failing cryptically deep in the tool.
if [ "${BASH_VERSINFO:-0}" -lt "$ONIONARMOR_INSTALL_MIN_BASH" ]; then
  die "bash >= ${ONIONARMOR_INSTALL_MIN_BASH} required, found ${BASH_VERSION:-unknown}"
fi

# ---- 3. OS check --------------------------------------------------------
if [ ! -r "$OS_RELEASE_FILE" ]; then
  die "cannot read $OS_RELEASE_FILE — this installer supports Debian / Ubuntu only"
fi

# shellcheck disable=SC1090
. "$OS_RELEASE_FILE"
OS_ID="${ID:-}"
OS_ID_LIKE="${ID_LIKE:-}"
case " $OS_ID $OS_ID_LIKE " in
  *" debian "*|*" ubuntu "*) : ;;
  *) die "unsupported distro: ID=$OS_ID ID_LIKE=$OS_ID_LIKE (Debian / Ubuntu required)" ;;
esac
say "detected: ${PRETTY_NAME:-$OS_ID}"

# ---- 4. kernel version check -------------------------------------------
# Role configs include keys that need a recent kernel — most notably
# kernel.unprivileged_bpf_disabled=2 (>= 5.2). Warn-and-continue would let a
# silent partial-apply through later, so we hard-fail here with the keys named.
kernel_release="${ONIONARMOR_KERNEL_RELEASE:-$(uname -r)}"
kernel_mm="${kernel_release%%-*}"                 # strip -generic / -amd64 etc.
k_major="${kernel_mm%%.*}"
k_rest="${kernel_mm#*.}"
[ "$k_rest" = "$kernel_mm" ] && k_minor="0" || k_minor="${k_rest%%.*}"
min_major="${ONIONARMOR_INSTALL_MIN_KERNEL%%.*}"
min_rest="${ONIONARMOR_INSTALL_MIN_KERNEL#*.}"
[ "$min_rest" = "$ONIONARMOR_INSTALL_MIN_KERNEL" ] && min_minor="0" || min_minor="${min_rest%%.*}"
case "$k_major$k_minor$min_major$min_minor" in
  *[!0-9]*) die "could not parse kernel version: $kernel_release" ;;
esac
if [ "$k_major" -lt "$min_major" ] \
   || { [ "$k_major" -eq "$min_major" ] && [ "$k_minor" -lt "$min_minor" ]; }; then
  die "kernel $kernel_release is older than ${ONIONARMOR_INSTALL_MIN_KERNEL} — \
the role sysctl keys (e.g. kernel.unprivileged_bpf_disabled=2) need a newer kernel"
fi
say "kernel: $kernel_release (>= ${ONIONARMOR_INSTALL_MIN_KERNEL} ok)"

# ---- 5. prerequisite packages / apt install ----------------------------
# Fast path: if every required package already reports `install ok installed`,
# skip the apt update + install so re-runs stay fast and don't touch the apt
# lock when nothing needs to change.
need_apt=0
for pkg in "${REQUIRED_APT_PACKAGES[@]}"; do
  if ! dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null \
      | grep -q '^install ok installed$'; then
    need_apt=1
    break
  fi
done

if [ "$need_apt" -eq 1 ]; then
  say "installing apt packages: ${REQUIRED_APT_PACKAGES[*]}"
  DEBIAN_FRONTEND=noninteractive "$APT" update \
    || die "apt-get update failed — check network / apt sources and re-run"
  DEBIAN_FRONTEND=noninteractive "$APT" install -y --no-install-recommends \
    "${REQUIRED_APT_PACKAGES[@]}" \
    || die "apt-get install failed — see output above"
else
  say "all required apt packages already installed — skipping apt"
fi

# ---- 6. clone or update the repo ---------------------------------------
if [ -d "$INSTALL_PREFIX/.git" ]; then
  say "updating existing checkout at $INSTALL_PREFIX"
  # Refuse to clobber local edits. The hard reset below discards anything not
  # committed, so a dirty checkout would silently lose operator/local changes.
  if [ -n "$("$GIT" -C "$INSTALL_PREFIX" status --porcelain 2>/dev/null)" ] \
     && [ "${ONIONARMOR_INSTALL_FORCE:-0}" != "1" ]; then
    die "$INSTALL_PREFIX has uncommitted local changes; refusing to hard-reset. \
Commit or stash them, or re-run with ONIONARMOR_INSTALL_FORCE=1 to discard them."
  fi
  "$GIT" -C "$INSTALL_PREFIX" fetch --quiet origin "$ONIONARMOR_REPO_REF"
  "$GIT" -C "$INSTALL_PREFIX" checkout --quiet "$ONIONARMOR_REPO_REF"
  "$GIT" -C "$INSTALL_PREFIX" reset --quiet --hard FETCH_HEAD
else
  if [ -e "$INSTALL_PREFIX" ] && [ -n "$(ls -A "$INSTALL_PREFIX" 2>/dev/null)" ]; then
    die "$INSTALL_PREFIX exists and is non-empty but is not a git checkout; refusing to clobber"
  fi
  mkdir -p "$INSTALL_PREFIX"
  say "cloning $ONIONARMOR_REPO_URL ($ONIONARMOR_REPO_REF) -> $INSTALL_PREFIX"
  "$GIT" clone --quiet --branch "$ONIONARMOR_REPO_REF" \
    "$ONIONARMOR_REPO_URL" "$INSTALL_PREFIX"
fi

CLI="$INSTALL_PREFIX/bin/onionarmor"
[ -x "$CLI" ] || die "expected $CLI to be executable after clone"

# ---- 7. symlink onto PATH ----------------------------------------------
# `ln -sfn` is idempotent: re-running just repoints the symlink. We refuse to
# clobber a real file sitting where the symlink should go.
if [ -e "$SYMLINK_PATH" ] && [ ! -L "$SYMLINK_PATH" ]; then
  die "$SYMLINK_PATH exists and is not a symlink; refusing to overwrite it"
fi
mkdir -p "$(dirname "$SYMLINK_PATH")"
ln -sfn "$CLI" "$SYMLINK_PATH"
say "linked $SYMLINK_PATH -> $CLI"

# Make sure the host config dir exists so the operator's one-time role
# declaration is a single `tee`. We do NOT write role.conf for them — that
# classification is a deliberate operator step (safety rail #2).
mkdir -p "$ONIONARMOR_ETC_DIR"

# ---- 8. verify the CLI runs --------------------------------------------
if [ "${ONIONARMOR_INSTALL_SKIP_VERIFY:-0}" != "1" ]; then
  "$CLI" help >/dev/null 2>&1 || die "installed CLI failed to run ($CLI help)"
fi

# ---- 9. optional opt-in apply ------------------------------------------
# Default behaviour is to INVITE, never apply. If the operator explicitly set
# ONIONARMOR_INSTALL_ROLE, declare that host role and apply it now (auto-
# confirming the first-run prompt). Still never touches GRUB lockdown.
if [ -n "${ONIONARMOR_INSTALL_ROLE:-}" ]; then
  role="$ONIONARMOR_INSTALL_ROLE"
  say "opt-in apply requested: role=$role"
  printf 'role=%s\n' "$role" > "$ONIONARMOR_ETC_DIR/role.conf"
  ONIONARMOR_AUTO_CONFIRM=yes "$CLI" apply --role "$role" --first-run \
    || die "apply --role $role failed — see output above"
  applied_note="Applied role '$role' sysctl posture (audit: onionarmor audit)."
else
  applied_note="No role applied — pick one below when you're ready."
fi

# ---- 10. summary --------------------------------------------------------
if [ -n "${ONIONARMOR_INSTALL_ROLE:-}" ]; then
  cat <<EOF

[install] onionarmor installed at $INSTALL_PREFIX
[install] CLI on PATH at $SYMLINK_PATH
[install] $applied_note

What this installer did NOT do (by design):
  * It did NOT apply kernel lockdown. That stays behind the explicit
    \`onionarmor apply-lockdown\` subcommand and never auto-reboots.

Next steps — apply kernel lockdown (Phase 2):

  # Inspect the lockdown settings before applying.
  onionarmor show-lockdown

  # Apply and stage GRUB lockdown (requires reboot to take effect).
  sudo onionarmor apply-lockdown

Available roles: tor-relay, eval-host, receiver.
Run \`onionarmor help\` for the full command set.
EOF
else
  cat <<EOF

[install] onionarmor installed at $INSTALL_PREFIX
[install] CLI on PATH at $SYMLINK_PATH
[install] $applied_note

What this installer did NOT do (by design):
  * It did NOT apply kernel lockdown. That stays behind the explicit
    \`onionarmor apply-lockdown\` subcommand and never auto-reboots.
  * It did NOT classify this host. Applying a role posture is opt-in.

Next steps — apply a hardening posture (Phase 1 sysctls):

  # 1. Declare this host's role (one-time, deliberate).
  echo 'role=tor-relay' | sudo tee $ONIONARMOR_ETC_DIR/role.conf

  # 2. Preview what would change vs the live kernel.
  onionarmor diff --role tor-relay

  # 3. First-time apply (interactive confirmation, with backup + audit).
  sudo onionarmor apply --role tor-relay --first-run

Available roles: tor-relay, eval-host, receiver.
Run \`onionarmor help\` for the full command set.
EOF
fi
