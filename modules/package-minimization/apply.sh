#!/usr/bin/env bash
# MODULE: package minimization — purge build/debug/network-analysis tools (gcc/gdb/tcpdump/strace/...) that aid post-exploitation. Low risk; recommended-off; needs --confirm.
#
# apply.sh — remove the configured set of build/debug/network-analysis packages
# that are currently installed. Idempotent; supports --dry-run. REFUSES to remove
# anything without --confirm (so packages can never be stripped silently), and
# SKIPS entirely on a build-host role.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

pkg_parse_flags "$@"

present=$(pkg_present_list)
present_count=$(printf '%s\n' "$present" | grep -c . || true)
reclaim_kib=$(printf '%s\n' "$present" | pkg_reclaim_kib)

# ---------------------------------------------------------------------------
# Dry run: list the present removable packages + the reclaimable space, change
# nothing. Exit 0.
# ---------------------------------------------------------------------------
if [ "$PKG_DRY_RUN" -eq 1 ]; then
  info "dry-run: package-minimization (no host changes)"
  skip=$(pkg_skip_role)
  cat <<EOF

PLAN
  removable set      -> $(pkg_remove_list | tr '\n' ' ')
  purge command      -> $ONIONARMOR_PKG_APT purge -y <present pkgs>
  role skip ($ONIONARMOR_PKG_SKIP_ROLE) -> $([ -n "$skip" ] && echo "YES — would skip" || echo "no")

PRESENT (installed; would be purged)
EOF
  if [ "$present_count" -eq 0 ]; then
    printf '  (none — nothing to remove)\n'
  else
    printf '%s\n' "$present" | while read -r p; do
      [ -n "$p" ] || continue
      printf '  %-22s %s\n' "$p" "$(pkg_human_kib "$(pkg_installed_size_kib "$p")")"
    done
  fi
  printf '\nReclaimable: %s across %s package(s)\n' "$(pkg_human_kib "$reclaim_kib")" "$present_count"
  exit 0
fi

# ---------------------------------------------------------------------------
# Role skip: a build host legitimately needs toolchains — never strip them.
# ---------------------------------------------------------------------------
skip=$(pkg_skip_role)
if [ -n "$skip" ]; then
  audit_log pkg.apply.skip "role=$skip"
  info "host role is '$skip' — skipping package removal (a build host needs these toolchains)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Confirmation gate: refuse to remove anything without --confirm (or an
# operator yes via oa_confirm). This is what makes a bare apply safe.
# ---------------------------------------------------------------------------
if [ "$PKG_CONFIRM" -ne 1 ]; then
  if [ "$present_count" -eq 0 ]; then
    info "no removable packages installed — nothing to do"
    exit 0
  fi
  warn "package-minimization removes: $(printf '%s\n' "$present" | tr '\n' ' ')"
  if ! oa_confirm "Purge the ${present_count} package(s) above? This is destructive (re-add later with apt-get install)."; then
    audit_log pkg.apply.refused "present=$present_count confirm=no"
    die "refusing to remove packages without --confirm (or a 'yes' confirmation). Re-run with --confirm, or --dry-run to preview."
  fi
fi

audit_log pkg.apply.start "present=$present_count reclaim_kib=$reclaim_kib"

# ---------------------------------------------------------------------------
# Nothing installed -> idempotent no-op.
# ---------------------------------------------------------------------------
if [ "$present_count" -eq 0 ]; then
  info "no removable packages installed — nothing to do"
  audit_log pkg.apply.done "removed=0"
  cat <<EOF

[package-minimization] applied.
  removed : 0 package(s) — host already minimal

Check status any time:  onionarmor audit  --module package-minimization
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Purge the present removable packages, then record exactly what we removed so
# revert can print the reinstall command. We pass the whole present set in one
# apt-get purge invocation.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2046  # intentional word-split: pass each pkg as a separate arg
set -- $(printf '%s\n' "$present" | tr '\n' ' ')
if DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_PKG_APT" purge -y "$@"; then
  info "purged: $*"
else
  audit_fail_die pkg.apply.fail "stage=purge" "apt-get purge failed for: $*"
fi

mkdir -p "$ONIONARMOR_PKG_STATE_DIR" || die "cannot create $ONIONARMOR_PKG_STATE_DIR"
state=$(pkg_state_file)
# Append (de-duplicated) so repeated applies accumulate the full removal history
# that revert reinstalls from.
{
  [ -f "$state" ] && cat "$state"
  printf '%s\n' "$present"
} | sort -u | grep . > "$state.tmp.$$" || true
mv "$state.tmp.$$" "$state" || { rm -f "$state.tmp.$$"; die "cannot write $state"; }
audit_log pkg.apply.removed "pkgs=$* state=$state"

removed_count=$present_count
audit_log pkg.apply.done "removed=$removed_count reclaim_kib=$reclaim_kib"

cat <<EOF

[package-minimization] applied.
  removed : $removed_count package(s) — $*
  reclaimed (est.) : $(pkg_human_kib "$reclaim_kib")
  recorded : $state

NOTE: removal is NOT auto-reversible. To reinstall later:
  onionarmor revert --module package-minimization   (prints the exact apt-get install command)

Check status any time:  onionarmor audit  --module package-minimization
EOF
