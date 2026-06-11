#!/usr/bin/env bash
# MODULE: mac-profile-install — install + enforce a Mandatory Access Control LSM (AppArmor on Debian/Ubuntu, SELinux on RHEL/Fedora); enforce the tor profile. Reboot may be required; never auto-reboots.
#
# apply.sh — install and enforce the distro-appropriate MAC LSM. On AppArmor:
# install apparmor + utils if absent, ensure the kernel cmdline carries
# apparmor=1 security=apparmor (backing up grub first), and put the tor profile
# into enforce mode. On SELinux: install policycoreutils + targeted policy if
# absent and set SELINUX=enforcing. Kernel-cmdline / enforcing changes can need a
# reboot or relabel — printed as a notice; NEVER reboots or relabels itself.
# Idempotent; --dry-run.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

mac_parse_flags "$@"

lsm=$(mac_detect_lsm)
state_path=$(mac_state_path)
grub_backup=$(mac_grub_backup_path)
tor_profile=$(mac_tor_profile_path)

# ---------------------------------------------------------------------------
# Dry run: print the plan, change nothing.
# ---------------------------------------------------------------------------
if [ "$MAC_DRY_RUN" -eq 1 ]; then
  info "dry-run: mac-profile-install (no host changes)"
  printf '\nPLAN (LSM: %s)\n' "$lsm"
  if [ "$lsm" = "apparmor" ]; then
    if mac_aa_installed; then
      printf '  package          -> apparmor already installed\n'
    else
      printf '  package          -> %s install -y apparmor apparmor-profiles apparmor-utils\n' "$ONIONARMOR_MAC_APT"
    fi
    if mac_grub_has_tokens; then
      printf '  kernel cmdline   -> already has %s\n' "$ONIONARMOR_MAC_GRUB_TOKENS"
    else
      printf '  kernel cmdline   -> append "%s" to GRUB_CMDLINE_LINUX_DEFAULT in %s (REBOOT REQUIRED)\n' "$ONIONARMOR_MAC_GRUB_TOKENS" "$ONIONARMOR_GRUB_FILE"
    fi
    if mac_aa_tor_profile_exists; then
      printf '  tor profile      -> aa-enforce %s\n' "$tor_profile"
    else
      printf '  tor profile      -> none installed at %s (no change — not a failure)\n' "$tor_profile"
    fi
  else
    if mac_se_installed; then
      printf '  package          -> selinux tools already installed\n'
    else
      printf '  package          -> %s install -y policycoreutils selinux-policy-targeted\n' "$ONIONARMOR_MAC_DNF"
    fi
    printf '  config           -> set SELINUX=enforcing in %s (may need relabel/reboot)\n' "$ONIONARMOR_MAC_SELINUX_CONFIG"
  fi
  mac_skip_reload && printf '\n  ONIONARMOR_SKIP_RELOAD=yes -> plan only, no apt/dnf/enforce/setenforce\n'
  exit 0
fi

audit_log mac.apply.start "lsm=$lsm skip_reload=${ONIONARMOR_SKIP_RELOAD:-no}"
mkdir -p "$ONIONARMOR_MAC_STATE_DIR" || die "cannot create state dir $ONIONARMOR_MAC_STATE_DIR"

reboot_required=0
verify_failed=0
changes=""

# ---------------------------------------------------------------------------
# AppArmor branch (Debian/Ubuntu).
# ---------------------------------------------------------------------------
if [ "$lsm" = "apparmor" ]; then

  # 1. Install apparmor + utils if the tools are missing.
  if ! mac_aa_installed; then
    if mac_skip_reload; then
      info "SKIP_RELOAD: would install apparmor apparmor-profiles apparmor-utils (plan only)"
    else
      info "installing apparmor apparmor-profiles apparmor-utils"
      if "$ONIONARMOR_MAC_APT" install -y apparmor apparmor-profiles apparmor-utils >/dev/null 2>&1; then
        audit_log mac.apply.install "pkgs=apparmor,apparmor-profiles,apparmor-utils"
        changes="${changes}installed-apparmor "
      else
        audit_log mac.apply.fail "stage=install pkgs=apparmor"
        warn "apparmor install failed — host remains without mandatory access control (permissive, not broken)"
        verify_failed=1
      fi
    fi
  else
    info "apparmor already installed"
  fi

  # 2. Ensure the kernel cmdline carries the AppArmor tokens (reboot to take
  #    effect). Back the grub file up before the first edit.
  if [ -r "$ONIONARMOR_GRUB_FILE" ]; then
    if mac_grub_has_tokens; then
      info "kernel cmdline already has: $ONIONARMOR_MAC_GRUB_TOKENS"
    elif [ -w "$ONIONARMOR_GRUB_FILE" ]; then
      cp "$ONIONARMOR_GRUB_FILE" "$grub_backup" \
        || die "cannot back up $ONIONARMOR_GRUB_FILE to $grub_backup"
      tmp="$ONIONARMOR_GRUB_FILE.onionarmor.$$"
      # Insert the tokens before the closing quote of GRUB_CMDLINE_LINUX_DEFAULT
      # (same approach as bin/onionarmor cmd_apply_lockdown).
      awk -v toks="$ONIONARMOR_MAC_GRUB_TOKENS" '
        BEGIN { changed = 0 }
        /^GRUB_CMDLINE_LINUX_DEFAULT[[:space:]]*=/ {
          sub(/"[[:space:]]*$/, " " toks "\"")
          changed = 1
        }
        { print }
        END { if (changed == 0) exit 3 }
      ' "$ONIONARMOR_GRUB_FILE" > "$tmp" \
        || { rm -f "$tmp"; audit_fail_die mac.apply.fail "stage=grub-awk" "no GRUB_CMDLINE_LINUX_DEFAULT line in $ONIONARMOR_GRUB_FILE"; }
      mv "$tmp" "$ONIONARMOR_GRUB_FILE" \
        || { rm -f "$tmp"; audit_fail_die mac.apply.fail "stage=grub-move" "cannot replace $ONIONARMOR_GRUB_FILE"; }
      audit_log mac.apply.grub "added=$ONIONARMOR_MAC_GRUB_TOKENS file=$ONIONARMOR_GRUB_FILE backup=$grub_backup"
      info "added '$ONIONARMOR_MAC_GRUB_TOKENS' to GRUB_CMDLINE_LINUX_DEFAULT (backup: $grub_backup)"
      changes="${changes}grub-cmdline "
      reboot_required=1
    else
      warn "grub file not writable ($ONIONARMOR_GRUB_FILE) — cannot ensure AppArmor kernel cmdline (run as root)"
    fi
  else
    warn "grub file not found/readable ($ONIONARMOR_GRUB_FILE) — skipping kernel cmdline step"
  fi

  # 3. Enforce the tor profile if one is installed. Absent => info, not failure.
  if mac_aa_tor_profile_exists; then
    if mac_skip_reload; then
      info "SKIP_RELOAD: would aa-enforce $tor_profile (plan only)"
    else
      if "$ONIONARMOR_MAC_AA_ENFORCE" "$tor_profile" >/dev/null 2>&1; then
        audit_log mac.apply.enforce "profile=$tor_profile"
        info "tor profile set to enforce: $tor_profile"
        changes="${changes}tor-enforce "
      else
        audit_log mac.apply.fail "stage=aa-enforce profile=$tor_profile"
        warn "aa-enforce $tor_profile failed — tor profile not enforcing (permissive, not broken)"
        verify_failed=1
      fi
    fi
  else
    info "no tor AppArmor profile installed yet at $tor_profile — nothing to enforce (not a failure)"
  fi

  # 4. Verify (default on).
  if [ "$MAC_VERIFY" -eq 1 ] && ! mac_skip_reload; then
    if mac_aa_active; then
      info "verify: AppArmor is installed/active"
    else
      warn "verify: AppArmor is NOT active"; verify_failed=1
    fi
    if mac_aa_tor_profile_exists; then
      if [ "$(mac_aa_tor_mode)" = "enforce" ]; then
        info "verify: tor profile is in enforce mode"
      else
        warn "verify: tor profile is present but not in enforce mode"; verify_failed=1
      fi
    fi
  fi

# ---------------------------------------------------------------------------
# SELinux branch (RHEL/CentOS/Fedora).
# ---------------------------------------------------------------------------
else

  # 1. Install selinux tools if missing.
  if ! mac_se_installed; then
    if mac_skip_reload; then
      info "SKIP_RELOAD: would install policycoreutils selinux-policy-targeted (plan only)"
    else
      info "installing policycoreutils selinux-policy-targeted"
      if "$ONIONARMOR_MAC_DNF" install -y policycoreutils selinux-policy-targeted >/dev/null 2>&1; then
        audit_log mac.apply.install "pkgs=policycoreutils,selinux-policy-targeted"
        changes="${changes}installed-selinux "
      else
        audit_log mac.apply.fail "stage=install pkgs=selinux"
        warn "selinux install failed — host remains without mandatory access control (permissive, not broken)"
        verify_failed=1
      fi
    fi
  else
    info "selinux tools already installed"
  fi

  # 2. Set SELINUX=enforcing in the config (backup first). awk-rewrite the
  #    SELINUX= line; enforcing may need a relabel/reboot.
  if [ -r "$ONIONARMOR_MAC_SELINUX_CONFIG" ]; then
    if [ "$(mac_se_config_mode)" = "enforcing" ]; then
      info "SELINUX already set to enforcing in $ONIONARMOR_MAC_SELINUX_CONFIG"
    elif [ -w "$ONIONARMOR_MAC_SELINUX_CONFIG" ]; then
      cp "$ONIONARMOR_MAC_SELINUX_CONFIG" "$grub_backup.selinux" \
        || die "cannot back up $ONIONARMOR_MAC_SELINUX_CONFIG"
      tmp="$ONIONARMOR_MAC_SELINUX_CONFIG.onionarmor.$$"
      if grep -qE '^[[:space:]]*SELINUX=' "$ONIONARMOR_MAC_SELINUX_CONFIG"; then
        awk '/^[[:space:]]*SELINUX=/ { print "SELINUX=enforcing"; next } { print }' \
          "$ONIONARMOR_MAC_SELINUX_CONFIG" > "$tmp" \
          || { rm -f "$tmp"; audit_fail_die mac.apply.fail "stage=selinux-awk" "cannot rewrite $ONIONARMOR_MAC_SELINUX_CONFIG"; }
      else
        cat "$ONIONARMOR_MAC_SELINUX_CONFIG" > "$tmp" \
          || { rm -f "$tmp"; die "cannot read $ONIONARMOR_MAC_SELINUX_CONFIG"; }
        printf 'SELINUX=enforcing\n' >> "$tmp"
      fi
      mv "$tmp" "$ONIONARMOR_MAC_SELINUX_CONFIG" \
        || { rm -f "$tmp"; audit_fail_die mac.apply.fail "stage=selinux-move" "cannot replace $ONIONARMOR_MAC_SELINUX_CONFIG"; }
      audit_log mac.apply.selinux "set=SELINUX=enforcing file=$ONIONARMOR_MAC_SELINUX_CONFIG"
      info "set SELINUX=enforcing in $ONIONARMOR_MAC_SELINUX_CONFIG (backup: $grub_backup.selinux)"
      changes="${changes}selinux-enforcing "
      reboot_required=1
    else
      warn "selinux config not writable ($ONIONARMOR_MAC_SELINUX_CONFIG) — cannot set enforcing (run as root)"
    fi
  else
    warn "selinux config not found/readable ($ONIONARMOR_MAC_SELINUX_CONFIG) — skipping enforcing step"
  fi

  # 3. Verify (default on): config requests enforcing.
  if [ "$MAC_VERIFY" -eq 1 ]; then
    if [ "$(mac_se_config_mode)" = "enforcing" ]; then
      info "verify: SELINUX=enforcing is set in the config"
    else
      warn "verify: SELINUX is not enforcing in the config"; verify_failed=1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Record what this apply did, for audit + revert.
# ---------------------------------------------------------------------------
{
  printf 'lsm=%s\n' "$lsm"
  printf 'changes=%s\n' "$(printf '%s' "$changes" | sed 's/ *$//')"
  printf 'grub_modified=%s\n' "$([ "$reboot_required" -eq 1 ] && [ "$lsm" = "apparmor" ] && echo 1 || echo 0)"
} > "$state_path" 2>/dev/null \
  || warn "could not write apply state to $state_path"

audit_log mac.apply.done "lsm=$lsm changes=$(printf '%s' "$changes" | sed 's/ *$//') verify_failed=$verify_failed reboot_required=$reboot_required"

cat <<EOF

[mac-profile-install] applied.
  LSM       : $lsm
  changes   : $(printf '%s' "${changes:-none}" | sed 's/ *$//')
  state     : $state_path
EOF

if [ "$reboot_required" -eq 1 ]; then
  cat >&2 <<EOF

============================================================
REBOOT REQUIRED
============================================================
EOF
  if [ "$lsm" = "apparmor" ]; then
    printf 'AppArmor kernel cmdline (%s) has been staged in %s.\n' "$ONIONARMOR_MAC_GRUB_TOKENS" "$ONIONARMOR_GRUB_FILE" >&2
    printf 'It takes effect on next reboot. Run update-grub if your distro needs it.\n' >&2
  else
    printf 'SELINUX=enforcing has been staged in %s.\n' "$ONIONARMOR_MAC_SELINUX_CONFIG" >&2
    printf 'Switching to enforcing may require a filesystem relabel and a reboot.\n' >&2
  fi
  cat >&2 <<EOF
onionarmor does NOT reboot or relabel automatically.
============================================================
EOF
fi

cat <<EOF

Check status any time:  onionarmor audit  --module mac-profile-install
Relax the posture:      onionarmor revert --module mac-profile-install
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above (host is permissive, not broken)"; exit 2; }
