# shellcheck shell=bash
# lib/remediate.sh — `onionarmor remediate --from-audit <score.json>`.
#
# Reads an onionauditor `scan --output json` document, maps each failing/at-risk
# finding's CATEGORY to the onionarmor module that remediates it, prints an
# ordered remediation plan, and (with --apply) runs each module's apply.sh in a
# dependency-safe order.
#
# The auditor finding shape is: { id:"<category>:<name>", category, status, ... }
# with status in {pass,warn,fail,skip}. There is no per-finding "module" field,
# so the mapping lives here, keyed by the auditor's stable category names.

# oa_remediate_table: the ordered category->module plan. One line per module:
#   <module> [<auditor-category>...]
# ORDER IS THE APPLY ORDER and is deliberate:
#   * kernel-hardening first  — pure sysctl uplift, zero behavioural risk.
#   * firewall-default-deny before any service-inventory remediation.
#   * ssh-hardening LAST       — so the operator can confirm every other change
#                                worked before risking the SSH config.
# A module with no auditor category (e.g. mac-profile-install) is intentionally
# absent: nothing in a scan triggers it.
oa_remediate_table() {
  cat <<'EOF'
kernel-hardening kernel-sysctl
chrony-pinning time-ntp
dns-posture tor-dns-resolver
systemd-hardening systemd-tor-units
kernel-reserved-ports
package-minimization package-hygiene
account-hygiene accounts
tor-config-baseline tor-config
firewall-default-deny firewall
ssh-hardening ssh-hardness
EOF
}

# _oa_remediate_categories: every auditor category that maps to a module.
_oa_remediate_categories() {
  oa_remediate_table | awk '{ for (i=2;i<=NF;i++) print $i }'
}

# cmd_remediate <args...>: the `remediate` subcommand entrypoint.
cmd_remediate() {
  local src="" mode="dry-run"
  while [ $# -gt 0 ]; do
    case "$1" in
      --from-audit)   src=${2:-}; shift 2 ;;
      --from-audit=*) src=${1#--from-audit=}; shift ;;
      --dry-run)      mode="dry-run"; shift ;;
      --apply)        mode="apply"; shift ;;
      -h|--help)      oa_remediate_usage; return 0 ;;
      *)              die "remediate: unknown argument: $1 (try: onionarmor remediate --help)" ;;
    esac
  done

  command -v jq >/dev/null 2>&1 || die "remediate: jq is required to parse the auditor JSON (apt install jq)"
  [ -n "$src" ] || die "remediate: --from-audit <onionauditor-scan.json> is required (use - for stdin)"

  local json
  if [ "$src" = "-" ]; then
    json=$(cat)
  else
    [ -r "$src" ] || die "remediate: cannot read audit file: $src"
    json=$(cat "$src")
  fi
  printf '%s' "$json" | jq -e . >/dev/null 2>&1 || die "remediate: $src is not valid JSON"

  local host profile grade aggregate
  host=$(printf '%s' "$json" | jq -r '.host // "unknown"')
  profile=$(printf '%s' "$json" | jq -r '.profile // "unknown"')
  grade=$(printf '%s' "$json" | jq -r '.grade // "?"')
  aggregate=$(printf '%s' "$json" | jq -r '.aggregate // "?"')

  # Failing/at-risk findings as "category<TAB>id" (status fail or warn).
  local findings
  findings=$(printf '%s' "$json" \
    | jq -r '.findings[]? | select(.status=="fail" or .status=="warn") | [.category, .id] | @tsv')

  info "remediate plan from $src"
  printf '  host=%s profile=%s grade=%s aggregate=%s\n\n' "$host" "$profile" "$grade" "$aggregate"

  if [ -z "$findings" ]; then
    info "no failing/at-risk findings — nothing to remediate"
    return 0
  fi

  # Build the ordered plan: for each module (in table order), collect the finding
  # ids whose category it handles AND that the module is installed to fix.
  local planned_modules=0 planned_findings=0
  local applied_ok=0 applied_fail=0 applied_skip=0
  local step=0 mod cats idlist count have_mod

  printf '%s\n' "PLAN (apply order — kernel first, ssh last):"
  printf '\n'

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    mod=$(printf '%s' "$line" | awk '{print $1}')
    cats=$(printf '%s' "$line" | cut -s -d' ' -f2-)
    [ -n "$cats" ] || continue

    # Collect finding ids for this module's categories.
    idlist=""
    local c
    for c in $cats; do
      while IFS=$'\t' read -r fcat fid; do
        [ "$fcat" = "$c" ] || continue
        case " $idlist " in *" $fid "*) : ;; *) idlist="$idlist $fid" ;; esac
      done <<EOF
$findings
EOF
    done
    idlist=$(printf '%s' "$idlist" | sed 's/^ *//;s/ *$//')
    [ -n "$idlist" ] || continue

    count=$(printf '%s' "$idlist" | tr ' ' '\n' | grep -c . || true)
    have_mod=yes
    module_is_valid "$mod" || have_mod=no

    step=$((step + 1))
    planned_modules=$((planned_modules + 1))
    planned_findings=$((planned_findings + count))

    if [ "$mod" = "ssh-hardening" ]; then
      printf '  [%d] %-22s <- %-18s (%d finding(s))   [applied LAST]\n' "$step" "$mod" "$cats" "$count"
    else
      printf '  [%d] %-22s <- %-18s (%d finding(s))\n' "$step" "$mod" "$cats" "$count"
    fi
    printf '        addresses: %s\n' "$idlist"
    [ "$have_mod" = no ] && printf '        NOTE: module not installed — will be skipped on --apply\n'
  done <<EOF
$(oa_remediate_table)
EOF

  # Categories present in the scan that map to no module at all.
  local mapped unmapped
  mapped=$(_oa_remediate_categories | sort -u)
  unmapped=$(printf '%s\n' "$findings" | awk -F'\t' '{print $1}' | sort -u \
    | grep -vx -F -f <(printf '%s\n' "$mapped") || true)
  if [ -n "$unmapped" ]; then
    printf '\n  unmapped categories (no onionarmor module): %s\n' "$(printf '%s' "$unmapped" | tr '\n' ' ' | sed 's/ *$//')"
  fi

  printf '\n  %d module(s), %d finding(s) planned.\n' "$planned_modules" "$planned_findings"

  if [ "$mode" = "dry-run" ]; then
    printf '\n  This is a DRY RUN. Re-run with --apply to apply these modules in order.\n'
    return 0
  fi

  # --- apply ----------------------------------------------------------------
  printf '\n'
  audit_log remediate.start "from=$src modules=$planned_modules findings=$planned_findings"
  info "applying $planned_modules module(s) in dependency order"
  printf '\n'

  step=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    mod=$(printf '%s' "$line" | awk '{print $1}')
    cats=$(printf '%s' "$line" | cut -s -d' ' -f2-)
    [ -n "$cats" ] || continue

    idlist=""
    for c in $cats; do
      while IFS=$'\t' read -r fcat fid; do
        [ "$fcat" = "$c" ] || continue
        case " $idlist " in *" $fid "*) : ;; *) idlist="$idlist $fid" ;; esac
      done <<EOF
$findings
EOF
    done
    idlist=$(printf '%s' "$idlist" | sed 's/^ *//;s/ *$//')
    [ -n "$idlist" ] || continue

    step=$((step + 1))
    if ! module_is_valid "$mod"; then
      warn "[$step] $mod: module not installed — SKIPPED (findings: $idlist)"
      audit_log remediate.skip "module=$mod reason=not-installed findings=$idlist"
      applied_skip=$((applied_skip + 1))
      continue
    fi

    info "[$step] applying $mod (addresses: $idlist)"
    local script rc=0
    script=$(module_action_script "$mod" apply)
    if [ "${ONIONARMOR_REMEDIATE_NOOP:-}" = "yes" ]; then
      # Test/inspection hook: record the order without executing module apply.
      printf '%s\n' "$mod" >> "${ONIONARMOR_REMEDIATE_ORDER_LOG:-/dev/null}"
    else
      ONIONARMOR_PREFIX="$ONIONARMOR_PREFIX" ONIONARMOR_AUTO_CONFIRM=yes bash "$script" || rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
      info "[$step] $mod: OK"
      audit_log remediate.apply "module=$mod result=ok findings=$idlist"
      applied_ok=$((applied_ok + 1))
    else
      warn "[$step] $mod: apply exited $rc (continuing; review before re-running)"
      audit_log remediate.apply "module=$mod result=fail rc=$rc findings=$idlist"
      applied_fail=$((applied_fail + 1))
    fi
  done <<EOF
$(oa_remediate_table)
EOF

  audit_log remediate.done "ok=$applied_ok fail=$applied_fail skip=$applied_skip"
  printf '\n'
  info "remediate: applied=$applied_ok failed=$applied_fail skipped=$applied_skip"
  printf '\nRe-scan to confirm the uplift:  onionauditor scan\n'
  [ "$applied_fail" -eq 0 ] || return 2
}

oa_remediate_usage() {
  cat <<'EOF'
onionarmor remediate --from-audit <onionauditor-scan.json> [--dry-run | --apply]

Map an onionauditor scan's failing findings to onionarmor modules and apply them
in a dependency-safe order (kernel-hardening first, ssh-hardening last).

  onionauditor scan --output json > /tmp/score.json
  onionarmor remediate --from-audit /tmp/score.json            # dry-run (plan only)
  onionarmor remediate --from-audit /tmp/score.json --apply    # apply in order
  onionarmor remediate --from-audit - < /tmp/score.json        # read stdin

OPTIONS
  --from-audit <file>   The auditor JSON (or - for stdin). Required.
  --dry-run             Print the plan only (default).
  --apply               Run each mapped module's apply.sh in order.
  -h, --help            This help.
EOF
}
