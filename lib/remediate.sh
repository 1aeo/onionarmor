# shellcheck shell=bash
# lib/remediate.sh — drive module remediation from an onionauditor scorecard.
#
# `onionarmor remediate --from-audit <scorecard.json>` reads an onionauditor
# JSON scorecard, maps each actionable finding (status fail|warn) to the
# onionarmor module that fixes its category, and prints an ORDERED apply plan.
# With --apply it runs each module's apply in that order.
#
# The join key is the auditor's `category` field (kernel-sysctl, ssh-hardness,
# accounts, …). A future auditor that emits a structured `remediation.module`
# per finding is honoured too: when `remediation` is an object with a `module`,
# that wins over the category map (forward-compatible with the richer schema).
#
# JSON parsing uses jq (overridable via ONIONARMOR_JQ_CMD). jq is a tiny,
# ubiquitous dependency and the right tool for JSON — far more robust than an
# awk hand-roll. remediate is an operator-driver command, not something that
# runs on the minimal relay itself, so the dependency is cheap.
#
# Kept bash-3.2 clean (no associative arrays) so it runs anywhere the rest of
# onionarmor does.

: "${ONIONARMOR_JQ_CMD:=jq}"
# Optional test/automation hook: a command that takes a module name and applies
# it. Defaults to invoking this same CLI's `apply --module <name>`.
: "${ONIONARMOR_REMEDIATE_RUNNER:=}"

# remediate_module_for_category <category> -> the onionarmor module that
# remediates that auditor category (empty if none maps).
remediate_module_for_category() {
  case "$1" in
    ssh-hardness)               printf 'ssh-hardening' ;;
    accounts)                   printf 'account-hygiene' ;;
    tor-config|tor-data-dirs)   printf 'tor-config-baseline' ;;
    apparmor-selinux)           printf 'mac-profile-install' ;;
    package-hygiene)            printf 'package-minimization' ;;
    kernel-sysctl)              printf 'kernel-hardening' ;;
    firewall)                   printf 'firewall-default-deny' ;;
    service-inventory)          printf 'service-inventory' ;;
    systemd-tor-units)          printf 'systemd-hardening' ;;
    time-ntp|time-drift)        printf 'chrony-pinning' ;;
    *)                          printf '' ;;
  esac
}

# remediate_rank <module> -> apply-order rank (lower = earlier). Encodes the
# hard ordering constraints:
#   * kernel-hardening is safe to apply any time -> first.
#   * firewall-default-deny BEFORE service-inventory (close the surface, then
#     inventory what is left listening).
#   * ssh-hardening LAST: verify every other posture is healthy before taking on
#     the one change that can lock the operator out.
remediate_rank() {
  case "$1" in
    kernel-hardening)       printf '10' ;;
    firewall-default-deny)  printf '20' ;;
    service-inventory)      printf '30' ;;
    mac-profile-install)    printf '40' ;;
    package-minimization)   printf '45' ;;
    unattended-upgrades)    printf '46' ;;
    chrony-pinning)         printf '47' ;;
    systemd-hardening)      printf '50' ;;
    account-hygiene)        printf '60' ;;
    tor-config-baseline)    printf '70' ;;
    ssh-hardening)          printf '99' ;;
    *)                      printf '55' ;;
  esac
}

# remediate_run_module <module>: apply one module (default: self `apply`).
remediate_run_module() {
  local m=$1
  if [ -n "$ONIONARMOR_REMEDIATE_RUNNER" ]; then
    # shellcheck disable=SC2086  # RUNNER may be "cmd arg" — intentional split
    $ONIONARMOR_REMEDIATE_RUNNER "$m"
  else
    bash "$ONIONARMOR_PREFIX/bin/onionarmor" apply --module "$m"
  fi
}

# remediate_extract <scorecard>: emit one TSV row per actionable finding:
#   category <TAB> status <TAB> severity <TAB> name <TAB> explicit-module <TAB> detail
#
# Interior fields that can be empty (severity, explicit-module) are emitted as a
# "-" placeholder: `read` with a TAB IFS treats tab as whitespace and COLLAPSES
# an empty interior field, which would shift every later column left. The caller
# maps "-" back to empty. @tsv guarantees no literal tab/newline inside a field,
# so the only tabs are real delimiters.
remediate_extract() {
  "$ONIONARMOR_JQ_CMD" -r '
    .findings[]
    | select(.status == "fail" or .status == "warn")
    | [ .category,
        .status,
        (.severity // "-"),
        .name,
        ( .remediation | if type == "object" then (.module // "-") else "-" end),
        ( .detail // "-" )
      ]
    | @tsv
  ' "$1"
}

# remediate_meta <scorecard> <field>: print a top-level scalar (host/profile/…).
remediate_meta() {
  "$ONIONARMOR_JQ_CMD" -r --arg f "$2" '.[$f] // "?"' "$1"
}
