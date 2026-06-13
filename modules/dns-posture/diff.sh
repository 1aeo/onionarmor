#!/usr/bin/env bash
# diff.sh — read-only preview of the dns-posture posture.
#
# dns-posture's output is a rendered unbound config snippet plus a managed
# /etc/resolv.conf (deterministic for the given flags), so its "diff" compares
# each would-be rendered file to whatever is on disk now and reports
# create / no-change / would-rewrite. PURE READ: renders into memory, compares,
# and writes nothing (no install, no systemctl, no chattr). Exits 0 regardless
# of drift. Use `apply --module dns-posture --dry-run` to see the full rendered
# content.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

dns_parse_flags "$@"

# preview_file <label> <path> <rendered-content> [follow-symlinks]:
# Print one status row. When follow-symlinks=yes, mirrors oa_write_if_changed
# logic (-f follows symlinks, compares target bytes). When no (default), a
# symlink is always flagged for replacement (matching resolv.conf apply behavior).
preview_file() {
  local label=$1 path=$2 rendered=$3 follow_symlinks=${4:-no} status content
  if [ "$follow_symlinks" = "yes" ]; then
    # Like oa_write_if_changed: -f follows symlinks, compare target content.
    if [ ! -e "$path" ]; then
      status="→ would create"
    elif [ -f "$path" ] && content=$(cat "$path" 2>/dev/null) && [ "$rendered" = "$content" ]; then
      status="(no change)"
    else
      status="→ would rewrite"
    fi
  else
    # Symlinks are always replaced (resolv.conf behavior).
    if [ -L "$path" ]; then
      status="→ would replace symlink"
    elif [ ! -e "$path" ]; then
      status="→ would create"
    elif content=$(cat "$path" 2>/dev/null) && [ "$rendered" = "$content" ]; then
      status="(no change)"
    else
      status="→ would rewrite"
    fi
  fi
  printf '%-18s %-18s %s\n' "$label" "$status" "$path"
}

info "dns-posture diff (read-only preview; no host changes)"
printf '\n%-18s %-18s %s\n' "TARGET" "DELTA" "PATH"
printf '%-18s %-18s %s\n' "------------------" "------------------" "----"

snippet=$(dns_render_snippet)
preview_file "unbound snippet" "$(dns_snippet_path)" "$snippet" "yes"

# resolv.conf is always managed by apply (pinned to the local resolver).
resolv=$(dns_render_resolv_conf)
preview_file "resolv.conf" "$DNS_RESOLV_CONF" "$resolv"

printf '\nPreview only — nothing was written.\n'
printf 'Full render: onionarmor apply --module dns-posture --dry-run\n'
