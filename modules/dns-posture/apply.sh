#!/usr/bin/env bash
# MODULE: DNS posture — local validating DoT resolver (unbound + DNSSEC), systemd-resolved masked.
#
# apply.sh — bring DNS under the 1aeo fleet posture. Idempotent; supports
# --dry-run. Never duplicates the DNSSEC trust anchor (the bug that crashed
# three hosts): the anchor is declared exactly once, deferring to Debian's
# stock root-auto-trust-anchor-file.conf when present.

set -euo pipefail

_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$_here/lib.sh"

dns_parse_flags "$@"

snippet=$(dns_snippet_path)
backup=$(dns_resolv_backup)

# ---------------------------------------------------------------------------
# Dry run: print the plan + rendered config, change nothing.
# ---------------------------------------------------------------------------
if [ "$DNS_DRY_RUN" -eq 1 ]; then
  info "dry-run: dns-posture (no host changes)"
  cat <<EOF

PLAN
  unbound snippet     -> $snippet
  resolv.conf         -> $DNS_RESOLV_CONF (backup: $backup)
  listen              -> $(dns_interface_addrs | paste -sd, - | tr ',' ' ') port $DNS_LISTEN_PORT
  upstreams (DoT/853) -> $(printf '%s' "$DNS_UPSTREAMS" | tr ',' ' ')
  DNSSEC              -> $([ "$DNS_DNSSEC" -eq 1 ] && echo on || echo off)
  anchor file         -> $DNS_ANCHOR_FILE (bootstrap: $([ "$DNS_BOOTSTRAP_ANCHOR" -eq 1 ] && echo yes || echo no))
  mask systemd-resolved -> $([ "$DNS_MASK_RESOLVED" -eq 1 ] && echo yes || echo no)
  immutable resolv.conf -> $([ "$DNS_IMMUTABLE_RESOLV" -eq 1 ] && echo yes || echo no)

--- unbound snippet ($snippet) ---
$(dns_render_snippet)

--- resolv.conf ($DNS_RESOLV_CONF) ---
$(dns_render_resolv_conf)
EOF
  exit 0
fi

audit_log dns.apply.start "listen=$DNS_LISTEN:$DNS_LISTEN_PORT dnssec=$DNS_DNSSEC mask_resolved=$DNS_MASK_RESOLVED"

# ---------------------------------------------------------------------------
# 1. Ensure unbound is installed (skip when its tooling is already on PATH).
# ---------------------------------------------------------------------------
if ! command -v "$ONIONARMOR_DNS_UNBOUND_CHECKCONF" >/dev/null 2>&1; then
  info "unbound not found — installing via apt"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_DNS_APT" update \
    || audit_fail_die dns.apply.fail "stage=apt-update" "apt-get update failed"
  DEBIAN_FRONTEND=noninteractive "$ONIONARMOR_DNS_APT" install -y --no-install-recommends \
    unbound ca-certificates dns-root-data \
    || audit_fail_die dns.apply.fail "stage=apt-install" "apt-get install unbound failed"
fi
mkdir -p "$ONIONARMOR_DNS_UNBOUND_CONFD"

# ---------------------------------------------------------------------------
# 2. DNSSEC trust anchor: bootstrap if missing, then verify present + owned.
#    We never write a second auto-trust-anchor-file line (see lib + README).
# ---------------------------------------------------------------------------
if [ "$DNS_DNSSEC" -eq 1 ]; then
  if [ ! -e "$DNS_ANCHOR_FILE" ]; then
    if [ "$DNS_BOOTSTRAP_ANCHOR" -eq 1 ]; then
      [ -r "$ONIONARMOR_DNS_ANCHOR_SOURCE" ] \
        || audit_fail_die dns.apply.fail "stage=anchor" \
             "anchor missing and source $ONIONARMOR_DNS_ANCHOR_SOURCE not readable (install the dns-root-data package)"
      mkdir -p "$(dirname "$DNS_ANCHOR_FILE")"
      "$ONIONARMOR_DNS_INSTALL" -o unbound -g unbound -m 0644 \
        "$ONIONARMOR_DNS_ANCHOR_SOURCE" "$DNS_ANCHOR_FILE" \
        || audit_fail_die dns.apply.fail "stage=anchor" "failed to bootstrap anchor $DNS_ANCHOR_FILE"
      audit_log dns.apply.anchor "bootstrapped=$DNS_ANCHOR_FILE from=$ONIONARMOR_DNS_ANCHOR_SOURCE"
      info "bootstrapped DNSSEC anchor: $DNS_ANCHOR_FILE"
    else
      audit_fail_die dns.apply.fail "stage=anchor" \
        "DNSSEC anchor $DNS_ANCHOR_FILE missing and --no-bootstrap-anchor set"
    fi
  fi
  [ -e "$DNS_ANCHOR_FILE" ] \
    || audit_fail_die dns.apply.fail "stage=anchor" "DNSSEC anchor still missing: $DNS_ANCHOR_FILE"
  owner=$(dns_file_owner "$DNS_ANCHOR_FILE")
  if [ "$owner" != "unbound:unbound" ]; then
    audit_fail_die dns.apply.fail "stage=anchor" \
      "anchor $DNS_ANCHOR_FILE owned '$owner', expected 'unbound:unbound' — fix with: install -o unbound -g unbound -m 0644 $ONIONARMOR_DNS_ANCHOR_SOURCE $DNS_ANCHOR_FILE"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Write the managed unbound snippet (idempotent: skip if byte-identical).
# ---------------------------------------------------------------------------
rendered=$(dns_render_snippet)
if [ -f "$snippet" ] && [ "$(cat "$snippet")" = "$rendered" ]; then
  info "unbound snippet already current: $snippet"
else
  tmp="$snippet.tmp.$$"
  printf '%s\n' "$rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$snippet" || die "cannot move $tmp -> $snippet"
  audit_log dns.apply.snippet "wrote=$snippet"
  info "wrote unbound snippet: $snippet"
fi

# Guard against the duplicate-anchor bug before we ever (re)start unbound.
anchor_lines=$(dns_count_anchor_lines)
if [ "$anchor_lines" -gt 1 ]; then
  audit_fail_die dns.apply.fail "stage=anchor-dup" \
    "found $anchor_lines auto-trust-anchor-file declarations under $ONIONARMOR_DNS_UNBOUND_CONFD — exactly one is allowed (duplicate anchor crashes unbound)"
fi

# ---------------------------------------------------------------------------
# 4. Validate the whole config before touching the running resolver.
# ---------------------------------------------------------------------------
if ! "$ONIONARMOR_DNS_UNBOUND_CHECKCONF" >/dev/null 2>&1; then
  # Surface the real error to the operator, then fail.
  "$ONIONARMOR_DNS_UNBOUND_CHECKCONF" >&2 2>&1 || true
  audit_fail_die dns.apply.fail "stage=checkconf" "unbound-checkconf rejected the config; snippet left at $snippet"
fi

# ---------------------------------------------------------------------------
# 5. (Re)start unbound so the posture is live BEFORE the DNS cutover.
# ---------------------------------------------------------------------------
"$ONIONARMOR_DNS_SYSTEMCTL" enable --now unbound >/dev/null 2>&1 || true
unbound_restart_failed=0
"$ONIONARMOR_DNS_SYSTEMCTL" restart unbound >/dev/null 2>&1 \
  || { warn "could not restart unbound via systemctl — a running instance may still be serving the OLD config"; unbound_restart_failed=1; }

# ---------------------------------------------------------------------------
# 6. Pin resolv.conf at the local resolver (back up the original ONCE).
# ---------------------------------------------------------------------------
mkdir -p "$ONIONARMOR_DNS_STATE_DIR"
if [ ! -e "$backup" ] && [ -e "$DNS_RESOLV_CONF" ]; then
  # cp -L derefs a systemd-resolved symlink so the backup is real content.
  cp -L "$DNS_RESOLV_CONF" "$backup" 2>/dev/null || cp "$DNS_RESOLV_CONF" "$backup"
  audit_log dns.apply.resolv-backup "from=$DNS_RESOLV_CONF to=$backup"
  info "backed up original resolv.conf -> $backup"
fi

resolv_rendered=$(dns_render_resolv_conf)
resolv_current=""
[ -f "$DNS_RESOLV_CONF" ] && [ ! -L "$DNS_RESOLV_CONF" ] && resolv_current=$(cat "$DNS_RESOLV_CONF")
if [ "$resolv_current" = "$resolv_rendered" ]; then
  info "resolv.conf already pinned: $DNS_RESOLV_CONF"
else
  # Clear any prior immutability so we can replace it, and drop a symlink.
  "$ONIONARMOR_DNS_CHATTR" -i "$DNS_RESOLV_CONF" >/dev/null 2>&1 || true
  [ -L "$DNS_RESOLV_CONF" ] && rm -f "$DNS_RESOLV_CONF"
  tmp="$DNS_RESOLV_CONF.tmp.$$"
  printf '%s\n' "$resolv_rendered" > "$tmp" || die "cannot write $tmp"
  mv "$tmp" "$DNS_RESOLV_CONF" || die "cannot move $tmp -> $DNS_RESOLV_CONF"
  audit_log dns.apply.resolv "wrote=$DNS_RESOLV_CONF"
  info "pinned resolv.conf -> $DNS_RESOLV_CONF"
fi

if [ "$DNS_IMMUTABLE_RESOLV" -eq 1 ]; then
  "$ONIONARMOR_DNS_CHATTR" +i "$DNS_RESOLV_CONF" >/dev/null 2>&1 \
    && info "set immutable bit on $DNS_RESOLV_CONF" \
    || warn "could not set immutable bit on $DNS_RESOLV_CONF (chattr unavailable?)"
fi

# ---------------------------------------------------------------------------
# 7. Mask + stop systemd-resolved (and reap stragglers).
# ---------------------------------------------------------------------------
if [ "$DNS_MASK_RESOLVED" -eq 1 ]; then
  "$ONIONARMOR_DNS_SYSTEMCTL" disable --now systemd-resolved >/dev/null 2>&1 || true
  "$ONIONARMOR_DNS_SYSTEMCTL" mask systemd-resolved >/dev/null 2>&1 \
    || warn "could not mask systemd-resolved"
  "$ONIONARMOR_DNS_PKILL" -x systemd-resolved >/dev/null 2>&1 || true
  audit_log dns.apply.mask-resolved "masked=systemd-resolved"
  info "masked + stopped systemd-resolved"
fi

# ---------------------------------------------------------------------------
# 8. Verify (default on). Failures are surfaced but do not unwind the apply.
# A failed unbound restart counts as a failure even when --no-verify is set:
# the new config was never loaded, so apply must not exit 0.
# ---------------------------------------------------------------------------
verify_failed=$unbound_restart_failed
if [ "$DNS_VERIFY" -eq 1 ]; then
  if "$ONIONARMOR_DNS_UNBOUND_CHECKCONF" >/dev/null 2>&1; then
    info "verify: unbound-checkconf ok"
  else
    warn "verify: unbound-checkconf FAILED"; verify_failed=1
  fi

  fwd=$("$ONIONARMOR_DNS_UNBOUND_CONTROL" list_forwards 2>/dev/null || true)
  case "$(dns_forwards_classify "$fwd")" in
    only-dot) info "verify: forwarders are DoT/:853 only" ;;
    has-do53) warn "verify: a non-DoT (:53) forwarder is present"; verify_failed=1 ;;
    none)     warn "verify: list_forwards reports no forwarders"; verify_failed=1 ;;
  esac

  if [ "$DNS_DNSSEC" -eq 1 ]; then
    stub=$(dns_stub_addrs | head -1)
    dig_out=$("$ONIONARMOR_DNS_DIG" "@$stub" -p "$DNS_LISTEN_PORT" +dnssec cloudflare.com A 2>/dev/null || true)
    if printf '%s\n' "$dig_out" | grep -qE 'flags:[^;]* ad'; then
      info "verify: DNSSEC ad flag present"
    else
      warn "verify: DNSSEC ad flag NOT seen in dig answer"; verify_failed=1
    fi
  fi
fi

audit_log dns.apply.done "verify_failed=$verify_failed"

cat <<EOF

[dns-posture] applied.
  unbound snippet : $snippet
  resolv.conf     : $DNS_RESOLV_CONF (backup: $backup)
  upstreams       : $(printf '%s' "$DNS_UPSTREAMS" | tr ',' ' ')
  DNSSEC          : $([ "$DNS_DNSSEC" -eq 1 ] && echo on || echo off)
  systemd-resolved: $([ "$DNS_MASK_RESOLVED" -eq 1 ] && echo masked || echo untouched)

Check status any time:  onionarmor audit  --module dns-posture
Undo the posture:       onionarmor revert --module dns-posture
EOF

[ "$verify_failed" -eq 0 ] || { warn "apply finished but verification reported problems above"; exit 2; }
