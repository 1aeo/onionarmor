# Security policy

`onionarmor` is a host-hardening toolkit: the **apply-side** counterpart to
the read-only sister tools `onionwarden` (monitor/detect drift) and
`onionleak` (audit relay metadata). Where those two only observe, `onionarmor`
mutates — it applies kernel/sysctl posture and, gated separately, stages GRUB
kernel-lockdown. Because it changes host state, its trust model and blast
radius matter, and this document states them explicitly.

This document covers the threat model, the DNS posture `onionarmor` assumes of
its hosts, the trust boundaries it ships hardened by default, and how to
report a vulnerability.

## Threat model

`onionarmor` reduces a host's **kernel and boot attack surface** on
Debian 12+/Ubuntu 22.04+ relay-fleet machines. It is a thin, auditable mutator
with safety rails, not a runtime defender.

### What it addresses

- **Kernel attack-surface reduction.** Applies a complete, role-pinned set of
  25 security-relevant sysctls (CIS Debian 12 / RHEL 9 STIG / Linux kernel
  docs) so an attacker has fewer kernel primitives to reach: hidden kernel
  pointers (`kernel.kptr_restrict`), restricted `dmesg`
  (`kernel.dmesg_restrict`), disabled unprivileged BPF
  (`kernel.unprivileged_bpf_disabled`), and the rest of the tracked posture.
- **Sysctl misconfiguration / drift.** `diff` flags every live value that has
  drifted from the role target (`ok` / `DRIFT` / `missing`); `apply` writes a
  single managed `/etc/sysctl.d/99-onionarmor-<role>.conf` so posture is
  declarative and reproducible rather than accreted by hand.
- **Untrusted USB / FireWire (DMA) devices.** Posture keys blunt hot-plug and
  DMA-capable peripheral attack vectors as part of the tracked sysctl set.
- **Unsigned kernel-module loading.** The `receiver` role recommends staging
  `lockdown=integrity`, which blocks loading unsigned kernel modules; the
  posture also constrains module-load surface via the tracked keys.
- **GRUB / boot-cmdline tampering.** `apply-lockdown` is the *only* path that
  edits `/etc/default/grub`; it brackets that edit with a `REBOOT REQUIRED`
  warning and never auto-reboots, so a boot-line change is always an explicit,
  audited operator action.

### What it does NOT address

- **Application-level vulnerabilities.** A bug in a service running on the host
  (tor, a web app, a model endpoint) is out of scope — `onionarmor` hardens
  the kernel/boot surface beneath the application, not the application.
- **Network-layer DDoS.** Volumetric or connection-exhaustion attacks against
  the host's services are not a posture-tuning problem and are out of scope.
- **Social engineering.** Tricking an operator into running a malicious
  command, handing over credentials, or disabling protections is outside the
  toolkit's reach.
- **Already-resident kernel rootkit.** Once the kernel is owned, sysctl
  posture cannot be trusted to mean what it says. `onionarmor` raises the bar
  to *get* there; it does not evict an attacker who already has ring 0.
- **Physical attacks and firmware/hypervisor compromise** below the OS.

### Trust boundaries

- `onionarmor` runs as **root** to write `/etc/sysctl.d/`, call
  `sysctl --system`, and (separately) edit GRUB. It trusts the role configs
  shipped in this repo and the host's `/etc/onionarmor/role.conf`.
- Recommendations are **pinned in this repo's role configs**, not read from
  `onionwarden` at runtime — an upstream change to the reference list cannot
  silently change apply behaviour.
- The operator is trusted to declare the host's role correctly; the
  role.conf cross-check (below) catches the common *mistake*, not a malicious
  operator.

## DNS posture

`onionarmor` itself performs no name resolution at apply time — it is a local,
offline mutator. The DNS posture below is part of the **fleet baseline** it
hardens *toward*: relay, receiver, and eval hosts all depend on trustworthy
DNS (relays for directory/exit resolution, receivers for ingest, eval hosts
for upstream fetches), and a poisoned resolver undermines every other control.

`onion-{warden,armor,leak}` assumes the host runs DNS through a local
validating resolver, not plain UDP/53 to the network operator. Recommended
posture:

1. **Local validator**: `unbound` listening on `127.0.0.1:53` with
   `tls-upstream: yes` and `do-tcp: yes`.
2. **DoT upstreams** (port 853, TLS-pinned hostnames): pick two or more from
   diverse providers (e.g. `1.1.1.1@853#cloudflare-dns.com` +
   `9.9.9.9@853#dns.quad9.net` + `8.8.8.8@853#dns.google`).
3. **DNSSEC**: trust anchor pinned at `/var/lib/unbound/root.key`
   (auto-bootstrapped via `unbound-anchor` then ownership-fixed to
   `unbound:unbound`).
4. **`/etc/resolv.conf` is a real file** pointing only to `127.0.0.1` — not a
   symlink to `systemd-resolved`, which we observed leaking memory under
   sustained high parallel DNS load.
5. **`systemd-resolved` stopped and masked** (`systemctl stop systemd-resolved
   && systemctl mask systemd-resolved`). Prefer this deterministic
   stop-then-mask over a broad `pkill -f`, which can match unrelated processes.
6. **No fallback to plain Do53** — confirm via `unbound-control list_forwards`
   showing only `853` ports.

This is the exact posture onionleak's fleet rolled out across all 6 hosts
after a `systemd-resolved` leak under parallel ExoneraTor enrichment. A future
`onionarmor` role addition that tracks resolver posture would target precisely
this configuration.

## Hardened defaults

`onionarmor` ships conservative, opt-in-to-mutate defaults — its blast radius
is bounded by design:

- **Phase 1: sysctl tunings only.** The current release applies *only* sysctl
  posture — 25 keys, no kernel-module surgery, no service changes. Each key in
  a role config carries `# DOC:` (what it does), `# REF:` (CIS Debian 12 /
  RHEL 9 STIG / kernel docs), and `# COMPAT:` (known gotchas), so every applied
  value is self-documenting and reversible.
- **Kernel lockdown documented but gated.** `lockdown=integrity` is described
  and stageable but **never applied by `apply`**. It lives behind a separate
  `apply-lockdown` subcommand because it requires a GRUB cmdline edit plus a
  reboot. `apply-lockdown` prints `REBOOT REQUIRED` and never auto-reboots.
- **Three role profiles, each a complete posture (not a delta).** Every role
  fully describes the host's expected state across all 25 keys:
  - `tor-relay` — full baseline, no exceptions.
  - `receiver` — baseline plus a recommendation to run `apply-lockdown` after
    `apply` (lockdown blocks unsigned-module load on the next boot).
  - `eval-host` (the general/compute profile) — baseline with
    `kernel.kexec_load_disabled=0` so nested-KVM guest workloads can run.
- **Safety rails on every mutation:**
  - `apply` refuses without `--role`, and refuses unless
    `/etc/onionarmor/role.conf` matches the `--role` flag (prevents applying a
    relay posture to the wrong host).
  - The prior managed file is backed up (`…conf.bak.<UTC-ts>`) before every
    write; `rollback` restores the most recent backup and reloads.
  - `apply --first-run` requires an interactive `yes` before the first write.
  - Applies are **convergent** — a no-change re-run writes zero `apply.change`
    audit entries. (The managed file is rewritten unconditionally with a fresh
    `# Written:` header timestamp, and a backup is taken on every apply, so the
    file is not byte-identical run-to-run, but its sysctl posture does not
    change.)
  - Every apply, backup, and rollback is appended to
    `/var/log/onionarmor/audit.log` with timestamp, operator, and details. The
    log is a plain append-only record, not cryptographically tamper-evident;
    treat it as an operator audit trail, not an integrity control.

## Reporting a vulnerability

Report security issues privately through either channel:

- **GitHub private vulnerability reporting** — open the repository's **Security**
  tab and choose **Report a vulnerability**. This is the preferred channel: it
  is always available on the repo and keeps the report private until disclosure.
- **Email** — **security@1aeo.com**.

Please include:

- the affected component (file/path) and version,
- a description of the issue and its impact under the threat model above,
- reproduction steps or a proof-of-concept where possible.

Do not open a public issue for an unfixed vulnerability. We aim to acknowledge
reports promptly and will coordinate disclosure timing with the reporter.
