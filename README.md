# onionarmor

> **Apply kernel + network hardening to Ubuntu/Debian Tor-relay fleets — idempotently, with a backup and one-command rollback for every change.**

`onionarmor` is a single self-contained Bash CLI. Everything it can harden
follows the same three verbs, so nothing it does is one-way:

- **`apply`** — put a posture in place (backs up what it replaces first),
- **`audit`** — check whether it's still in place (green / yellow / red),
- **`revert`** / **`rollback`** — undo it from the backup.

It's the apply-side of a read-only monitoring pair: [`onionwarden`](https://github.com/1aeo/onionwarden)
detects drift from CIS / RHEL-STIG / kernel-doc baselines, and onionarmor closes
the gap — deliberately, never automatically. → [Why a separate tool](docs/architecture.md#why-a-separate-apply-tool)

## Contents

- [Install](#install)
- [Quick start (5 minutes)](#quick-start-5-minutes)
- [Try a module: dns-posture](#try-a-module-dns-posture)
- [Commands](#commands)
- [Roles](#roles) · [Modules](#modules) · [Safety rails](#safety-rails)
- [Docs](#docs)

## Install

```sh
curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh | sudo bash
```

Idempotent and conservative: it installs onionarmor onto `PATH` but **never**
applies a posture or touches the kernel on its own — that stays a deliberate
operator step. Prefer to pin and review a revision before running as root, or
install manually? → [Install guide](docs/install.md)

## Quick start (5 minutes)

Everything in steps 1–3 is **read-only** — look before you touch.

```sh
# 1. Declare this host's role once (a safety cross-check, see Safety rails).
sudo mkdir -p /etc/onionarmor
echo 'role=tor-relay' | sudo tee /etc/onionarmor/role.conf

# 2. See the target posture, then how the live kernel differs (read-only).
onionarmor list --role tor-relay        # the 25 target sysctls + values
onionarmor diff --role tor-relay        # marks each key ok / DRIFT / missing

# 3. Preview the apply — changes nothing.
sudo onionarmor apply --role tor-relay --dry-run

# 4. Apply for real (first time asks for an interactive 'yes').
sudo onionarmor apply --role tor-relay --first-run

# 5. Review every change ever made on this host.
sudo onionarmor audit

# 6. Changed your mind? Roll back to the previous managed file.
sudo onionarmor rollback --role tor-relay
```

After the first apply, subsequent applies don't need `--first-run`:
`sudo onionarmor apply --role tor-relay`.

> Pick the role that matches the host: `tor-relay`, `eval-host`, or `receiver`.
> They differ only in a couple of exceptions. → [Roles](docs/roles.md)

## Try a module: dns-posture

Modules are optional, self-contained postures applied with `--module`. The same
`apply` / `audit` / `revert` rhythm applies — and every module previews itself
with `--dry-run`. Here's the full safe loop on `dns-posture` (a local validating
DNS-over-TLS resolver):

```sh
# 1. Preview — prints the full plan + rendered config, changes nothing.
sudo onionarmor apply --module dns-posture --dry-run

# 2. Apply it.
sudo onionarmor apply --module dns-posture

# 3. Check status any time (exits non-zero if anything is red).
onionarmor audit --module dns-posture
```

```text
$ onionarmor audit --module dns-posture

[ ok ] unbound active             systemctl is-active unbound = active
[ ok ] single trust anchor        exactly 1 auto-trust-anchor-file
[ ok ] resolv.conf pinned         real file, nameserver 127.0.0.1
[ ok ] systemd-resolved masked    is-enabled = masked
[ ok ] forwarders DoT-only        all forward-addr are @853
[ ok ] DNSSEC ad flag             validating answer carries the ad flag

onionarmor: audit: all green
```

```sh
# 4. Don't want it? One command puts everything back
#    (restores resolv.conf, unmasks systemd-resolved).
sudo onionarmor revert --module dns-posture
```

Every default (upstreams, DNSSEC, listener, masking) is overridable.
→ [dns-posture README](modules/dns-posture/README.md) · [all modules](#modules)

## Commands

| Command | What it does |
|---|---|
| `list --role <r>` | Print the role's 25 target sysctls + values (read-only). |
| `diff --role <r>` | Show current host values vs target; mark each `ok` / `DRIFT` / `missing`. |
| `apply --role <r>` `[--dry-run]` `[--first-run]` | Apply the role's sysctls. Backs up the prior managed file, writes the new one, runs `sysctl --system`, audits the change. |
| `rollback --role <r>` | Restore the most recent backup of the managed file and reload. |
| `audit` | Print the full audit log (every apply / rollback ever). |
| `apply-lockdown` `[--no-reboot]` | Stage `lockdown=integrity` in the GRUB cmdline (needs a reboot — never auto-reboots). |
| `list-modules` | List installed hardening modules + one-line descriptions. |
| `apply` / `audit` / `revert` `--module <m>` | Apply / status / undo a [module](#modules). |
| `help` | Show usage. Add `--help` after `--module <m>` for that module's flags. |

## Roles

A **role** is a complete kernel-sysctl posture (all 25 tracked keys, not a
delta). Declare one per host; onionarmor keeps it converged.

| Role | For | Exception vs baseline |
|---|---|---|
| `tor-relay` | a Tor relay | none — the full baseline |
| `eval-host` | a model-eval / GPU host | allows `kexec` (nested-KVM workloads) |
| `receiver` | a consensus/metrics receiver | also recommends `apply-lockdown` |

Each key in a role file carries `# DOC:` (what it does), `# REF:` (CIS / STIG /
kernel-doc source), and `# COMPAT:` (gotchas). → [Roles guide](docs/roles.md)

## Modules

Optional postures beyond the sysctl roles. Always dry-run first; every module's
`audit` exits non-zero if anything is red.

| Module | What it does | Risk | Needs |
|---|---|---|---|
| [`dns-posture`](modules/dns-posture/README.md) | Local validating DoT + DNSSEC resolver (`unbound`); masks `systemd-resolved`. | Medium — replaces the system resolver (clean revert) | `unbound` (auto-installed) |
| [`kernel-reserved-ports`](modules/kernel-reserved-ports/README.md) | Reserve the relay's loopback tor ports from the kernel ephemeral pool so an outbound connection can't steal one. | Low — one sysctl drop-in, fully reversible | reads your torrc (`--auto`) |
| [`bgp-hardening`](modules/bgp-hardening/README.md) | Bind FRR `bgpd` to a specific peer-facing IP; opt-in `tcp/179` firewall, RPKI, GTSM. | Medium — restarts `bgpd` (graceful) | FRR under `/etc/frr` |

→ [How modules work + authoring guide](docs/modules.md)

## Safety rails

1. **No `apply` without `--role`** — and the host's `/etc/onionarmor/role.conf`
   must declare that same role (so a relay posture can't land on a workstation).
2. **Backup before every write**, with timestamped `.bak` files; `rollback`
   restores the latest.
3. **First-run confirmation** — `apply --first-run` needs an interactive `yes`.
4. **Convergent & idempotent** — re-applying with no config change is a no-op.
5. **Reboot-gated items stay manual** — kernel lockdown is never applied by
   `apply`, and `apply-lockdown` never auto-reboots.
6. **Append-only audit log** at `/var/log/onionarmor/audit.log` (a plain
   operator trail, not cryptographically signed).

→ [Full safety-rail details](docs/architecture.md#safety-rails-full-list) · [SECURITY.md](SECURITY.md)

## Docs

| Doc | What's in it |
|---|---|
| [Install guide](docs/install.md) | One-liner, manual install, pinning a revision, env knobs, uninstall. |
| [Roles](docs/roles.md) | The three roles, role-file format, the 25 sysctls, reference data. |
| [Modules](docs/modules.md) | How modules work, the catalog, reading audit output, authoring a module. |
| [Troubleshooting](docs/troubleshooting.md) | The common first-run snags and their fixes. |
| [Architecture](docs/architecture.md) | The three-tool split, status/roadmap, safety rails, repo layout, tests. |
| [SECURITY.md](SECURITY.md) | Threat model and the audit log's guarantees. |

## License

MIT — see [LICENSE](LICENSE).
