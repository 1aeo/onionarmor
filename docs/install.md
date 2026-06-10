# Installing onionarmor

`onionarmor` is a self-contained Bash CLI. Pick whichever install fits your
trust model. For the fast path, see [Install in the README](../README.md#install).

## Requirements

- Debian 12+ or Ubuntu 22.04+ (the installer refuses other distros).
- Kernel ≥ 5.13 for the full role posture: `kernel.unprivileged_bpf_disabled=2` landed in 5.13 (commit `08389d888287`). The installer itself only refuses kernels older than 5.2 (its `ONIONARMOR_INSTALL_MIN_KERNEL` floor) — 5.2–5.12 install fine but can't take that one key's hardened value. Debian 12 and Ubuntu 22.04+ ship 5.15 or newer, so this only bites unusually old kernels.
- `bash` 4+, plus `awk` and `sysctl` (the installer `apt-get install`s anything missing).
- `root` (the tool writes `/etc`, `/opt`, and `/usr/local/sbin`).

## Option A — one-liner installer (recommended)

```sh
curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh | sudo bash
```

The installer is conservative and idempotent (safe to re-run). It:

- refuses to run as non-root, on a non-Debian/Ubuntu distro, on too-old a bash, or on a kernel too old for the role sysctl keys (≥ 5.2);
- `apt-get install`s any missing prerequisites;
- clones (or updates) the repo into `/opt/onionarmor` and symlinks `onionarmor` onto `PATH` at `/usr/local/sbin/onionarmor`;
- **never** applies a role posture and **never** stages GRUB kernel lockdown on its own — both stay deliberate, opt-in operator steps. It only prints the next steps.

### Pin and review before running as root

Piping branch-tip code into `sudo bash` is convenient but non-reproducible. To
pin and review a fixed revision first:

```sh
curl -sSLO https://raw.githubusercontent.com/1aeo/onionarmor/<tag-or-sha>/install.sh
less install.sh                                   # review before running
sudo ONIONARMOR_REPO_REF=<tag-or-sha> bash install.sh
```

### Install and apply a role in one run

To also declare the host role and run a first apply in the same step, set
`ONIONARMOR_INSTALL_ROLE`:

```sh
curl -sSL https://raw.githubusercontent.com/1aeo/onionarmor/main/install.sh \
  | sudo ONIONARMOR_INSTALL_ROLE=tor-relay bash
```

## Option B — manual clone

```sh
git clone https://github.com/1aeo/onionarmor.git /opt/onionarmor
git -C /opt/onionarmor checkout <tag-or-sha>      # pin to a reviewed revision
sudo ln -s /opt/onionarmor/bin/onionarmor /usr/local/sbin/onionarmor
```

`onionarmor` mutates host state as root, so don't track branch tip blindly —
check out a reviewed tag or commit SHA and inspect the diff before putting
`bin/` on `PATH`. No dependencies beyond a POSIX shell, `awk`, `sysctl`, and
(for the optional CI lint) `shellcheck`.

## Installer environment knobs

Operators rarely need these; the bats suite uses them. Full list is in the
header of [`install.sh`](../install.sh).

| Variable | Default | Purpose |
|---|---|---|
| `INSTALL_PREFIX` | `/opt/onionarmor` | install root |
| `SYMLINK_PATH` | `/usr/local/sbin/onionarmor` | CLI symlink location |
| `ONIONARMOR_REPO_REF` | `main` | branch, tag, or commit SHA to check out |
| `ONIONARMOR_REPO_URL` | `https://github.com/1aeo/onionarmor.git` | override the git remote |
| `ONIONARMOR_INSTALL_ROLE` | _(unset)_ | declare role + run a first apply during install |
| `ONIONARMOR_INSTALL_FORCE` | `0` | on update, discard uncommitted local changes in `$INSTALL_PREFIX` |

## Uninstall

```sh
sudo rm /usr/local/sbin/onionarmor      # remove the CLI from PATH
sudo rm -rf /opt/onionarmor             # remove the checkout
```

Removing the CLI does **not** revert applied postures. Revert those first while
the tool is still installed — `sudo onionarmor rollback --role <r>` for sysctls,
`sudo onionarmor revert --module <name>` for each applied module — then remove
the binary. Host config (`/etc/onionarmor`), managed drop-ins
(`/etc/sysctl.d/99-onionarmor-*`), and the audit log
(`/var/log/onionarmor/audit.log`) are left in place for you to remove
deliberately.
