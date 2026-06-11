# Module: `mac-profile-install`

**Install + enforce a Mandatory Access Control LSM — AppArmor on Debian/Ubuntu, SELinux on RHEL/CentOS/Fedora — and put the tor profile under enforcement.**

`mac-profile-install` brings the host under a kernel-enforced Mandatory Access
Control (MAC) layer so a compromised `tor` (or any confined service) is boxed
into what its policy allows, instead of having the full privileges of its user.
It detects the distro family from `/etc/os-release` and does the right thing:

- **Debian / Ubuntu** (`ID`/`ID_LIKE` matches `debian`/`ubuntu`) -> **AppArmor**
  - installs `apparmor apparmor-profiles apparmor-utils` if absent,
  - ensures the kernel cmdline carries `apparmor=1 security=apparmor`
    (`GRUB_CMDLINE_LINUX_DEFAULT`, grub backed up first),
  - puts the tor profile (`/etc/apparmor.d/usr.bin.tor`) into **enforce** mode.
- **RHEL / CentOS / Fedora** (`ID_LIKE` matches `rhel`/`centos`/`fedora`) ->
  **SELinux**
  - installs `policycoreutils selinux-policy-targeted` if absent,
  - sets `SELINUX=enforcing` in `/etc/selinux/config`.

> ### Risk: **low** — recommended **on by default**
> The failure mode of this module is **"permissive, not broken"**: if a step
> can't complete (package install fails, no tor profile yet, grub not writable),
> the host keeps running — it is simply not yet under mandatory access control.
> Nothing here stops a service; it only *confines* one. That's why it's part of
> the default-on baseline.

## ⚠️ Reboot / relabel — never automatic

Two changes only take effect after a reboot, and **`onionarmor` never reboots or
relabels for you**:

- the AppArmor kernel cmdline (`apparmor=1 security=apparmor`) needs a reboot
  (run `update-grub` first if your distro requires it), and
- switching SELinux from permissive to enforcing can require a filesystem
  **relabel** plus a reboot.

`apply` prints a `REBOOT REQUIRED` notice when it stages either; schedule the
reboot at your convenience.

## Quick start

```sh
# ALWAYS dry-run first — see the detected LSM + planned changes:
sudo onionarmor apply --module mac-profile-install --dry-run

# Apply (enforce the tor profile + stage the kernel cmdline / enforcing):
sudo onionarmor apply --module mac-profile-install
#   ... then REBOOT when convenient if it printed REBOOT REQUIRED.

# Check status (green/yellow/red; non-zero exit if any red):
onionarmor audit --module mac-profile-install

# Relax to permissive (LSM stays installed — never uninstalled):
sudo onionarmor revert --module mac-profile-install
```

## Options

| Flag | Meaning |
| --- | --- |
| `--dry-run` | Print the plan (detected LSM + changes). Changes nothing. |
| `--verify` / `--no-verify` | Post-apply verification (default: verify). |
| `-h`, `--help` | Usage. |

`ONIONARMOR_SKIP_RELOAD=yes` makes apply/revert **plan only** — it never invokes
`apt`/`dnf`/`aa-enforce`/`aa-disable`/`setenforce` (symmetric across apply and
revert), so file edits are staged without touching the live LSM.

## Audit status

`audit` reports one line each for: which LSM is active, the kernel cmdline /
enforcing mode, and the tor profile's state.

- **green** — the LSM is enforcing and (AppArmor) the tor profile is in enforce
  mode.
- **yellow** — installed but complain/permissive, or the tor profile is absent /
  the kernel cmdline isn't staged yet.
- **red** — no MAC LSM is active at all (AppArmor not installed, or SELinux
  disabled). Exit code 1.

The verdict line is `no mandatory access control LSM is enforcing` when red.

## Revert

`revert` is best-effort and deliberately conservative — it **does not uninstall**
the LSM, it only steps enforcement *down*:

- **AppArmor**: `aa-disable` the tor profile (AppArmor itself stays enabled) and,
  if apply modified the grub cmdline, restore the grub backup (reboot to take
  effect).
- **SELinux**: set `SELINUX=permissive` in the config (SELinux stays installed).

After revert the host is **permissive, not broken**. Re-apply to restore
enforcement.

## Threat model

MAC confinement limits the blast radius of a compromised relay process: even with
code execution inside `tor`, the attacker is restricted to the paths, capabilities
and network operations the profile permits, frustrating privilege escalation,
lateral movement, and tampering with unrelated files. Installing the LSM but
leaving it permissive (the audit *yellow* state) gives policy violations as logs
without enforcement — useful for tuning, but not protection; this module pushes
to *enforce* so the policy is actually applied.

## Overridable knobs (testing)

Every external command and path is env-overridable so the bats suite runs fully
offline against stubs (never touching the real host): `ONIONARMOR_MAC_OS_RELEASE`,
`ONIONARMOR_MAC_APT`, `ONIONARMOR_MAC_DNF`, `ONIONARMOR_MAC_AA_STATUS`,
`ONIONARMOR_MAC_AA_ENFORCE`, `ONIONARMOR_MAC_AA_DISABLE`,
`ONIONARMOR_MAC_APPARMOR_D`, `ONIONARMOR_MAC_SESTATUS`,
`ONIONARMOR_MAC_SELINUX_CONFIG`, `ONIONARMOR_MAC_SETENFORCE`,
`ONIONARMOR_GRUB_FILE`, `ONIONARMOR_MAC_STATE_DIR`.
