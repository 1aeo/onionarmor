# Troubleshooting

The most common first-run snags, and how to clear them. Every fix here is safe
to re-run — onionarmor is idempotent.

## `apply` says role mismatch / refuses to run

```
onionarmor: refusing to apply — /etc/onionarmor/role.conf does not declare role=tor-relay
```

`apply` and `rollback` cross-check the host's declared role against your
`--role` flag. Declare the role once:

```sh
sudo mkdir -p /etc/onionarmor
echo 'role=tor-relay' | sudo tee /etc/onionarmor/role.conf
```

Then re-run with the **matching** `--role`. This guard is intentional — it stops
a relay posture from landing on the wrong host. See [Roles](roles.md).

## `apply` refuses because `--role` is missing

```
onionarmor: apply requires --role <name>
```

There is no default role — it must be explicit. Pass `--role tor-relay`
(or `eval-host` / `receiver`), and make sure `/etc/onionarmor/role.conf` agrees
(above).

## "Did anything actually change?" — dry-run vs apply

`--dry-run` **never** touches the host; it only prints the plan. If you ran a
dry-run and nothing changed on the box, that's correct. Re-run **without**
`--dry-run` (and with `sudo`) to apply for real:

```sh
sudo onionarmor apply --module dns-posture --dry-run   # preview only
sudo onionarmor apply --module dns-posture             # actually applies
```

Confirm afterward with `onionarmor audit --module dns-posture` (or
`onionarmor diff --role <r>` for sysctls).

## A package is missing (`unbound`, FRR, …)

The one-liner installer `apt-get install`s onionarmor's own prerequisites, but a
**module** may need a daemon it doesn't manage:

- `dns-posture` installs `unbound` for you. If apt is wedged, fix apt first
  (`sudo apt-get update`) and re-run.
- `bgp-hardening` needs **FRR already installed and configured** under
  `/etc/frr`. It hardens an existing BGP setup; it does not install or bootstrap
  FRR. If `/etc/frr/daemons` doesn't exist, install and configure FRR first.

## `sysctl` value won't stick / something else manages it

If another tool (cloud-init, a config-management agent, a hand-written
`/etc/sysctl.d` drop-in) also writes one of the managed keys, the
lexically-last file under `/etc/sysctl.d/` wins after `sysctl --system`.
onionarmor writes `99-onionarmor-*.conf` (high priority) but a conflicting file
can still fight it.

```sh
onionarmor diff --role tor-relay        # shows ok / DRIFT / missing per key
grep -rn '<key>' /etc/sysctl.d /etc/sysctl.conf   # find the competing writer
```

Remove or reconcile the competing drop-in, then re-`apply`.

## I want to undo everything

Nothing here is one-way. Roll back sysctls and revert each module:

```sh
sudo onionarmor rollback --role tor-relay        # restore the previous managed sysctl file
sudo onionarmor revert  --module dns-posture     # restore resolv.conf, unmask systemd-resolved
sudo onionarmor revert  --module kernel-reserved-ports
sudo onionarmor revert  --module bgp-hardening   # restore /etc/frr/daemons, drop opt-in extras
```

Each module README documents exactly what its `revert` restores. Kernel lockdown
staged with `apply-lockdown` is undone by editing `/etc/default/grub` back and
running `update-grub`; it only takes effect on the next reboot either way.

## Still stuck?

- `onionarmor audit` prints the full change history for the host.
- `onionarmor help` (or `apply --module <name> --help`) shows usage and flags.
- File an issue at <https://github.com/1aeo/onionarmor/issues>.
