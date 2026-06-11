# ssh-hardening

Apply the [Mozilla OpenSSH "modern" guidelines](https://infosec.mozilla.org/guidelines/openssh)
to a `sshd_config.d` drop-in, drop weak host keys, regrow a small RSA host key,
and reload `sshd` — all behind a **5-minute safety latch** so a misconfiguration
can never lock the operator out.

| | |
|---|---|
| **Risk** | Medium-high — highest lockout risk of any module. Mitigated by the safety latch + `AllowUsers` preserving current logins. |
| **Default** | **Off** (opt-in). Run it explicitly once you have a working key and console fallback. |
| **Manages** | `/etc/ssh/sshd_config.d/99-onionarmor-hardening.conf`, weak host keys under `/etc/ssh`. Never edits the operator's `sshd_config`. |
| **Needs** | `at` (for the latch), `sshd`, `ssh-keygen`. |

```sh
sudo onionarmor apply  --module ssh-hardening --dry-run   # preview
sudo onionarmor apply  --module ssh-hardening             # apply (+ schedules latch)
# open a NEW ssh session, confirm you can log in, THEN:
atrm <job>                                                # cancel the latch
onionarmor      audit  --module ssh-hardening
sudo onionarmor revert --module ssh-hardening
```

## What it sets

The drop-in pins the Mozilla "modern" primitives and relay-operator session
limits:

- `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`,
  `KbdInteractiveAuthentication no`, `ChallengeResponseAuthentication no`,
  `UsePAM yes`, `Protocol 2`
- `X11Forwarding no`, `AllowAgentForwarding no`, `GatewayPorts no`,
  `PermitTunnel no`
- `MaxAuthTries 3`, `LoginGraceTime 30s`, `ClientAliveInterval 300`,
  `ClientAliveCountMax 2`
- Modern `HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs` (curve25519,
  chacha20-poly1305, AES-GCM, ETM MACs)
- `AllowUsers` scoped to the **currently logged-in** non-root users plus any
  `--allow-user <name>` you pass (and any existing `AllowUsers`). If no user can
  be determined, `AllowUsers` is **omitted** rather than risk locking everyone
  out — pass `--allow-user` to scope it.

It also removes `ssh_host_dsa_key*` and `ssh_host_ecdsa_key*` (backed up under
the state dir), and regenerates the RSA host key at 4096-bit if it is smaller.
Pass `--no-host-keys` to skip all host-key changes.

## The safety latch

Before reloading `sshd`, apply validates the config with `sshd -t` (rolling back
and refusing to reload if it fails), then schedules an `at` job for 5 minutes
out that **auto-restores the prior config and reloads** `sshd`. Confirm a *fresh*
SSH session works, then cancel the latch with the `atrm` command the apply
prints. If you do not cancel it, the hardening is rolled back automatically.

`--no-safety-latch` skips this (console access required). `--latch-minutes <n>`
changes the delay.

## Threat model

Hardening SSH shrinks the remote attack surface (no password brute-force, no
root login, no downgraded crypto) and removes weak host keys an attacker could
use for MITM after a key-confidence downgrade. The dominant *operational* risk is
self-lockout from a wrong key, `AllowUsers`, or cipher mismatch — which is
exactly what the `sshd -t` gate, `AllowUsers` preservation, and the 5-minute
auto-restore latch defend against. The module never touches the base
`sshd_config`, so a clean revert restores the prior policy.

## Audit

`audit` reports the drop-in presence, every managed directive's value (red on
drift), `AllowUsers` scoping, `sshd -t` validity, weak host keys, RSA strength,
and any pending latch. Exit is non-zero only when a hardened directive drifted or
`sshd -t` fails.
