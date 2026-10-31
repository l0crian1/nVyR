# SSH service: implementation and maintenance

For configuration and command usage, see the [user guide](../users/ssh.md).

## Implementation

`config_scripts/service_ssh.py` uses the shared rendering pipeline and passes the
configuration dictionary directly to `templates/ssh/sshd_config.j2`. The backend in
`helpers/ssh.py` validates generated text with `sshd -t`, publishes it under
`/run/nvyr-ssh/default.conf`, then starts or restarts `nvyr-ssh@default.service`.
After systemd's readiness notification, the backend verifies every requested socket
is owned by this SSH listener. A partial bind failure rolls back the change even if
OpenSSH reports itself active. Unchanged active
configuration does not restart the listener.

Changes restart the listening daemon and may briefly interrupt new connection
attempts. Existing authenticated sessions survive the listener restart or stop.
If application fails, the backend restores the previous generated file and service;
failed restoration retains the engine's recovery journal and requires configd recovery.
The runtime file is reconstructed from nVyR state rather than enabling the instance
independently at boot.

OpenSSH permits nVyR-managed accounts in `nvyr-access`, with PAM enabled and empty
passwords forbidden. Fresh systems enable SSH and use `nvyr` / `nvyr`; replace this
default account after installation. Interactive logins enter the CLI. Administrators
may use SSH commands, SFTP and forwarding; restricted roles cannot. User SSH startup
scripts and environment overrides are disabled. See [users and roles](login.md).

nVyR generates its persistent Ed25519 host identity on first enable at
`/var/lib/nvyr/ssh/host_ed25519_key` (beneath a custom configd state directory when used).
Removing and re-enabling the service preserves this identity. Image builds do not
contain this key and remove the stock package's build-time host keys.

The image includes `openssh-server` and masks the stock `ssh.service` and `ssh.socket`.
Only the configured nVyR service listens. On a standalone Debian installation, an
already-active stock service/socket causes a useful commit error; nVyR does not
overwrite its configuration or take over its listener. Stop and disable that stock
service/socket when intentionally handing SSH management to nVyR.

The backend plan, runtime paths, and systemd template identify a service instance.
Only `default` is wired to the CLI today. Future VRF support can add schema selection
and instance-specific network binding/execution without sharing one global SSH
configuration file; naming an instance alone does not implement VRF isolation.

Native JSON stores `listen-address` as a list, including a singleton such as
`["10.0.0.1"]`. Each `set service ssh listen-address <address>` adds a list entry.

## Verification

Unit tests cover the lifecycle, address validation, removal and compensation.
`tests/test_ssh_live.py` runs only with `NVYR_NETWORK_TEST=1` inside the disposable
privileged Debian container. It exercises real IPv4/IPv6 listeners, public-key login,
port-conflict recovery, commit-confirm rollback, configd restart, host-key persistence,
and an interface address configured in the same commit.
