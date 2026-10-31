# Local users and isolated CLI sessions: implementation and maintenance

For configuration and command usage, see the [user guide](../users/login.md).

## Account and session implementation

`system_login.py` and `helpers/accounts.py` own account reconciliation and
compensation. The account ledger preserves UIDs across deletion, restoration and
image upgrades. `nvyr-login` selects host or container login; `nvyr-session` owns
Podman launch and cleanup. `nvyr-developer-access.service` establishes boot policy
and optional recovery access before configd. `nvyr-session-images.service` loads
the bundled images, and `nvyr-session-reap.timer` checks abandoned sessions.

`tests/test_login.py`, `tests/test_cli_sessions.py` and the operational authorization
tests cover credentials, permissions, persistence, installer policy and isolation
contracts. Native login testing must additionally cover SSH and console entry,
terminal resizing, Ctrl+C, disconnects, role revocation and boot recovery.

## Session mounts and cleanup

The only host mounts are the configd socket and the user's private
`/config/users/<username>` directory, presented as `/home/user`. This directory
holds command history and survives image upgrades. The whole `/config` directory,
saved configuration, account ledger and other users' files are not mounted.

Podman removes the session after logout or disconnect. A reaper removes orphaned
sessions whose launcher has died, and boot cleanup removes stale runtime records.
CLI containers use separate storage in `/var/lib/nvyr-sessions`, so workload
container/image displays, suggestors and cleanup never include them. The three
images share their filesystem layer and are built offline from installed nVyR and
Python packages. Login never pulls an image from a registry.
