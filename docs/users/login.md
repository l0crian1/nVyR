# Local users and isolated CLI sessions

For implementation and testing, see the [developer guide](../dev/login.md).

nVyR has four roles:

- **dev-admin:** nVyR CLI running directly on the host, with `shell` access and
  password-authenticated sudo. This role is for development, testing and recovery.
- **sys-admin:** all router administration plus ordinary account management.
  It cannot create, promote, delete or reset a dev-admin account.
- **net-admin:** router configuration and operations, including containers, image
  installation, upgrades and reboot. It cannot manage accounts.
- **read-only:** operational inspection and diagnostics without configuration changes.

Sys-admin, net-admin and read-only logins run the CLI in a disposable Podman
container. Each role has its own image. Configuration and operational commands
are executed by configd on the host over its Unix socket. The role is checked
on every request; image selection and hidden completions do not grant permission.

## Initial installation and developer access

The live ISO starts with `nvyr` / `nvyr` as a dev-admin. Interactive logins enter
the nVyR CLI; use `shell` for a Linux shell. Noninteractive SSH commands execute
on the host through Bash.

Initial disk installation asks **Enable developer administration? [y/N]**.
No creates the selected initial account as sys-admin; Yes creates it as dev-admin.
Only initial installation asks this question. **Adding or updating an image
preserves the installation's developer-access policy without prompting**, including
when selecting factory configuration for the new image.

Developer access is stored in `/config/.nvyr/login/developer.json`, outside the
configuration tree. A sys-admin cannot enable it through set, load or rollback.
When enabled, a dev-admin can create other developer accounts. To disable
permanent developer logins, first create and test a sys-admin account, then run:

```text
nvyr

disable system developer-access

reboot
```

The change takes effect after reboot. Existing developer configuration records
remain visible, but their Linux accounts are removed. Subsequent account commits
must preserve a usable sys-admin while disablement is pending.

## Account configuration

From the CLI:

```text
configure

set system login user admin authentication plaintext-password "a strong unique password"
set system login user admin role sys-admin

set system login user monitor authentication plaintext-password "another unique password"
set system login user monitor role read-only

commit
```

Test the replacement administrator in another session before deleting an old
account. Deleting your own account closes its active sessions. Every account
needs a role and password, and verification preserves a usable administrative
account. `root`, `nvyr-dev` and unmanaged Linux accounts cannot be adopted.

**Account changes are durable on commit**, even without `save`. Other configuration
still follows normal save semantics. On boot, configd overlays the most recently
committed account configuration onto the saved configuration. Role changes and
account deletion terminate existing sessions. Permissions are checked on every
request.

## Isolation and persistent files

A CLI session has no network, no Linux capabilities, a read-only root filesystem,
private process/IPC namespaces, and no access to the host Podman socket. It runs
as the user's real UID so configd can authenticate Unix socket peer credentials.
The defaults are 256 MiB memory, one CPU and 64 processes/threads.

Your private workspace is `/config/users/<username>`, presented as `/home/user`.
It holds command history and survives image upgrades. Saved configuration and other
users' files are not available in the session. Sessions are removed after logout or
disconnect and are separate from workload containers shown by `show containers`.

Restricted roles cannot execute SSH commands, use SFTP/forwarding, obtain a host
shell or invoke arbitrary sudo commands. Their only sudo allowance launches the
fixed CLI session. A failed session does not fall back to Bash.

Workload containers remain separately configurable, including capabilities,
devices and privileged mode. A privileged workload can undermine host isolation;
use only the capabilities an application needs. Allowing net-admins to manage such
workloads is intentional and is not a claim that those administrators are isolated
from the host against their deliberate use of privileged containers.

## Recovery

Each installed image has a GRUB **one-boot developer recovery** entry. Selecting
it locally creates `nvyr-dev` with a random password printed to the active local
consoles. The password is not written to configuration or the journal. Account
creation runs independently of configd, so it also works when configd cannot
recover configuration. This recovery account opens a host Bash shell directly;
it does not require configd or the nVyR CLI. The account is removed at the next boot.

Use this account, an enabled permanent dev-admin, or recovery media when session
images or configd are unavailable. There is no permanent fallback shell for the
container roles. VGA and serial consoles still require authentication.

## Credentials

`plaintext-password` is input-only. Configd converts it to a salted yescrypt hash
before it reaches the candidate, journals or saved configuration. Credential
commands are omitted from navigation history and error echoes. Linux receives
hashes over `chpasswd` standard input, not command-line arguments. Net-admin and
read-only configuration displays exclude authentication fields.
