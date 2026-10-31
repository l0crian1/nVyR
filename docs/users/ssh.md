# SSH service

For implementation and testing, see the [developer guide](../dev/ssh.md).

SSH is controlled by the configuration tree:

```text
set service ssh

commit
save
```

An empty `service ssh` subtree enables listening on port 22 on all IPv4 and IPv6
addresses. To bind only selected assigned local addresses, repeat `listen-address`:

```text
set service ssh listen-address 10.0.0.1
set service ssh listen-address 2001:db8::1

commit
```

`listen-address` is a multi-value leaf accepting IPv4 or IPv6 addresses, without
prefixes or zone IDs. Every address must belong to the default routing instance.
You can configure an interface address and the SSH listener in the same commit.

Delete `listen-address <address>` to remove one binding. Deleting the final address,
or the entire `listen-address` leaf, restores wildcard listening. Deleting `service ssh`
stops the nVyR listener and removes its generated configuration. As with other owners,
`save` persists the resulting enabled or disabled state across boot. Commit-confirm
rollback and history rollback restore the previous listener configuration.


## Connection behavior

Listener changes can briefly interrupt new connection attempts. Existing authenticated
sessions survive listener restarts or stops. Failed changes attempt to restore the
previous listener configuration. Removing and re-enabling SSH preserves its host key.

Interactive logins enter the nVyR CLI. Only dev-admin users have host SSH-command,
SFTP, forwarding, and shell access; see [users and roles](login.md).
