# Early firewall protection: implementation and maintenance

For configuration and command usage, see the [user guide](../users/firewall-failsafe.md).

## Testing

Run the installed packet functional tests as root:

```text
python3 /usr/lib/nvyr/functionaltests/test_firewall_failsafe.py
```

They use disposable network namespaces, load the real generated rules before
creating a test interface, and cover both address families, groups, verdict maps, nested jumps, failed
main transactions, handover, inactive edits/rollback, and active deletion. They
do not install boot restrictions on the management interface.

The comprehensive reboot acceptance configuration also contains a fail-safe and
checks that the temporary table is absent after the full firewall is ready.

## Schema reuse

The single `schemas/includes/firewall/fail-safe.yaml.i` file reuses the normal
firewall fragments. After expansion, a narrowly scoped schema-builder pass
removes `dependency`, `depends`, `reapply-on-change` and `dependency-format` from
this subtree and rewrites its firewall configuration-path suggestors. Normal
firewall metadata is unchanged. This also covers future nested registrar fields
without maintaining hundreds of individual replacements.
