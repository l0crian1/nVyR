# DHCP operational views: implementation and maintenance

For configuration and command usage, see the [user guide](../users/dhcp-operations.md).

## Validation

`tests/test_dhcp_views.py` covers journal cleanup, expiry, release, declined and
infinite leases, utilization, scope filters, client generations, and CLI access.
`tests/test_kea_live.py` includes real IPv4/IPv6 exchanges with these displays in
an isolated privileged container. Installed smoketests cover both server families
in `test_dhcp_server.py` and client detail in `test_ethernet.py` (the latter needs
`--ethernet-interface` and `--ethernet-dhcp`).

## Structured output

Operational scripts also accept `--raw` for internal automation. Server results
contain `records` and `disabled_servers`; client results are a list of records.
There is no public `json` node.

## Lease snapshot consistency

Lease journal reads retry when append/cleanup overlaps the snapshot. If a stable
snapshot cannot be obtained, the command asks the user to retry. This follows
[Kea's lease cleanup lifecycle](https://reports.kea.isc.org/dev_guide/d1/d47/lfc.html)
without requiring a lease-command hook library or triggering a database export.
