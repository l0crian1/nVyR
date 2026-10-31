# Connection tracking operations: implementation and maintenance

For configuration and command usage, see the [user guide](../users/conntrack-operations.md).

## Implementation and testing

The reader uses the existing pyroute2 dependency and the kernel Netlink interface.
Family and protocol selection narrow the dump in the kernel; original-address
and state comparisons run in the shared reader. This also avoids the inverted
IPv6 tuple-filter comparison observed on the WSL test kernel; see
[the investigation record](upstream-issues.md#linux-ct-001-ipv6-conntrack-dump-filters-invert-address-matches).

Native functional tests run in disposable namespaces, leaving the router's connections
and rules untouched:

```text
sudo python3 /usr/lib/nvyr/functionaltests/test_conntrack.py
sudo python3 /usr/lib/nvyr/functionaltests/test_nat_operations.py
```

## Structured connection output

The scripts expose `--raw` JSON for programmatic callers without a public JSON
keyword. NAT translation views use the same reader and filters.
