# Connection tracking operations: implementation and maintenance

For configuration and command usage, see the [user guide](../users/conntrack-operations.md).

## Implementation and testing

The reader uses the existing pyroute2 dependency and the kernel Netlink interface.
Family and protocol selection narrow the dump in the kernel; original-address,
state and offload-status comparisons run in the shared reader. The offload filter
accepts either decoded `offload` or `hw-offload` status and retains the complete
record, including accounting. The accounting filter checks for an available
packet counter in either direction, preserving zero counts and excluding missing
counters. This also avoids the inverted
IPv6 tuple-filter comparison observed on the WSL test kernel; see
[the investigation record](upstream-issues.md#linux-ct-001-ipv6-conntrack-dump-filters-invert-address-matches).

Presentation sorting runs after filtering and NAT selection, before either text
or structured output. Stable endpoint sorting compares numeric addresses and
ports, preserving missing values at the end even when reversed. Summary counter
totals require both directions; sorting by counters does not implicitly enable
the accounting availability filter.

Native functional tests run in disposable namespaces, leaving the router's connections
and rules untouched:

```text
sudo python3 /usr/lib/nvyr/functionaltests/test_conntrack.py
sudo python3 /usr/lib/nvyr/functionaltests/test_nat_operations.py
```

## Structured connection output

The scripts expose `--raw` JSON for programmatic callers without a public JSON
keyword. NAT translation views use the same reader and filters.
