# Neighbor inspection: implementation and maintenance

For configuration and command usage, see the [user guide](../users/neighbor-operations.md).

## Testing

`functionaltests/test_neighbor_dns.py` exercises real IPv4/IPv6 neighbor entries and
VRF filtering in disposable namespaces without changing router interfaces.
