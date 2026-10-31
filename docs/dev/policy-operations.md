# Routing-policy operational commands: implementation and maintenance

For configuration and command usage, see the [user guide](../users/policy-operations.md).

## Structured output

Internal callers can request `raw=True` from the wrappers for native JSON. FRR's
per-daemon objects are retained unchanged. There is no `json` keyword in nVyR's
operational tree. FRR 10.7.1 provides JSON for route-map, ACL, AS-path-list, and
prefix-list list/sequence/summary/detail views. Community-list definitions and
prefix-list prefix lookups are text-only; raw requests for those fail explicitly.

## Testing and references

`functionaltests/network/test_policy_operations.py` exercises each policy type through configd
and the native display commands. `test_bgp_operations.py` also checks clearing an
actively used route-map's counters without withdrawing its BGP route. The opt-in
`tests/test_policy_op_live.py` runs the policy smoke functions through the real
configuration engine and reload manager against disposable FRR daemons.

References: [FRR filtering](https://docs.frrouting.org/en/stable-10.7/filter.html),
[route maps](https://docs.frrouting.org/en/stable-10.7/routemap.html), and
[BGP](https://docs.frrouting.org/en/stable-10.7/bgp.html). Exact command and JSON
availability is tested against the packaged FRR 10.7.1 binaries.
