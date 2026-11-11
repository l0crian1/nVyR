# IS-IS implementation

`protocols_isis.py` follows the normal configuration lifecycle:

- `get_config()` collects default/named-VRF IS-IS sections, policies and interface inventory.
- `verify()` checks NET consistency, family/VRF relationships, native timer constraints,
  metric/topology compatibility and policy references. Scalar checks belong to the schema.
- `generate()` renders `frr/isis.conf.j2` and selects the owned native blocks.
- `apply()` submits those blocks through the shared FRR transaction manager.

One `isisd` daemon serves the default instance and named VRFs. The internal area
tag is `nvyr`; `router isis nvyr [vrf NAME]` and each interface's
`ip router isis nvyr` / `ipv6 router isis nvyr` use the same tag. This does not
create separately numbered daemon processes. Interface membership is checked
against the configured VRF.

`frr_isis.py` owns these process blocks and IS-IS leaves in shared interface blocks.
It preserves other routing protocols and interface descriptions. Normalization
handles native default omission and combined level-1/level-2 writers; it does not
substitute different runtime semantics. The shared manager performs readback,
rollback and durable owner recovery.

## Native dependency fixes

`vendor/frr/isis-reload.patch` accompanies FRR package revision
`10.7.1-0~deb13u1+nvyr5`:

- Removing explicit hello-padding must restore `isis hello padding` (always).
  Negating the during-adjacency command would disable padding instead.
- Table redistribution edits must update existing entries. Removing the last
  table must delete the protocol/level parent and return native failures.
- Circuit option resets precede removal of the final address-family binding and
  process, avoiding recreation of a circuit without its mandatory area tag.
- Table metrics and route maps are applied through the parent's finish callback
  for both families; IPv6 table removal also withdraws its native registration.
- Route-map creation, deletion and recreation refresh the stored redistribution
  reference before evaluating routes in default and named VRFs.

See [upstream issues](upstream-issues.md). Rebuild the FRR packages when changing
this patch, and install matching FRR packages alongside the router package.

## Tests

- `tests/test_isis.py`: schema, verification, ownership, operational scoping,
  redistribution references and validation of the combined lab configurations.
- `tests/test_isis_native.py`: opt-in real FRR configure/edit/delete/readback,
  native defaults, advertisement metrics, route-map withdrawal and table removal.
- `smoketests/test_isis.py`: configuration translation with persistent default/VRF
  instances and dummy interfaces. No adjacency or packet assertions.
- `functionaltests/configs/network-isis.conf` and `network/test_isis.py`: shared
  BGP/OSPF/RIP links, dual-stack authenticated adjacencies, dedicated redistribution
  prefixes, policy withdrawal, forwarding and scoped adjacency reset.
- `acceptance/config/isis.set`: default and named-VRF peers on the existing lab
  links, verified before and after reboot.

Run the opt-in native tests only in their disposable FRR environment with zebra,
mgmtd, isisd and the patched reload script. BFD, MPLS, Segment Routing, remote LFA,
TI-LFA and Flex-Algo remain deferred.
