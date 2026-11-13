# BGP: implementation and maintenance

For configuration and command usage, see the [user guide](../users/bgp.md).

## BGP lifecycle

BGP uses the shared `frr-reload.py` manager alongside static routes and routing
policies. One `bgp` owner applies all configured routing instances after policies
and static routes. Reload verifies native readback and restores the previous
configuration if applying or verifying the target fails. It does not save FRR
configuration independently of nVyR.

## Tests

On the router:

```sh
sudo python3 /usr/lib/nvyr/smoketests/test_bgp.py
sudo python3 /usr/lib/nvyr/smoketests/test_bgp.py -k ipv6
sudo python3 /usr/lib/nvyr/smoketests/test_bgp_default.py
sudo python3 /usr/lib/nvyr/smoketests/test_bgp_neighbors.py
```

The script reserves `NVYRBGP` (table 41040) and `NVYRBGPPOLICY`, exercises each
feature directly, checks native output, and cleans up between functions. The
common suite fixture restores the original running configuration after all
selected scripts finish. Existing default-VRF BGP sessions are not replaced.

The default-only script tests dampening and the daemon-wide route-map timer. It
skips when default-VRF BGP is already configured, including unmanaged native
configuration. Neighbor tests additionally reserve `dum41040` and check IPv4,
IPv6, runtime-only addresses, and peers in another VRF.

Developer tests in `tests/test_bgp_live.py` additionally exchange and withdraw
real IPv4/IPv6 routes over veth links between isolated VRFs, test local-AS
changes, and inject a lost reload response to verify rollback. Run these only
against disposable FRR daemons with `NVYR_BGP_TEST=1`.

## Labeled-unicast

LU uses the existing BGP lifecycle, FRR owner and transaction manager. Neighbor
AF definitions are shared through `peer-ipv4.yaml.i` and `peer-ipv6.yaml.i`.
The named-VRF include removes LU configuration because the pinned FRR rejects
those SAFIs outside the default instance. Kernel MPLS membership remains owned
by `protocols mpls` and netlinkd.

Only family path selection and neighbor controls are introduced. Route
origination remains in unicast's shared RIB. FRR also maps AddPath transmit
strategies from LU to unicast: the BGP adapter canonicalizes those statements
and verification rejects conflicting effective peer settings, including
peer-group inheritance. Receive limits and activation stay in their own SAFI.

`tests/test_bgp_lu_native.py` checks native creation, replacement, inheritance,
member overrides and removal with `NVYR_LU_NATIVE=1`. It creates private FRR
processes in a namespace and must run as root on a disposable test system.
The default-BGP smoketests check CLI-to-FRR translation without convergence
waits. Acceptance persists LU alongside unicast across reboot. Functional LU
checks share the routed network's MPLS peer and link; dedicated destinations
verify filtering, kernel label encapsulation and bidirectional packet delivery
without static or IGP fallback routes.
