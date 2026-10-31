# Bridge interfaces: implementation and maintenance

For configuration and command usage, see the [user guide](../users/bridges.md).

## Bridge testing

The live suites reserve disposable `br990`, dummy/veth interfaces, and test VRFs;
they restore the original running configuration when finished:

```sh
sudo python3 -m pytest -v -s /usr/lib/nvyr/smoketests/test_bridge.py /usr/lib/nvyr/functionaltests/interfaces/test_bridge_packets.py
```

Packet tests require existing firewall policy to permit the test VRF traffic,
as with the virtual-Ethernet suite. Device and route-name collisions are rejected
before creating resources. Interfaces are retained between test functions;
each function resets settings and verifies a specific feature.
