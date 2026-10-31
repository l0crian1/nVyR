# Static routing: implementation and maintenance

For configuration and command usage, see the [user guide](../users/static.md).

## Testing

`tests/test_static.py` and `tests/test_static_features.py` cover the CLI, validation,
references, rendering, defaults and commit-confirm restoration. Native reload and
recovery tests are described in [FRR integration](frr.md#testing).

Run the feature smoketests on a test router:

```sh
sudo python3 /usr/lib/nvyr/smoketests/test_static.py
```

See the [smoketest guide](../../smoketests/README.md) for setup, selection and
configuration restoration.

## Static dependency handling

Interface and explicit next-hop VRF references use `depends: interface` and
`depends: vrf`. Disabled references still block provider deletion. The registrar
does not require providers to exist; normal host validation checks local next-hop
addresses in the selected VRF, and FRR determines interface reachability and RIB
eligibility. Errors identify the route, source prefix where applicable, and VRF.
All additions, withdrawals, disable/re-enable operations and VRFs use one shared
FRR reload per static apply.

## Next-hop validation

`verify()` queries current host addresses in the next hop's resolution VRF using
`interfaces.local_addresses(vrf=...)` and rejects a next hop equal to one of them.
An address local only in another VRF does not cause a false rejection. Comparison
uses parsed addresses, including equivalent IPv6 spellings and addresses on down
links. Verification runs after earlier-priority interface owners, so it sees their
actually applied state. It does not require the next hop to be reachable: FRR
controls RIB selection and kernel installation, and an unreachable next hop may
remain inactive.
