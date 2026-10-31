# BGP operational commands: implementation and maintenance

For configuration and command usage, see the [user guide](../users/bgp-operations.md).

## Internal JSON

```sh
bgp.nvyr.op show 'show bgp vrf BLUE ipv4 unicast summary' --raw
```

Internal `--raw` appends FRR's `json` keyword and validates the response as a
single JSON document without reshaping it. Neither `raw` nor `json` is exposed
in the CLI tree. `wide` is text-only and cannot be combined with raw output.
Reset commands do not offer raw output.

The wrapper resolves the schema path, expands abbreviations, removes an optional
`run` prefix and excludes output pipes. It then passes the ordered words as one
`vtysh -c` argument. It does not construct a shell command or translate syntax.

## Validation

`test_bgp_operations.py` runs direct IPv4/IPv6 display and reset checks in the
shared `NVYRLEFT` VRF. The suite restores the original running configuration.
`test_bgp_operational_peers.py` additionally checks route exchange and the
difference between soft refresh and hard reset on established IPv4/IPv6 peers.

```sh
sudo python3 /usr/lib/nvyr/functionaltests/network/test_bgp_operations.py
```

Command grammar was checked against the pinned FRR 10.7.1 binary. See also the
[FRR BGP operational reference](https://docs.frrouting.org/en/stable-10.7/bgp.html#displaying-bgp-information).
