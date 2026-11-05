# RIP and RIPng implementation

`protocols_rip.py` serves two schema owners, `rip` and `ripng`, each with its own
priority and registered default/named-VRF sections. Both daemons were already
enabled in the image's FRR daemon configuration.

- `get_config()` gathers this owner's instances, routing policies and configured
  interface inventory.
- `verify()` checks references, VRF membership and cross-field requirements.
  Scalar validation belongs in the schema.
- `generate()` renders `frr/rip.conf.j2` and selects owned native blocks.
- `apply()` submits those blocks to the existing FRR transaction manager.

`frr_rip.py` owns `router rip[ng]` blocks and only its protocol's leaves inside
shared interface blocks. It preserves BGP, OSPF, interface descriptions and the
other RIP family. FRR's management model keys RIP interface settings by interface
name, even for a named VRF; its writer emits `interface <name>` without a VRF suffix.
Instance membership is verified against the nVyR interface inventory.

Normalization handles only native readback equivalents: default timers and metric,
ordinary split horizon, the default MD5 length spelling, and passive settings
equal to the current process default. The shared manager still verifies the
result and restores prior native state after a failed reload.

## FRR reload patch

`vendor/frr/rip-reload.patch` fixes passive-default exception removal in FRR
10.7.1. A deleted `no passive-interface eth1` must restore the desired passive
default, rather than blindly becoming `passive-interface eth1`. Resets run after
any default change. Native tests cover removal and both default transitions.

The pinned FRR package revision is `10.7.1-0~deb13u1+nvyr3`; both package dependencies
and the build recipe include it. Rebuild `nvyr-image-builder` before producing an
ISO with RIP support. A router deb requires the matching FRR packages as well.
See [upstream issues](upstream-issues.md) before removing the patch on an FRR upgrade.

## Verification

- `tests/test_rip.py`: schema bounds, reference checks, family restrictions,
  ownership and operational scoping.
- `tests/test_rip_native.py`: opt-in real FRR readback, changes/removal, policy
  filters, offsets, supported redistribution sources, authentication, operational
  commands, MD5-authenticated RIPv2 and RIPng route exchange, ping and withdrawal.
- `smoketests/test_rip.py`: CLI-to-native translation using one persistent VRF
  and dummy link. No neighbor-convergence or packet checks.
- `functionaltests/configs/network-rip.conf` and `network/test_rip.py`: RIP shares
  the existing BGP/OSPF topology and configuration batch, with dedicated prefixes.
- `acceptance/config/rip.set`: default and BOOTLEFT instances share the existing
  transit and advertise RIP-only prefixes, checked before and after reboot.

Run the opt-in native tests only in a disposable privileged container with zebra,
mgmtd, ripd and ripngd and the patched reload script:

```sh
NVYR_RIP_NATIVE=1 python3 -m pytest -v tests/test_rip_native.py
```

The shipped RIP/RIPng daemons do not expose SHARP redistribution in this build.
Do not add it based solely on FRR's source enum; verify the compiled CLI. BFD remains
outside this implementation.
