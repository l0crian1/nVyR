# Run the local regression and package checks

The Python 3.13 Linux test container runs the [regression and packaging script](../../scripts/test-ci.sh) on your current checkout.
Docker must be running Linux containers. No router or privileged container is
required.

From the repository root, build the test image:

```sh
docker build -t nvyr-test -f tests/container/Dockerfile .
```

Run the checks from PowerShell:

```powershell
docker run --rm -v "${PWD}:/workspace" nvyr-test
```

The same command works in a Linux shell. The container copies the current
checkout, including uncommitted changes, onto its temporary Linux filesystem.
This avoids Windows file-sharing overhead and lets tests use Linux permissions.
Build outputs, experiment data, virtual environments and test caches are excluded
from that copy. Reports and packages are copied back even when a check fails;
generated source changes stay inside the disposable container.

Source changes do not require rebuilding the image. Rebuild when
`pyproject.toml` dependencies, the test Dockerfile or its constraints change.
The image is separate from `nvyr-image-builder`; it does not compile the kernel,
FRR or Podman.

## Checks and results

The script stops on the first failed stage:

1. Check that generated schemas match their sources.
2. Install the current checkout using the image's cached dependencies.
3. Run `tests/` with two pytest workers, distributing complete files to workers.
4. Build the Python source distribution and wheel.
5. Build the Debian package.

Pytest prints the 30 slowest test durations and writes its report to
`test-results/framework.xml`. Packages are written to `dist/`. Both directories
are ignored by Git. A successful run exits with status zero and prints
`All local checks passed`.

Run the [smoketests](../../smoketests/README.md), [functional tests](../../functionaltests/README.md)
and [reboot acceptance suite](../../acceptance/README.md) separately on a test router.
Native integration tests in `tests/` require their documented opt-in flags.

Dependency downloads happen during the image build. The test script uses those
installed dependencies for editable installation and distribution builds.
`tests/container/constraints.txt` selects pyroute2 0.7.7 to match the router's
Debian trixie package; newer releases changed its Netlink codec API. Review this
constraint when upgrading the router dependency.

## 0.4.0 release coverage

The release's new behavior is divided between native configuration checks,
packet tests, and reboot persistence. Passing schema or readback tests alone
does not establish forwarding support.

- **MPLS/LDP:** `smoketests/test_mpls.py` covers kernel settings, static labels,
  timer settings, synchronization overrides and removal. Native tests in
  `tests/test_ldp_native.py` and `tests/test_mpls_forwarding_native.py` cover
  the FRR reload fixes and initial label allocation. Routed functional tests
  cover dual-stack bindings, explicit-null, interface recreation, static
  push/swap/pop, two-label MTU boundaries, and uniform/pipe TTL.
- **MP-BGP:** `smoketests/test_bgp_default.py` and native LU/VPN tests cover
  translation, peer-group inheritance, AddPath limits, direct VPN networks,
  deletion and recreation. The functional tests exercise import/export maps,
  RT isolation, filtered advertisements, dynamic policy withdrawal/recovery,
  operational commands and actual labeled forwarding. The MPLS IGP matrix
  runs OSPFv2/OSPFv3, IS-IS and RIP/RIPng separately, each with IPv4 and IPv6
  BGP peering and LDP TCP transport. All four AFs cross a native P router with
  two-label captures in both directions; an alternate static/IGP route cannot
  satisfy the checks.
- **WireGuard:** smoke checks cover key/peer edits and removal, VRFs, disable,
  recreation, hostname failure/retry scheduling and secret-free output.
  Shared functional tests cover both outer and inner address families, PSKs,
  overlapping AllowedIPs, source validation, static/BGP route interactions,
  peer failure and recovery. Overlaps remain allowed; identical prefixes on
  separate enabled peers remain invalid.
  Hostname endpoint checks resolve real A/AAAA answers, invoke manual refresh,
  and verify both inner families continue forwarding.
- **Conntrack:** logging tests cover NEW/DESTROY, family/protocol selection,
  NAT tuples, ICMP formatting, rotation and accounting. Flowtable tests also
  read real offloaded flows through the operational `offload`, `accounting`
  and `sort-by` filters. Local tests cover every sort key, reverse ordering,
  numeric address/port ordering and missing counters.
- **Acceptance:** `acceptance/config/mpls.set`, `vpn.set` and `wireguard.set`
  retain the new configuration across reboot; checks verify native state,
  VPN export/import policy, label allocation, WireGuard settings and both
  families of conntrack log events. Packet/convergence combinations belong
  in the shared functional scenario rather than duplicating that topology
  in acceptance.

Run the complete routed scenario to check coexistence as well as individual
features:

```sh
sudo python3 -m pytest -v -s /usr/lib/nvyr/functionaltests/network/ --ethernet-interface eth5 --container-image alpine
```

Use the site's spare Ethernet interface and installed container image. The
scenario restores the original running configuration and does not save its
test configuration. The full acceptance, smoke and functional runs remain
the release gate; this coverage audit is not a substitute for testing the ISO.

Known FRR VPNv6/IPv4-nexthop limitations are recorded in
[upstream issues](upstream-issues.md#vpnv6-over-ipv4-mpls-transport-incorrect-nexthop-programming).
Deferred conntrack UPDATE events/address filters, SR/SRv6 and physical hardware
offload are not claimed as supported by these checks.
