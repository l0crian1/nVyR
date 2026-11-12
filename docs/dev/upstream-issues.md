# Upstream investigation and fixes

Track dependency defects observed while developing nVyR, the evidence separating
them from nVyR defects, and the conditions for removing temporary restrictions.
Last reviewed: 2026-11-11.

These entries are local investigation records, not confirmation that an upstream
report has been filed or a fix merged. No upstream report or verified fix is
recorded for the issues below. Add report URLs, patch/commit IDs, affected versions,
and retest results as they become available.

## FRR-RIP-002: Shared policy refresh omits named VRFs

**Status:** Reproduced with FRR 10.7.1 on Linux 6.18.63-nvyr-amd64 and in a
separate disposable container. Local fix: `vendor/frr/rip-vrf-routemap.patch`,
package revision `+nvyr4`. No upstream report or released fix is verified.

Configure RIP or RIPng redistribution in a named VRF with a route-map reference
before creating that map. The native configuration reads back correctly, but
permitted connected routes are not advertised. Debug output reports that the
route-map filtered the prefix. Reapplying the identical redistribution setting
makes the route appear immediately; no interface, route or firewall change is
needed.

Both daemons' route-map creation/deletion callbacks look up only `VRF_DEFAULT`.
The named VRF retains a null map reference when the map is created later,
including during configuration replay. Interface map references are refreshed
by the same callback and have the same VRF omission. The fix walks all VRFs and
uses the existing interface and redistribution refresh functions.

The prefix-list/access-list update callbacks have the same default-only scope.
The local patch also refreshes distribute-list references in all VRFs, and
tests both list types through creation, deletion and recreation.

Interfaces also retain cached list/map pointers after their RIP instance is
removed. Deleting the policy and recreating the instance can reuse a dangling
pointer; the combined regression reproduced RIPng SIGSEGV in
`prefix_list_apply_ext` from `ripng_read`. The patch clears those interface
references when their instance association changes. An explicit regression
deletes a filtered instance and its prefix list, then verifies unfiltered route
exchange after recreating the instance on the same interfaces.

`tests/test_rip_native.py` exercises creation, deletion and recreation after
both reference types, checking route advertisement, withdrawal and traffic for
IPv4 and IPv6. The combined acceptance test checks bidirectional redistribution
between default and named VRFs before and after reboot. Retest all these paths
when upgrading FRR; do not hide the defect by changing configuration order or
reapplying redistribution after each policy update.

See [patch provenance](../../vendor/frr/README.md).

## FRR-RIP-003: RIPng poisoned-reverse removal disables split horizon

**Status:** Reproduced with FRR 10.7.1; local reload correction included in
`vendor/frr/rip-vrf-routemap.patch`, package revision `+nvyr4`.

Removing `ipv6 ripng split-horizon poisoned-reverse` through the generic reload
negation leaves `no ipv6 ripng split-horizon` in native readback. This disables
split horizon instead of restoring the default simple mode, causing nVyR's
readback verification and rollback to reject the result. The corrected reset
emits `ipv6 ripng split-horizon`. Both native removal and the generated reload
command are tested; no readback exception is introduced.

## FRR-RIP-001: Removing passive-default leaves active exceptions passive

**Status:** Reproduced with FRR 10.7.1; fixed locally by
`vendor/frr/rip-reload.patch` in FRR package revision `+nvyr3`. No upstream fix or
report has been verified.

Given `passive-interface default` and `no passive-interface eth1`, remove both
settings using `frr-reload.py`. The generic inverse of the negative exception is
`passive-interface eth1`, which persists after the process default becomes active.
The interface therefore stops sending updates despite the desired configuration
having no passive settings.

The patch restores each removed exception to the target configuration's default,
after default changes, while preserving explicit replacement settings. Native
round-trip and packet tests in `tests/test_rip_native.py` exercise both protocols;
the passive-default defect itself applies to RIP, since RIPng has no such switch.
Retest exception removal and both passive-default transitions before dropping
this patch when updating FRR.

## NFT-IFNAME-001: Adjacent interface prefixes corrupt anonymous set listings

**Status:** Tracked upstream defect, not a release blocker. Reproduced with
nftables 1.1.7 on the October 27 nVyR ISO. No upstream report, patch or fixing
release has been verified.

An anonymous interface-name set containing `"veth995*"` and `"veth996*"` lists
incorrectly. JSON emits `src/json.c:724: json_pack failure (NULL object)` on stderr
and returns an empty set for those entries. Text output renders a malformed range
with invalid UTF-8 bytes. With a third, separated `"bootfuture*"` prefix, only that
third entry survives JSON output. A single prefix and separated `"eth1*"`/`"wg1*"`
prefixes list correctly. Retests also confirmed `"eth*"`/`"wg*"` and
`"veth995*"`/`"veth997*"` list correctly, while the adjacent pair still fails.

Reproduced using only native nft commands in a disposable network namespace:

```nft
table inet example {
    chain input {
        iifname { "veth995*", "veth996*" } counter accept
    }
}
```

```sh
nft -j list table inet example
nft list table inet example
```

The original acceptance fixture triggered this in the generated ingress dispatch's
interface selector. The device subscription itself still lists all interfaces;
the anonymous `iifname` match does not. This observation proves a listing defect,
not whether the installed kernel match has the intended packet semantics.

That acceptance run stopped before saving or rebooting because full-table
inventory and snapshots could not faithfully represent these rules. The base
fixture now uses `veth995*` and `veth997*` so release acceptance can proceed
independently; this does not resolve the defect. Keep the adjacent-prefix
reproducer above for upstream investigation. Investigate interval
merging/delinearization and retest text, JSON, matching and nonmatching packets
with the offending pair before closing this issue.

## LINUX-HELPER-001: Object-reference map counters do not increment

**Status:** Reproduced with nftables 1.1.7 and Linux 6.18.58-nvyr-amd64 on
2026-10-27. No upstream report or verified fixing release is recorded.

A map declared with `typeof meta l4proto . th dport : ct helper` accepts a
map-level `counter`, and its elements list counters. However, FTP and TFTP
traffic assigned through `ct helper set meta l4proto . th dport map @helpers`
left those element counters at zero. Separate counters immediately before and
after the lookup counted 24 attempts and 16 hits, respectively; conntrack
confirmed helper assignment for the 16 matching IPv4/IPv6 connections.

Linux's [object-reference map evaluator](https://github.com/torvalds/linux/blob/v6.18/net/netfilter/nft_objref.c)
calls the selected object's evaluation function without updating set-element
expressions. The [ordinary lookup evaluator](https://github.com/torvalds/linux/blob/v6.18/net/netfilter/nft_lookup.c)
does update those expressions. This explains the missing statistics without
implying that helper assignment failed.

nVyR omits counters on this internal map. Retest with matching and nonmatching
packets in both families before enabling element counters or claiming a fix.

## NFT-TIMEOUT-001: Targeted conntrack timeout inventory is incomplete

**Status:** Observed with nftables 1.1.7 on the test router on 2026-10-27.

After installing a `ct timeout` object, `nft -j list ct timeout inet <table> <name>`
returned only metadata, while `nft -j list table inet <table>` returned the object
and its complete policy. The plural `list ct timeouts` form was rejected.

nVyR reads the table for operational display and uses a terse table listing during
recovery to avoid dumping set elements. It selects only timeout objects in its
reserved namespaces. Native timeout tests cover inventory, replacement, and
recovery against the real table listing. No upstream report or fixing release has
been identified; retest targeted and plural inventory before adopting either.

## LINUX-CT-001: IPv6 conntrack dump filters invert address matches

**Status:** Reproduced on `6.18.54.1-microsoft-standard-WSL2`. Current upstream
Linux source has the correct comparison; no fixing commit or stable release has
been identified in this investigation. The router kernel was not tested here.

Insert an IPv6 TCP connection from `2001:db8::10` to `2001:db8::20` using
`conntrack -I`. An unfiltered pyroute2 `Conntrack(nfgen_family=AF_INET6).dump()`
returns it, while `tuple_orig=NFCTAttrTuple(family=AF_INET6, saddr='2001:db8::10')`
incorrectly excludes it. IPv4 and protocol-only filtering work.

The WSL branch's `ctnetlink_filter_match_tuple()` rejects IPv6 tuples when
`!ipv6_addr_cmp(...)` is true, rejecting equality instead of inequality.
[WSL source](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.y/net/netfilter/nf_conntrack_netlink.c)
and [Linux upstream](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_netlink.c)
differ at that condition. These branch links are moving references.

nVyR performs explicit original-address and state comparisons in its reader for
both families; it uses only family/protocol kernel filters. There is no kernel
version branch or change to matching semantics. Native namespace smoketests check
positive and negative address filters. Before moving address selection into the
kernel, verify both source and destination matching against matching and unrelated
IPv6 connections on the supported kernel. No upstream report was filed.

## FRR-001: Reload adds BGP list replacements before removing old entries

**Status:** Reproduced with FRR 10.7.1; nVyR carries a tested ordering fix.

`ignore_delete_re_add_lines()` moves BGP list deletions into the bulk additions
to avoid issuing one vtysh call per entry. It appends them after new entries.
An AS-path rule replacement overwrites its old regex at the same sequence, so
the subsequent deletion fails because that old regex no longer exists.
Changing a community list from standard to expanded also fails because the old
type still occupies the name when the new type is created. Recovery can encounter
the same ordering defect while restoring the previous configuration.

The same ordering was present in upstream development when investigated.
The [build-time patch](../../vendor/frr/README.md) retains bulk execution and puts BGP
list deletions before additions. Native tests cover replacement, type changes,
unchanged reapply, deletion, and rollback after a lost successful reload reply.
IPv4/IPv6 BGP exchange tests also confirm route withdrawal after an AS-path
filter update. No upstream report has been filed. Retest these scenarios before
removing the patch on a future FRR upgrade. It is applied by our FRR package
build; the reload executable belongs to `frr-pythontools`.

## AARDVARK-001: DNS cannot bind a Netavark bridge inside a VRF

**Status:** Reproduced with Podman 6.1.4, Netavark 2.1.0 and Aardvark DNS 2.1.0.
VRF-attached container networks require explicit network-level `disable-dns`.

Creating a bridge with `--opt=vrf=OPTBLUE` succeeds, but starting a container with
network DNS enabled fails when Aardvark binds its UDP listener:

```text
failed to bind udp listener on 172.29.210.1:53:
Cannot assign requested address (os error 99)
```

The same network starts with `--disable-dns`; the bridge retains its VRF master
and configured MTU. nVyR does not silently disable DNS or change host-wide socket
acceptance settings. External container name servers remain available. Remove
the verification restriction only after testing Aardvark name resolution and
forwarding on simultaneous default and named-VRF bridges, including overlapping
addresses. No upstream patch or report has been confirmed.

## KEA-001: IPv4 default-VRF fallback socket collides with a named VRF

**Status:** Reproduced with Kea 3.0.4; conflicting local listener addresses rejected.

Kea's IPv4 raw receive path also opens a UDP fallback socket bound to the local
address and port 67. A default-VRF process leaves this socket unbound to a device.
Starting a second instance through `ip vrf exec BLUE` with the same local IPv4
address fails with `Address already in use`, despite `udp_l3mdev_accept=0` and
verified VRF device binding in the second process.

The [fallback socket implementation](https://github.com/isc-projects/kea/blob/Kea-3.0.4/src/lib/dhcp/pkt_filter.cc)
does not bind the default instance's socket to its receive interface. The same
implementation was present in upstream development when checked. No nVyR Kea
patch is carried. A future fix must be validated with simultaneous default/named
VRF servers using identical local addresses and independent lease exchanges.

Different local IPv4 listener addresses with overlapping client subnets passed
allocation and renewal tests. Two named VRFs with identical IPv4 listener addresses
also passed independent allocation tests. Identical IPv6 listener addresses in separate VRFs
also passed. The restriction is therefore specific to IPv4 listener collisions,
not to overlapping VRF subnet configuration in general.

## NFT-001: Standalone conntrack map keys have incorrect byte order

**Status:** Reproduced with native nftables; affected configurations blocked.

**Environment:** nftables 1.1.7, Linux 6.12.113+deb13-amd64, amd64 live router.

**Impact:** Single-field maps using the following keys install incorrect values
and fail packet matching:

- `connection zone`, `connection original zone`, `connection reply zone`.
- `connection original|reply|total packets`.
- `connection original|reply|total bytes`.
- `connection original|reply|total average-packet-size`.

Minimal native reproduction, independent of nVyR:

```nft
table inet ct_map_probe {
    map zones {
        typeof ct zone : verdict
        elements = { 3 : accept }
    }

    map bytes {
        typeof ct original bytes : verdict
        elements = { 1024 : accept }
    }

    set zone_members {
        typeof ct zone
        elements = { 3 }
    }
}
```

Run reproductions in a disposable network namespace. The map keys list as `768`
and `1125899906842624`; the equivalent set retains zone `3`.
In isolated packet tests, direct zone matches incremented while the zone map
lookup did not. Subsequent testing reproduced failed packet lookups for all
12 affected fields in both IPv4 and IPv6: 24 single-field cases.

Two-to-four-field maps passed 144 positive packet/listing cases, including
different key positions and two affected fields in the same key. All 48 negative
controls rejected mismatched keys. These results establish the tested combinations,
not every possible map expression. Equivalent tested match-groups also work.

**Current handling:** `verify_map_nftables_limitations()` in
[firewall.py](../../src/nvyr/config_scripts/firewall.py) rejects affected single-field
maps, including empty maps. It does not restrict direct rule matches or sets.
The check is independent of the map's result type.

**Investigation:** Compare the native reproduction on 1.1.6 and current upstream,
then bisect if behavior differs. The older
[conntrack zone patch series](https://www.spinics.net/lists/netfilter-devel/msg70221.html)
has related history; its evaluation fixes already appear in the
[0.9.9 changelog](https://www.netfilter.org/projects/nftables/files/changes-nftables-0.9.9.txt).
It is not a confirmed fix for this 1.1.7 failure. The
[1.1.7 announcement](https://www.mail-archive.com/netfilter-announce%40lists.netfilter.org/msg00289.html)
lists map normalization and byte-order changes worth examining; none has yet
been identified as the cause.

**Closure:** Verify correct installed keys and positive/negative packet matching
for every affected field in both families. Remove the dedicated single-field
guard and restore positive smoketests only after the fixed dependency is shipped.

**Coverage:** [Map restriction unit tests](../../tests/test_firewall_map_limitations.py)
and [group smoketests](../../smoketests/test_firewall_groups.py).

## NFT-002: Five-field conntrack maps lose correct listing information

**Status:** Native packet matching passes, but listings are corrupted; affected
configurations blocked. Same environment as NFT-001.

Native example:

```nft
table inet ct_map_five_probe {
    chain target {
        counter
    }

    map five {
        typeof ct mark . udp sport . ct zone . udp dport . meta l4proto : verdict
        elements = { 42 . 53099 . 3 . 53098 . udp : jump target }
    }
}
```

The tested build lists the map as:

```nft
type mark . inet_service . integer . inet_service . inet_proto : verdict
elements = { 0x0000002a . 53099 . 0 . 768 . 207 : jump target }
```

Hexadecimal mark formatting is equivalent. The zone, port and protocol values
are not. Both native text and JSON listings contained incorrect values.
All 24 tested five-field maps matched their intended IPv4/IPv6 packets.
Correct matching does not make the listing suitable for operational inspection;
export/restore fidelity remains unverified.

**Suspected cause:** Lost or incorrectly reconstructed type/width metadata.
The listing changes from `typeof` to generic types while shifting field values.
This is a lead, not an established root cause or a demonstrated universal
five-field limit.

**Current handling:** The same `verify_map_nftables_limitations()` helper rejects
five-field maps containing the NFT-001 fields. Other map fields and match-groups
are not blocked by this check. Two-to-four-field maps remain available.

**Investigation:** Compare declaration metadata, encoded key widths, packet
lookup behavior and listing reconstruction. Test mixed-width keys and field
positions separately; do not assume all five-field maps or sets are affected.

**Closure:** Require correct text/JSON values, preserved field widths,
positive/negative packet matching, and a successful list/reload round trip
before removing the five-field guard. Coverage is shared with NFT-001.

## NFT-003: IPv6 DSCP interval sets fail packet matching

**Status:** Previously reproduced with direct nft commands; upstream fix unverified.

**Recorded environment:** Debian nftables/libnftables 1.1.7-1 on
6.18.54.1-microsoft-standard-WSL2.

`ip6 dscp { 8-16, 63 }` loads but fails to match DSCP 10. Positive and negative
interval comparisons were affected. Individual values, sets of individual values,
and IPv4 ranges passed.

**Current handling:** Native expressions are retained without silently expanding
ranges. This is not covered by the conntrack map guards. See
[firewall documentation](../users/firewall.md#marks-dscp-and-tcp-mss).

**Next step / closure:** Reproduce on the target router and current upstream,
identify the faulty layer, and verify DSCP values below, inside and above the
interval in both positive and negative rules before declaring it resolved.

**Coverage:** `test_real_ipv6_dscp_range_packet_matching` in
[test_nftables_live.py](../../tests/test_nftables_live.py).

## NFT-004: Conntrack status symbols use bit positions as values

**Status:** Previously reproduced in nftables 1.1.7 descriptions and compiled
comparisons; explicit correct numeric constants are used.

`helper` is described/compiled as `0x0d` instead of `0x2000`;
`offload` as `0x0e` instead of `0x4000`. This changes matching semantics, not just
display. nVyR emits the correct masks for these two flags while using supported
symbolic constants elsewhere.

**Next step / closure:** Locate or report the symbol-table defect. Validate the
compiled comparisons and real matching for individual flags and combinations.
Only then replace these numeric constants with symbols.

**Evidence and coverage:** [Connection status documentation](firewall.md),
[native enhancement tests](../../tests/test_firewall_enhancements_live.py).

## NFT-005: Adjacent conntrack comparisons are misrepresented in listings

**Status:** Native program contains the correct distinct comparisons;
text/JSON reconstruction is incorrect in nftables 1.1.7.

Example: `ct expiration < 10s ct original bytes > 1024` can be listed as a
combined byte range even though it compares two different fields.
Operational output using that JSON can inherit the error.

**Current handling:** No predicate reordering or fabricated correction.
The native test inspects the generated netlink program.

**Next step / closure:** Investigate comparison coalescing in the listing code.
Require separate, correctly attributed comparisons in text and JSON, together
with packet tests and list/reload validation.

**Coverage:** `test_native_comparisons_program_distinct_fields` in
[test_firewall_connection_live.py](../../tests/test_firewall_connection_live.py).

## NFT-006: TTL bounds are displayed as an inverted range

**Status:** Previously reproduced in nftables 1.1.7; tested packet behavior is correct.

Adjacent `ip ttl > 10` and `ip ttl < 20` comparisons can be listed as
`ip ttl != 20-10`. Tests at TTL values 10, 15 and 20 confirmed the intended
exclusive bounds. Do not treat the printed range as the rule's actual semantics.

**Current handling:** Smoketests assert packet behavior. This may share a listing
problem with NFT-005, but a common root cause has not been established.

**Next step / closure:** Verify correct IPv4 TTL and IPv6 hop-limit text/JSON
reconstruction, boundary matching and list/reload behavior.

**Coverage:** `test_ttl_range_packet_behavior_ipv4` and
`test_ttl_range_packet_behavior_ipv6` in [test_firewall.py](../../functionaltests/network/test_firewall.py).

## FRR-BGP-001: Peer-group community selection does not retain member overrides

**Status:** Reproduced with FRR 10.7.1 in ordinary CLI mode.

After configuring `no neighbor G send-community extended` on a peer group,
`neighbor 192.0.2.2 send-community extended` on a member returns success but
`show running-config` omits it. `show bgp neighbors 192.0.2.2 json` still reports
only standard/large communities in `commAttriSentToNbr`. nVyR rejects member
attempts to re-enable classes disabled by their peer group. Narrowing the group's
selection is supported and passed native reload/readback tests.

Retest native configuration readback, neighbor effective flags, reload and
restart before removing the restriction. No upstream report or fix is confirmed.

## FRR-BGP-002: Default-originate timer cannot round-trip disabled state

**Status:** Reproduced with FRR 10.7.1; nVyR defers this parameter.

`bgp default-originate timer 0` cancels periodic evaluation, but the configuration
writer omits zero. A fresh instance defaults to five seconds. In addition,
`no bgp default-originate timer 10` sets zero rather than restoring five seconds.
Consequently an absent line cannot distinguish disabled evaluation from the
native default, and removing a custom timer through reload changes its meaning.

The pinned `bgp_vty.c` setter (`bgp_def_originate_eval`) and writer agree with
this observation. A future fix needs to preserve zero in configuration output
and restore the documented default on removal. Retest native readback, reload
in both directions, and restart before exposing the setting. No upstream fix
is confirmed. Neighbor-level `default-originate` remains supported.

## FRR-BGP-003: General parameter flag collisions and incorrect writer flags

**Status:** Reproduced with the pinned FRR 10.7.1 package; affected parameters deferred.

- `bgp always-compare-med` and `bgp deterministic-med` cause the writer to emit
  `use-underlays-nexthop-weight`. The writer tests
  `BGP_WECMP_BEHAVIOR_USE_RECURSIVE_VALUE` (an enum value) instead of
  `BGP_FLAG_USE_RECURSIVE_WEIGHT`; its negation handler has the same wrong flag.
  Replaying that output can change unrelated behavior, so nVyR does not hide
  the extra line or expose either MED switch yet. Best-path MED confederation
  and missing-as-worst controls remain available.
- `BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS` and
  `BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW` both use bit 45. Enabling either
  `bgp bestpath use-imported-attributes` or
  `bgp default software-version-capability latest-encoding` enables both.
  Both affected options are deferred; legacy software-version capability works.

Native testing on October 29 also confirmed that `neighbor ...
addpath-tx-bestpath-per-AS` automatically enables deterministic MED and triggers
the same incorrect writer line. The proposed `addpath transmit best-per-as`
option is deferred too. `all` and `best-selected` round-trip correctly and remain
available. Removing best-per-AS can also make reload attempt to remove
deterministic MED before its dependent AddPath setting; do not conceal that
failure by discarding the extra running-config lines.

These findings are confirmed in the pinned `bgpd.h` / `bgp_vty.c` and native
reload/readback tests. No upstream fix is confirmed. Retest independent enable,
disable, readback, restart, and preservation of unrelated flags after a fix.

## FRR-BGP-004: Instance shutdown message is not persisted

**Status:** Reproduced with FRR 10.7.1; the optional message is deferred.

`bgp shutdown message Planned maintenance` shuts down the instance, but its
writer emits only `bgp shutdown`. The message therefore cannot round-trip
through reload or restart. Plain instance shutdown remains supported. Retest
message replacement/removal and restart persistence before exposing this field.

## FRR-BGP-005: Minimum hold time 180 is omitted from configuration

**Status:** Reproduced with FRR 10.7.1; nVyR rejects only the affected value.

`bgp minimum-holdtime 180` succeeds but produces no line in `show running-config`.
The writer excludes both zero (no minimum) and `SAVE_BGP_HOLDTIME` (180 in the
traditional profile), despite these representing different minimums. Other
tested values round-trip normally. Verification rejects 180 until its readback
and restart persistence are fixed; no upstream fix is confirmed.

## FRR-BGP-006: Negative peer-group overrides do not retain the requested state

**Status:** Reproduced with FRR 10.7.1; the five proposed negative override leaves
are deferred.

With a group configured for shutdown/passive, `no neighbor <member> shutdown`
does not enable the member: native neighbor JSON still reports `adminShutDown:
true`. Neither this negation nor passive negation appears in running-config.
Member negations of group next-hop-self, route-reflector-client and
default-originate also disappear from the saved configuration.

Ordinary peer/group settings remain supported. nVyR does not flatten peer-groups
or treat missing negative lines as equivalent to a successful override. Retest
effective runtime state, writer output, reload, removal and restart before adding
`no-shutdown`, `no-passive`, `disable-next-hop-self`,
`disable-route-reflector-client`, or `disable-default-originate`. Address-family
`disable` was tested separately and correctly persists deactivation.

## LINUX-NFT-001: Flowtable interface prefixes require newer hook support

**Status:** Resolved in nVyR's pinned Linux `6.18.58-nvyr-amd64` image, tested
with nftables `1.1.7` on 2026-10-25. The previous Linux
`6.12.113+deb13-amd64` failure was a missing kernel feature, not a parser bug.

In an isolated network namespace, an exact veth device installs successfully,
but both an existing-device prefix and a prefix with no matching devices fail:

```text
add flowtable inet test exact { hook ingress priority 0; devices = { "nvtest0" }; }
add flowtable inet test prefix { hook ingress priority 0; devices = { "nvtest*" }; }
```

The second command returns `Could not process rule: Invalid argument`. Upstream
added native wildcard hook specifications in commit `6d07a289504a`;
see the [kernel patch](https://lists.openwall.net/netdev/2025/05/23/155) and
[nftables userspace support](https://www.spinics.net/lists/netfilter-devel/msg92231.html).

The replacement ISO was booted and installed in a disposable VM. Native checks
confirmed empty prefixes, late device creation, deletion/recreation, rename into
and out of the prefix, and removal of the table's hooks. Hook counts remained
exactly one for matching devices, with the original flowtable handle retained.
`CONFIG_NETFILTER_NETLINK_HOOK` is enabled so `nft list hooks` exposes this state.

IPv4 and IPv6 packet functional tests confirmed conntrack's `OFFLOAD` state and one
successful-enrollment counter increment through a prefix-selected flowtable.
Exact-device enrollment and rejected TCP-reset enrollment also passed.

nVyR accepts trailing-`*` prefixes in flowtable interfaces. Follow-up checks on
6.18.63 also confirmed absent exact names for flowtables and ingress chains: hooks
attach when the interface is created. Overlapping selectors in different
equal-priority flowtables are rejected. This requires the new ISO kernel, not just an updated
nVyR `.deb`. Regression coverage lives in
[`tests/test_kernel_flowtables_live.py`](../../tests/test_kernel_flowtables_live.py),
[`smoketests/test_firewall_interface_patterns.py`](../../smoketests/test_firewall_interface_patterns.py)
and [`functionaltests/network/test_firewall_flowtable_packets.py`](../../functionaltests/network/test_firewall_flowtable_packets.py).

## FRR-OSPF-001: Deferred configuration and replay limitations

**Status:** Reproduced on FRR 10.7.1, amd64; the affected options are not exposed.

- A virtual link is rejected until ospfd already considers the process an ABR.
  A valid eventual topology therefore cannot reliably be configured in one
  initial commit or replayed at boot.
  Upstream removed this operational-state check in
  [FRR PR #22979](https://github.com/FRRouting/frr/pull/22979), merged on
  2026-08-29 after 10.7.1 as
  [`b29b3372f356d72ddfecc4efddb38fbd05b743e6`](https://github.com/FRRouting/frr/commit/b29b3372f356d72ddfecc4efddb38fbd05b743e6)
  (fix commit
  [`92d85af830d2813569d50e319031a4e17b95a070`](https://github.com/FRRouting/frr/commit/92d85af830d2813569d50e319031a4e17b95a070)).
  When upgrading FRR, check whether that commit or an equivalent backport is
  included, then retest first-commit configuration and boot replay before
  enabling virtual links in the schema. The fix retains the prohibition on
  backbone, stub, and NSSA transit areas; operational activation still depends
  on SPF reachability to the remote endpoint.
- Per-address `ip ospf authentication-key KEY ADDRESS` silently omits the key:
  the command handler advances its argument index past the key when finding
  the address. Ordinary interface plaintext authentication works.
- Hidden `ospf lsa-refresh` and `ospf maxage-delay` commands do not survive
  native configuration readback. The separate `refresh timer` command works.
- The FRR daemon instance list does not support combining ordinary ospfd with
  numbered instances using an entry of zero. Numbered instances are deferred.

These are explicit scope deferrals, not readback normalization exceptions.
Retest first-commit application, replacement, removal and boot replay before
exposing the affected syntax. No upstream fixes have been incorporated for them.

## FRR-RELOAD-002: Keychain and OSPF reset defects

**Status:** Fixed locally in the FRR 10.7.1 `nvyr2` packages.

Key lifetime whitespace differs between file loading and native readback, and
the reload script incorrectly negates the full positive command. The native
operand-free removal handlers also address the wrong YANG paths. The keychain
patch corrects all three; unrelated commits, replacement and removal are tested.

OSPF aggregation timers, detailed adjacency logging and OSPFv3 graceful restart
need reset forms different from a simple negation of their positive commands.
Static OSPFv3 neighbor options must be removed before the neighbor itself;
otherwise their reset handlers recreate the neighbor. The OSPF reload patch
corrects the reset commands and deletion ordering, including stub/NSSA removal
after area default-cost resets. It also prevents the global opaque-extension
writer from emitting Router Information settings into nondefault VRFs, where
the native CLI rejects them. The live smoketests verify
that both creation and cleanup retain the requested native state.

See [patch provenance and retest requirements](../../vendor/frr/README.md).
No upstream fix is claimed; reevaluate these patches with the next FRR upgrade.

## Updating this tracker

For each investigation, record:

- Exact dependency and kernel versions, architecture, and reproduction steps.
- Whether the failure affects parsing, installed state, actual traffic, listing,
  or export/restore; keep those findings separate.
- Upstream report and patch links, commit IDs, and first verified fixed version.
- nVyR restrictions or lifecycle decisions and their associated regression tests.
- Retest evidence and the precise checks that can be removed after shipping a fix.

Keep unresolved native defects visible. Do not byte-swap user input, suppress
failures, or infer a fix from a similar patch title alone.

## NFT-JSON-FLOWTABLE: Counter flag omitted from JSON listings

**Status:** Reproduced with nftables 1.1.7 and Linux 6.18.58-nvyr-amd64.
A flowtable configured with `counter;` shows that option in `nft list flowtable`,
but `nft -j list ruleset` omits it from the flowtable object. The flag works:
IPv4 and IPv6 packet tests confirmed that offloaded packets update conntrack
accounting. No upstream report has been filed.

The operational normalizer preserves the available kernel listing without
inventing an installed flag from configuration. Use the native text listing to
inspect the option and conntrack detail for packet/byte totals. Recheck JSON
round-trip support when upgrading nftables.


## FRR-ISIS-001: hello-padding removal changes the default

FRR 10.7.1 reload negates `isis hello padding during-adjacency-formation`.
That negative command disables padding, while an absent setting means always
pad. `vendor/frr/isis-reload.patch` restores the positive default form when removing
an explicit mode. Test configure, change and deletion when upgrading FRR.

## FRR-ISIS-002: table redistribution edits and removal

FRR 10.7.1's native table handler returns success without updating existing entries.
Deleting the final table destroys an already-absent child collection, leaving a
hidden protocol/level parent that can reject subsequent `is-type` changes. Native
return statuses are also discarded. Table attribute edits do not reach the correct
runtime registration, and IPv6 table create/destroy callbacks are unfinished.

`vendor/frr/isis-reload.patch` fixes the handler and applies per-table attributes
through the common finish callback for both families. Recheck edits, last-entry
removal, level changes and actual advertisement/withdrawal before removing it.
These fixes ship in FRR `10.7.1-0~deb13u1+nvyr5`.

Circuit option resets also precede removal of the final IS-IS address-family
binding and process, so removal does not recreate an interface container missing
its mandatory area tag. The native runtime test verifies advertisement metrics,
route-map withdrawal, table removal and complete interface cleanup.

## FRR-ISIS-003: late route-map references remain unresolved

**Status:** Fixed locally in FRR `10.7.1-0~deb13u1+nvyr5`.

The IS-IS map callback re-evaluates redistributed routes without refreshing the
stored map pointer. A reference configured before its map therefore remains
unresolved, and deletion/recreation can retain a reference to the old map object.
Acceptance reproduced healthy adjacencies with no exported connected routes in
both the default and named VRFs. Reapplying redistribution resolved the map and
immediately restored advertisements; it is diagnostic evidence, not a workaround
used by nVyR.

`vendor/frr/isis-reload.patch` refreshes the reference and its usage counter before
re-evaluation. The native regression configures the reference first, then creates,
deletes and recreates the map while checking IPv4 and IPv6 advertisements. It fails
on the unpatched callback. Retest this sequence before removing the patch on an
FRR upgrade; no upstream fix or report is claimed.
