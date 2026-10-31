# Zone-based firewall

Zones classify member interfaces independently of VRFs. Policies use
[named firewall chains](firewall.md#named-chains-and-jumps) assigned to directional
zone pairs.

## Configuration

Create the zones and policy chains, then assign the policies:

```text
set firewall zone USERS description "User networks"

set firewall zone USERS interface eth1
set firewall zone USERS interface eth2
set firewall zone USERS default-action drop

set firewall zone WAN interface eth0

set firewall zone LOCAL local-zone
set firewall zone LOCAL default-action drop

set firewall ipv4 name USERS_TO_WAN default-action drop
set firewall ipv4 name USERS_TO_WAN rule 10 protocol tcp destination-port 443 action accept

set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy USERS_TO_WAN

set firewall ipv6 name USERS_TO_WAN default-action accept

set firewall zone-policy from-zone USERS to-zone WAN ipv6-policy USERS_TO_WAN

set firewall ipv4 name USERS_TO_LOCAL default-action drop
set firewall ipv4 name USERS_TO_LOCAL rule 10 protocol tcp destination-port 22 action accept

set firewall zone-policy from-zone USERS to-zone LOCAL ipv4-policy USERS_TO_LOCAL

set firewall ipv4 name LOCAL_TO_WAN default-action accept

set firewall zone-policy from-zone LOCAL to-zone WAN ipv4-policy LOCAL_TO_WAN

set firewall zone USERS intra-zone default-action drop

set firewall ipv4 name USERS_INTERNAL default-action accept

set firewall zone USERS intra-zone ipv4-policy USERS_INTERNAL

set firewall ipv6 name USERS_INTERNAL default-action accept

set firewall zone USERS intra-zone ipv6-policy USERS_INTERNAL
```

## Default actions and membership

Zone defaults support `accept` and `drop`, with implicit `drop`. Intra-zone
defaults support the same choices, with implicit `accept`. A family policy
overrides its default. Without a policy, traffic between different known zones
uses the destination zone's default. A missing family policy does not inherit
the other family's policy.

An interface belongs to at most one zone. Ordinary zones require interfaces;
the single optional local zone cannot have interfaces or intra-zone settings.
VRF masters cannot be assigned, but their member interfaces can. Policy targets
must exist in the corresponding address family. References protect
referenced zones, interfaces, and policy chains from deletion.

## Interface wildcards

Zone members can use prefixes:

```text
set firewall zone VPN interface wg*
set firewall zone LAN interface eth1.*

set firewall zone-policy from-zone VPN to-zone LAN ipv4-policy VPN_TO_LAN
set firewall zone-policy from-zone VPN to-zone LAN ipv6-policy VPN_TO_LAN
```

Define the referenced policies in their respective families first. A prefix must
not overlap another zone's exact name or prefix: `wg*` conflicts with both
`wg0` and `wg1*`, while `wg0*` and `wg1*` are disjoint. Redundancy within one
zone is merged. Prefixes matching a configured VRF master are rejected.
Generated zone maps use native interval keys for prefixes and retain their
per-element comments and counters.

## Input processing order

For traffic addressed to the router, the INPUT filter evaluates:

1. Global state policies, followed by family-neutral `inet` rules.
2. Numbered input rules for the packet's address family, in rule-number order.
3. The applicable zone policy or zone default.
4. The normal input hook's `default-action`, if no earlier step decided the verdict.

An earlier accept or drop decides the verdict for this filter hook. For example,
a management-access rule in the numbered input rules can allow SSH before zone
policies are evaluated. Traffic from an interface without an applicable zone entry
reaches the normal input default. A zone policy that returns also continues to
that default. Traffic between known zones without a policy instead uses the
zone defaults described above.

Forward and output filtering likewise evaluate their numbered rules before zone
policies, with their normal hook default as the fallback.

When zone handling is active, `commit check` and `commit` warn about each IPv4 or
IPv6 input, output, or forward filter whose normal default is `accept`, including
an implicit default. Traffic on interfaces not assigned to a zone may be allowed
by that fallback. These warnings do not prevent the commit or replace verification
of the rest of the configuration.

## Setting up zones while retaining management access

Keep the normal input default at `accept` while setting up zones. First add an
explicit management rule with a counter, before any numbered rules that could
drop that traffic. This example uses rule 5, SSH on port 22, and an administrator
at `192.0.2.10` arriving on `eth1`; replace those values for your network and use
an unused rule number.

```text
set firewall ipv4 input filter rule 5 description "Management SSH during zone setup"
set firewall ipv4 input filter rule 5 counter

set firewall ipv4 input filter rule 5 action accept protocol tcp destination-port 22
set firewall ipv4 input filter rule 5 source-address 192.0.2.10 inbound-interface eth1

set firewall ipv4 input filter default-action accept

commit
```

The normal default of `accept` only permits traffic that reaches it. A matching
zone policy or zone default can still drop traffic, which is why the earlier
management rule matters.

**Verify packets reach the management rule before changing the default action.**
Check its packet counter, open a fresh SSH connection from the permitted address,
and check that the counter increased:

```text
run show firewall ipv4 input filter rule 5
```

An existing SSH connection may be accepted by the global established-state policy
before reaching rule 5. Use a fresh connection rather than relying on the current
session staying connected. If the counter does not increase, resolve the match or
an earlier rule's effect before proceeding.

Configure the zones and their policies, then verify the intended access. When
ready, change the normal input default to `drop` with a confirmed commit:

```text
set firewall ipv4 input filter default-action drop

commit-confirm 5
```

Open another SSH connection and verify access before the five-minute deadline.
From configuration mode, confirm and save:

```text
confirm
save
```

Keep the management rule if it is intended to override zone policies. If access
should be controlled entirely by zones, first configure the appropriate policy
to the local zone, then remove the temporary management rule using another
confirmed commit and verify a fresh login again. Repeat the setup and checks for
IPv6 if you manage the router over IPv6; IPv4 rules do not protect IPv6 access.

## VRF output behavior

VRF-bound local traffic can first reach OUTPUT with the VRF master as `oifname`.
When output zone dispatch is active, a generated `meta oifkind "vrf" counter accept`
rule permits that preliminary pass. It appears after numbered output rules and
immediately before the zone map, with the comment `vrf-bypass`. The subsequent
member-interface pass still evaluates the zone policy and normal output default.
Explicit output rules retain precedence on both passes. No bypass is added to
raw chains or to output filter chains without zone dispatch.

## Operational commands and counters

```text
show firewall zone
show firewall zone detail

show firewall zone ipv4
show firewall zone ipv6

show firewall zone ipv4 USERS
show firewall zone ipv6 LOCAL detail
```

Zone dispatch maps also appear in `show firewall`. These displays show installed
interface mappings, zone relationships, verdicts, and per-element packet/byte
counters. Counters record packets selecting the map element, regardless of the
eventual policy verdict. They survive unrelated commits and reset when their
map is rebuilt or during full firewall recovery.

A zone name filters by the source zone. An ordinary zone shows its forward and
input entries; the local zone shows its output entries. The optional family
selects only IPv4 or IPv6 maps. Firewall output separates each table with a
visible heading divider.
