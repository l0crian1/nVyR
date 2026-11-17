# Connection tracking operations

For implementation and testing, see the [developer guide](../dev/conntrack-operations.md).

Inspect active kernel connections, filter them by family or tuple, and clear
runtime connection state when needed. These views also supply the data for
[NAT translations](nat.md#operational-views).

## Commands and filters

```text
show conntrack
show conntrack ipv4
show conntrack ipv6
show conntrack ipv4 offload
show conntrack ipv6 offload detail
show conntrack ipv4 accounting detail
show conntrack ipv6 offload accounting detail
show conntrack ipv4 accounting sort-by bytes
show conntrack ipv4 sort-by source reverse

show conntrack state established
show conntrack ipv4 protocol tcp state established
show conntrack ipv6 source-address 2001:db8::10 detail
show conntrack destination-address 198.51.100.20

show conntrack statistics

clear conntrack
```

Filters are anchored and may be combined in any order. `ipv4` and `ipv6` are
mutually exclusive. Source and destination filters are exact original-tuple
addresses, before NAT; an address alone selects its family. Conflicting families
and a transport state incompatible with the selected protocol produce errors.

`state` means the kernel's TCP, SCTP or DCCP protocol state, such as `established`,
`syn-sent` or `cookie-wait`. It does not mean nftables packet-level `ct state new`
or `related`. UDP and ICMP do not have those transport states and show an em dash.
State alone searches applicable protocols; `protocol tcp state established`
selects only TCP.

`offload` selects connections currently marked as software or hardware offloaded
by the kernel. Combine it with `detail` to see the `offload`/`hw-offload` status
flags and available original/reply packet and byte counters. It also works with
the shared `show nat ... translations` filters. This reports current status, not
whether a connection was offloaded earlier in its lifetime.

`accounting` selects connections with packet counters available in either
direction, including counters whose value is zero. Add `detail` to display
the packet and byte counts. It combines with the other filters and also works
with NAT translation views. It does not enable accounting; connections created
without accounting are excluded. The summary replaces State and Timeout with
Packets and Bytes, totaled across the original and reply directions. If either
direction's counter is unavailable, its combined total shows `—`; `detail`
still shows each available directional counter.

`sort-by` accepts `packets`, `bytes`, `source`, `destination`, `state`, and
`timeout`. Counters and timeout sort highest first; state sorts alphabetically.
Source and destination sort by numeric original address, then numeric port,
with IPv4 before IPv6. Add `reverse` to invert the selected order. Missing
values remain last, including missing ports within the same address.

Sorting by packets or bytes selects the accounting columns but does not exclude
connections without counters. Use `accounting` as well to exclude them. Sorting
also applies to detailed output and NAT translation views; NAT endpoints are
ordered by their original, pre-NAT addresses and ports.

## Output and statistics

The default table shows family, protocol, original endpoints, state and remaining
timeout. IPv6 endpoints with ports use brackets. `detail` shows original and reply
tuples, status flags and their full mask, mark, zone, kernel connection ID, numeric
label bit positions, and per-direction packet/byte counters when accounting is
available. Counters omitted by the kernel are not presented as zero. Viewing
connections does not enable accounting or change the table.

Statistics show occupancy, capacity and utilization, followed by summed per-CPU
kernel diagnostic counters. These counters are cumulative diagnostics, not a
breakdown of currently active connections. Statistics cannot be combined with
connection filters or `detail`. A live dump is an observation of a changing table,
not an atomic snapshot; connections may expire during inspection.

## Permissions and clearing state

All show commands are available to operators. `clear conntrack` retains its
net-admin requirement and confirmation, and clears connections and NAT state.
