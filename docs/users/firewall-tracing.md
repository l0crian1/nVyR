# Packet trace analysis

For implementation and testing, see the [developer guide](../dev/firewall-tracing.md).

nVyR tracing follows traffic through installed nftables rules and relates native
events to nVyR configuration paths. It shows which rules were evaluated, their
observed verdicts, named-chain jumps and returns, packet-header changes, and
connection-tracking information supplied by the kernel.

## Capture selected traffic

Enable tracing in a rule early enough to see the processing you are investigating.
Keep its matches specific to avoid capturing unrelated traffic:

```sql
set firewall ipv4 prerouting raw rule 10 description "Investigate the published application"

set firewall ipv4 prerouting raw rule 10 protocol tcp destination-port 443
set firewall ipv4 prerouting raw rule 10 source-address 192.0.2.10
set firewall ipv4 prerouting raw rule 10 nftrace action continue
commit
```

Capture from operational mode while generating the test traffic. Use `run` in
configuration mode:

```text
monitor firewall trace duration 30s save /config/traces/application.jsonl
```

The monitor streams events immediately and writes complete JSON Lines records
as they arrive. It does not retain the entire capture in memory. Files are private,
cannot overwrite existing files, and must reside directly in `/config/traces/`.
Ctrl+C stops collection and preserves already written records.

Tracing stays enabled until its configuration is removed:

```sql
delete firewall ipv4 prerouting raw rule 10 nftrace
commit
```

## Find the relevant trace

List saved captures, then display the index for a capture:

```text
show firewall trace

show firewall trace /config/traces/application.jsonl
```

The index contains native trace ID, observed address family, protocol, initial
source and destination, interfaces encountered, event count, observation passes,
last observed verdict, and its configuration location. Addresses include ports
when available; IPv6 endpoints use brackets.

Filters are anchored and can be combined in either order:

```text
show firewall trace /config/traces/application.jsonl ipv4 protocol tcp
show firewall trace /config/traces/application.jsonl destination-port 443

show firewall trace /config/traces/application.jsonl source-address 192.0.2.10 verdict drop
show firewall trace /config/traces/application.jsonl hook forward

show firewall trace /config/traces/application.jsonl path "nat destination rule 10"
show firewall trace /config/traces/application.jsonl path "firewall ipv4 name APPLICATION"
```

Supported filters are `ipv4`, `ipv6`, `protocol`, `source-address`,
`destination-address`, `source-port`, `destination-port`, `verdict`, `hook`, and
`path`. Address and port filters match observations before **or** after NAT.
Combined packet filters must match the same observation; a public address and
its translated port are not combined into a tuple that never existed.

The `path` filter selects an exact configuration path or its descendants.
`verdict` filters the last native verdict, so a reject statement appears as
`drop`; its story includes the reject response expression.

## Read a packet story

Select an ID from the index:

```text
show firewall trace /config/traces/application.jsonl id bd40a672

show firewall trace /config/traces/application.jsonl id bd40a672 detail
```

The default report starts with the flow, ingress, and egress, followed by five
sections:

- **Story:** a concise account of arrival, connection state, forwarding, chain
  calls and returns, NAT, and the last observed verdict.
- **Tables and chains visited:** every observed visit in order, including repeat
  visits to callers and chains with no recorded rule hits. Table identity
  includes the native address family.
- **Rules hit:** recorded rules with full nVyR paths, descriptions, operations,
  and referenced groups. Base-chain policies are not presented as rule hits.
- **Observed changes:** before/after packet values, including addresses, ports,
  TTL, IPv6 hop limit, marks, and interfaces.
- **Outcome:** the last observed decision and its location.

`L<number>` references the saved capture's line number. The itinerary's evidence
column points to the first event for that visit, or the jump/goto which identifies
its target. Empty and nonmatching chains can emit no events of their own. When
processing resumes in the jump caller, the report records **No rule hit recorded;
returned**. A target with no subsequent evidence stays visible without claiming
that it returned or that no rule matched.

For example, this report was rendered from a native TCP rejection capture:

```text
Trace e6ff4c0e
════════════════════════════════════════════════════════════════════════════

Flow       TCP 192.0.2.2:43126 → 198.51.100.2:9000
Ingress    tr-in
Egress     tr-out

STORY
────────────────────────────────────────────────────────────────────────────
• The packet arrived on interface "tr-in" with TCP SYN set.
• The forwarding path used egress interface "tr-out" (L5).
• TTL changed from 64 to 63 (L5).
• Rule 30 in IPv4 forward firewall rejected with a TCP reset; dropped (L10).
• Last observed verdict: DROP at firewall ipv4 forward filter rule 30 (L10).

TABLES AND CHAINS VISITED
────────────────────────────────────────────────────────────────────────────
Table             Chain         Evidence    What happened
----------------  ------------  ----------  -------------------------------------------
inet nvyr_filter  prerouting    L2          Base-chain policy: ACCEPT
inet nvyr_filter  forward       L5          Jumped to the IPv4 forward firewall
inet nvyr_filter  ipv4_forward  L10         Rule 30: rejected with a TCP reset; dropped

RULES HIT
────────────────────────────────────────────────────────────────────────────
L3  firewall inet prerouting raw
      Enabled tracing; continued.

L6  firewall inet forward filter
      Jumped to the IPv4 forward firewall.

L10  firewall ipv4 forward filter rule 30
      Description: reset
      Rejected with a TCP reset; dropped.

OBSERVED CHANGES
────────────────────────────────────────────────────────────────────────────
Location    Field    Before    After
----------  -------  --------  -------
L5          TTL      64        63

OUTCOME
────────────────────────────────────────────────────────────────────────────
DROP — last observed decision at firewall ipv4 forward filter rule 30 (L10).
```

The rule expression and the later observed change are separate evidence.
Port-only translation is reported even when neither address changes. Original
and translated addresses remain available in structured output.

`detail` appends a separate **Native evidence** section after the story. It
includes every event, full rule paths, expressions, handles, observed field
changes, native lines, capture line numbers, and userspace receive timestamps.
Repeated conntrack observations and routine header fields stay in this section
so they do not obscure the default narrative. It can also be used without an ID
to inspect all matching stories:

```text
show firewall trace /config/traces/application.jsonl verdict drop detail
```

## Connection tracking and VRFs

Current kernels can provide separate conntrack observations. nVyR decodes the
connection ID, original/reply direction, state, and status flags while retaining
the native values in the detailed event. For example, a new DNAT connection can
show `state new; status dnat, dnat-done`, followed later by `established` and
`seen-reply`. Numeric TCP flags are displayed by name. IPv4 TTL, IPv6 hop limit,
ICMP type/code, interfaces, marks, and transport endpoints are preserved when
present in the trace.

For VRF output, a story can show an initial `oif TRACEVRF`, the generated
`vrf-bypass` accept, and a subsequent output observation on the actual member
interface. The first accept does not end that packet's processing.

## Reading the evidence correctly

- **Last observed verdict** describes the captured processing, not confirmed
  delivery. An accept can be followed by another hook or base chain.
- A native trace ID is not a connection ID or a permanent packet identifier.
  Linux can reuse it when packet buffers are recycled. Repeated observation
  points or changed packet identifiers start a new displayed pass. nVyR does
  not interpret the boundary as a NAT rewrite. A pass can also be recirculation;
  it is not presented as a definitive count of distinct packets.
- A packet can have several header observations. The event count and observation
  count are not packet counters.
- Tracing begins only after `nftrace` is enabled. Packets dropped earlier or
  forwarded through the flowtable fast path may not appear. A missing event
  does not identify a drop location.
- Receive timestamps are not per-rule kernel processing times. Native messages
  can be buffered before they are read.
- The capture records chain metadata at startup. Rule expressions and comments
  come from the native events themselves. Avoid changing the ruleset during a
  diagnostic capture; hook metadata describes the startup snapshot.

Incomplete captures and undecoded native messages are reported visibly. Unknown
text remains available rather than being silently discarded. Malformed JSON
reports its line number. Analysis is bounded to 128 MiB, 250,000 events, and
10,000 selected trace IDs, with a 1 MiB individual-record limit. Use a narrower
trace rule or a shorter capture when these bounds are reached.
