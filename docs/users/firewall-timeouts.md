# Connection timeout groups

Timeout groups give selected TCP or UDP connections their own tracking lifetimes.
For example, shorten idle DNS tracking without changing every UDP connection, or
keep an application's established TCP connections longer than the global default.
These are connection-tracking policies, not rate limits or packet verdicts.

## Configure a policy

Groups have separate `inet`, `ipv4`, and `ipv6` namespaces. Use `inet` for one
policy applied to both address families through family-neutral rules.

```sql
set firewall group timeout-group inet DNS description "Short-lived DNS connections"

set firewall group timeout-group inet DNS protocol udp
set firewall group timeout-group inet DNS timeout unreplied 10s replied 30s

set firewall inet forward filter rule 10 protocol udp destination-port 53
set firewall inet forward filter rule 10 connection timeout-group DNS action accept
```

Each group requires a protocol and at least one timeout. Durations accept positive
integer values followed by `s`, `m`, `h`, or `d`, up to 2,147,483 seconds.
Omitted states inherit the corresponding firewall global connection-tracking
timeout. Changing an inherited global value also replaces the affected policy.

UDP states are `unreplied` and `replied`. The latter corresponds to the global
UDP `stream` timeout; the kernel applies its normal stream qualification.

TCP states are `syn-sent`, `syn-received`, `established`, `fin-wait`, `close-wait`,
`last-ack`, `time-wait`, `close`, `unacknowledged`, and `max-retransmissions`.

```sql
set firewall group timeout-group ipv4 APP description "Application TCP sessions"

set firewall group timeout-group ipv4 APP protocol tcp
set firewall group timeout-group ipv4 APP timeout established 1d close 20s

set firewall ipv4 forward filter rule 20 protocol tcp destination-port 8443
set firewall ipv4 forward filter rule 20 connection timeout-group APP action accept
```

The equivalent IPv6 policy uses `timeout-group ipv6 APP` and an
`firewall ipv6` rule. A rule references only a group in its own family namespace.
Protocol matching must select exactly the group's transport; a map or match-group
may supply that protocol instead of an explicit rule match.

## Placement and connection lifetime

Assignment is available in input, forward, and output filter rules and named
chains. Raw and ingress run before connection tracking and cannot assign these
policies. Verification follows nested jumps to reject unsupported callers.

The assignment executes after the rule's matches and before its verdict. Ensure
the opening packet reaches this rule. A global established-state accept can then
handle later packets without repeating the assignment.

Changes to a group and its rules take effect together. Unrelated rules are
unaffected. An `inet` timeout group applies to both IPv4 and IPv6.

**Replacing or deleting a timeout object detaches it from existing connections.**
It does not immediately rewrite their remaining timers or terminate them. In
native testing, later packets accepted by the global established-state policy
refreshed those connections using the global timeout. New connections receive
the replacement policy when they reach its assignment rule. nVyR does not clear
existing connections as part of a policy update.

## Inspect installed policies

```text
show firewall group timeout-group
show firewall group timeout-group inet
show firewall group timeout-group inet DNS
show firewall group timeout-group inet DNS detail

show conntrack
```

The group table shows the installed family, protocol, state, timeout, and
description. An `inet` group displays both native families under one heading.
Rule detail output includes the timeout-group reference.
