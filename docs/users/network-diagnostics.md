# Network diagnostics

For implementation and testing, see the [developer guide](../dev/network-diagnostics.md).

Use `ping` to test reachability and `traceroute` to inspect the path to a
destination. Both stream their output and support Ctrl+C to return to the CLI.
From configuration mode, prefix either command with `run`.

## VRF selection

Both tools accept `vrf <name>`, with configured VRFs offered in completion:

```text
ping 192.0.2.1 vrf BLUE count 5
ping 2001:db8::1 ipv6 vrf BLUE count 5

traceroute example.com vrf BLUE no-resolve
traceroute 2001:db8::1 ipv6 vrf BLUE icmp
```

The entire utility runs through `ip vrf exec`, including hostname resolution.
`interface` and `source-address` can still select the source within that VRF.
Use `vrf default` to explicitly select the default routing instance; omitting
`vrf` preserves normal command execution. An unavailable VRF produces an error.


## Ping

`ping` uses an anchored destination tag with leaf options. Options can appear in
any order, with the usual abbreviation, validation, Tab completion and `?` help:

```text
ping 1.1.1.1 count 5 interval 0.5 numeric
ping 1.1.1.1 numeric interval .5 count 5
ping ::1 ipv6 count 1
ping example.com interface eth0 source-address 192.0.2.1
run ping 127.0.0.1 count 1
ping 192.0.2.1 dscp 46 count 5
```

All supported options are listed by `ping <destination> ?`. Their meanings follow
[Debian's iputils ping](https://manpages.debian.org/trixie/iputils-ping/ping.8.en.html).
Completion offers available interfaces and hints for each value. Both `interface`
and `source-address` may be supplied; the selected interface, address family and
packet size must be valid for the host.
`dscp` accepts 0–63 and sends TOS as DSCP multiplied by four; it cannot be combined
with `tos`.

Replies appear immediately, Ctrl-C stops probing and returns to the CLI, and Linux
ping's exit status is preserved. Without `count` or `deadline`, it runs until
interrupted. Output modifiers are rejected for streaming commands, even when a
probe has a count or deadline. Run `ping 127.0.0.1 count 1` without a pipe.

## Traceroute

`traceroute` uses the same anchored destination and streaming execution as ping:

```text
traceroute 192.0.2.1 tcp port 443 probes 1 wait 1 no-resolve
traceroute 2001:db8::1 ipv6 icmp max-ttl 15
run traceroute example.com size 1000 dscp 46 do-not-fragment
```

Options can appear in any order. `size` becomes the positional packet length after
the destination. `wait` accepts only a maximum timeout, including fractional
seconds, rather than the underlying utility's optional additional timing factors.
`mark` becomes `--fwmark=<value>` and `dscp` becomes `-t <value times 4>`.

Choose only one address family, probe protocol and TOS/DSCP option.
`first-ttl` must not exceed `max-ttl` (defaults 1 and 30), and literal source and
destination addresses must agree with the selected family. Hostnames are resolved
by traceroute. Supported numeric ranges include
1–10 probes per hop and a maximum packet size of 65,000 bytes. These follow
[traceroute's manual](https://man7.org/linux/man-pages/man8/traceroute.8.html) and
[Debian's traceroute source](https://sources.debian.org/src/traceroute/).

All roles can use this diagnostic. Output streams immediately, Ctrl+C returns to the prompt,
and pipe modifiers are rejected.
