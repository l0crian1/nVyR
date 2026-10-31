# Static routing displays: implementation and maintenance

For configuration and command usage, see the [user guide](../users/static-routing-operations.md).

## Internal structured output

`static.nvyr.op show` accepts an internal `--raw` flag:

```sh
static.nvyr.op show 'show ip route static' --raw
static.nvyr.op show 'show static routes vrf default' --raw
```

The script validates the command through the same operational schema, resolves
abbreviations, removes a configuration-mode `run` wrapper, and sends one
read-only command to `vtysh`. `--raw` appends FRR's `json` option. There is no
`json` or `raw` command in the nVyR operational tree.

Raw mode returns serialized JSON with FRR's original structure. It does not
print Python dictionary representations or normalize the data. Future API
callers can decode it directly. This does not add a REST endpoint.

Command failures remain errors. Invalid or unsupported JSON output raises a
clear error instead of silently returning text. In particular, FRR 10.7.1 can
emit multiple JSON documents for `show ip route table all json`; that output
is rejected in raw mode. Use an individual table for structured queries.

The shared execution helper is `nvyr.helpers.vtysh.show()`. Other routing
scripts can reuse it after validating their own supported command paths.

## Positional command-tree values

Operational tag nodes can declare `positional: true`. Their YAML name identifies
the schema branch but is not a CLI keyword. For example:

```yaml
destination:
  kind: tag_node
  positional: true
  command: ['static.nvyr.op', 'show', '@line']
  validators:
    ipv4-prefix: {}
  hints:
    x.x.x.x/x: IPv4 destination prefix
```

This lets a parent accept a bare prefix, including after a named VRF. Each parent
can have one positional child, alongside ordinary named children. Named keywords
and their abbreviations take precedence; positional values retain validators,
choices, suggestors, hints, access restrictions and child commands. These are
operational declarations, not configuration nodes.

`@line` and `@1`, `@2`, etc. retain the original input positions. A resolved
cursor's internal path includes the schema branch name; `schema.command_path()`
removes that name and expands keyword abbreviations without reordering tokens.
The route wrapper uses this shared translation, not per-command argument maps.
An operational positional tag may also omit its own command when it has children.
In that case a child command is required before Enter becomes available, as with
`show bgp ipv4 unicast neighbors <peer> routes`.

References:

- [FRR static route status](https://docs.frrouting.org/en/stable-10.7/static.html#showing-static-route-status)
- [FRR Zebra routing displays](https://docs.frrouting.org/en/stable-10.7/zebra.html)
