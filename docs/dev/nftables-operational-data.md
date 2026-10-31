# nftables operational data: implementation and maintenance

For configuration and command usage, see the [user guide](../users/nftables-operational-data.md).

## Normalizer API

`nvyr.helpers.nftables_normalizer.normalize()` converts decoded `nft -j` listings
into dictionaries that operational scripts can use without unpacking nftables
expression trees. It does not execute commands, read configuration, modify the
input, or change the firewall.

An operational script can fetch the full ruleset once, then select its scope:

```python
import json

from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.process import cmd

document = json.loads(cmd(['nft', '-j', 'list', 'ruleset']))
data = normalize(document)

table = data['tables']['inet'].get('nvyr_filter', {})
chain = table.get('chains', {}).get('ipv4_forward', {})

for rule in chain.get('rules', []):
    number = rule.get('number', '')
    description = rule.get('description', '')
    packets = rule.get('counter', {}).get('packets')
```

The same function accepts a single table, chain, set, map, flowtable, counter, limit, or an
inventory listing. Table identity is always **family plus table name**. Under
each table, `chains`, `sets`, `maps`, `flowtables`, `counters`, and `limits` are indexed by their native
nftables names. Rule lists preserve kernel evaluation order, not comment order.

Scoped listings may omit the table definition, referenced objects, or collection
contents. Missing information remains absent: for example, an inventory-only
chain has no `rules` property, and a set without listed elements has no `entries`
property. Use `.get('rules', [])` or `.get('entries', [])` when displaying available
contents. Their absence does not establish that the kernel object is empty.
References do not require their targets to be included in the listing.

## Rules

Known matches use nVyR names directly:

```python
{
    'handle': 42,
    'number': '10',
    'description': 'Allow HTTPS',
    'protocol': ['tcp'],
    'source-address': {'192.0.2.0/24': {}},
    'destination-port': [443],
    'ttl': {'gt': 10, 'lt': 100},
    'action': 'accept',
    'counter': {'packets': 125, 'bytes': 18400},
    'last-used': None,
}
```

- Multi matches are lists, even with one value. IP and MAC address matches always
  use dictionaries keyed by address/prefix, with an optional `mask` in each value.
- Inequalities use a `not` dictionary alongside the corresponding positive
  fields, such as `{'destination-port': [80], 'not': {'destination-port': [443]}}`.
  TTL exclusions are under `ttl.not`; FIB exclusions are under `fib.result.not`.
  Detailed firewall output labels excluded fields with `(not)`.
- Individual numeric values remain numbers; ranges become strings such as
  `8000-8010`. DSCP names emitted by nftables are converted to numeric DSCP values.
- Connection-status values are comma-separated names for each exact bitmask.
  Unknown status bits remain hexadecimal; they are not discarded.
- Native `number|description` comments expose `number` and `description`; the
  original `comment` is also retained. Default rules use number `default`.
- Group references use configured names, such as `source-address-group: LAN` or
  `map: POLICY`. This decoding applies only inside the nVyR-owned `nvyr_filter`
  table. Object dictionaries retain their native names to avoid collisions.
- Map and match-group lookups expose `map-fields` and `match-group-fields` in
  packet-key order. Anonymous verdict maps expose `verdict-map` with `fields`
  and `entries`, including per-element counters.
- NAT exposes its installed `action` (`snat`, `dnat`, `masquerade`, or `return`)
  and a `translation` dictionary. Named NAT maps use the same `map` reference.
- Dynamic updates expose `add-to-group`, including their optional timeout.
  Flow offload exposes `action: offload` and `offload-target`.

Counters contain `packets` and `bytes`. `last-used` is elapsed **seconds**, including
fractions; `None` means never used. An absent tracking field means it was not
provided. Group declarations use booleans for tracking enablement; individual
entries contain the actual statistics. Timeout, expiry, and garbage-collection
interval values are also seconds.

Use normal listings when displaying statistics. A stateless (`-s`) query may
omit those values; an empty counter dictionary means unavailable statistics,
not zero packets. Such a query cannot reliably distinguish last-used state.

## Group entries and configured column ordering

Groups expose `key-datatypes`, an optional `result-datatypes`, and an `entries`
list. Every entry has a `key` list, including singleton keys. Map entries also
have a `result` dictionary (`action`/`jump-target` or `address`/`port`). Entry
comments expose `name` and `description`; anonymous learned entries have neither.

Supply the running configuration when named match columns are needed:

```python
data = normalize(document, configuration=running_config)

group = data['tables']['inet']['nvyr_filter']['maps']['ipv4_map_POLICY']

for entry in group.get('entries', []):
    matches = dict(zip(group['match-fields'], entry['key']))
    source = matches.get('source-address')
    result = entry['result']
```

`match-fields` comes from the same `nft_group_fields()` helper used by the
configuration rendering pipeline, not YAML insertion order. Configuration is
used only to label columns. Entries, statistics, timeouts, and translations
remain kernel data. Singleton groups have their member field (`address`, `port`,
or `interface`) without needing configuration.

The supplied configuration must describe the listing: use running configuration,
not uncommitted candidate changes. Mismatched key datatypes raise `ValueError`
rather than silently mislabeling entries. No configuration or an unconfigured
group leaves map/match-group column names absent; its key list remains available.

TCP flag combinations can expand into several native group elements. With running
configuration supplied, these become one logical entry: packet/byte counters are
summed and `last-used` reports the most recent match. Learned elements retain
their exact flag combination. Flag expressions use comma-separated components
such as `syn,not ack`; operational tables display these with `and`.

## Boundaries

This is an operational view, not a configuration round-trip parser. nftables may
canonicalize masks to prefixes, merge intervals, or eliminate explicit protocol
checks implied by TCP/UDP/ICMP payload fields. The normalizer reports installed
meaning; it cannot recover original spelling or disabled rules absent from the
kernel. Identically typed source/destination columns require the supplied
configuration to label them unambiguously.

Unknown statements and comparisons remain under `unsupported`, with their
original expression and position. Unknown object records and unsupported map
entries are also retained. A display should indicate incomplete interpretation
when this field is present. It must not present a partially understood rule as
fully interpreted. Repeated conflicting matches are not merged into an OR list.

Map catch-all elements carry `default: true` and an empty `key` list: their `*`
selects a whole-key miss rather than a value in one typed column. Their result,
counter and last-used data are preserved. Operational tables display a `default`
row with `*` in each key column.

Supported shapes are tested against real nftables 1.1.7 listings and the
[libnftables JSON documentation](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html).
Optional live tests generate rules through nVyR's formatters and inspect nft JSON
inside disposable network namespaces:

```sh
sudo env PYTHONPATH=src NVYR_NETWORK_TEST=1 python3 -m pytest -q tests/test_nftables_normalizer_live.py
```

## Shared detail formatting

Operational scripts can reuse `nvyr.helpers.output.detailed_output(dataset, headers)`
for headerless `presto` tables, one record at a time. Both the firewall and interface
scripts use this helper.

## Runtime limit and quota API

The `firewall.nvyr.op runtime limit|quota --raw` API returns chain sections with
structured records, exact quota byte counts, keys and expiry. Unsupported
expressions mark a section incomplete; missing referenced objects produce errors
rather than invented zero counters.
