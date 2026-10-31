# Build-time schema composition

The builder expands reusable YAML fragments into the JSON command trees shipped
with nVyR. This guide covers source layout, include edits and schema metadata.
For the feature-development workflow, value callbacks and script lifecycle, see
[Schema and module authoring](extending.md).

## Source files

Building the configuration schema also produces `script-priorities.json` alongside
the generated command trees. It records each script's priority and explicit
declaration paths after include expansion and validation. The operational command
`show system config script-priority` reads this packaged inventory without walking
the configuration tree at runtime. The builder's `--check` includes this artifact.

Edit the top-level YAML files in `schemas/`. These are the source trees for
configuration, operational, control, and pipeline commands. Reusable fragments live
under `schemas/includes/`, grouped by purpose, and end in `.yaml.i`. For example
(this is a selection, not the full file inventory):

```text
schemas/
    configuration.yaml
    operational.yaml
    control.yaml
    pipelines.yaml
    includes/
        interfaces.yaml.i
        firewall.yaml.i
        system.yaml.i
        protocols.yaml.i
        service.yaml.i
        nat.yaml.i
        generic/description.yaml.i
        generic/disable.yaml.i
        interfaces/ethernet.yaml.i
        interfaces/dummy.yaml.i
        interfaces/common.yaml.i
        interfaces/address.yaml.i
        interfaces/address_dhcp.yaml.i
        interfaces/mac.yaml.i
        interfaces/mtu.yaml.i
        protocols/static.yaml.i
        protocols/route.yaml.i
        protocols/route6.yaml.i
        nftables/common.yaml.i
        firewall/description.yaml.i
        firewall/global-options.yaml.i
        firewall/ipv4.yaml.i
        firewall/ipv6.yaml.i
        firewall/filter.yaml.i
        firewall/filter_ipv6.yaml.i
        firewall/raw.yaml.i
        firewall/rule.yaml.i
        firewall/rule_ipv6.yaml.i
        firewall/rule_raw.yaml.i
        nat/rule.yaml.i
        nat/source.yaml.i
        nat/destination.yaml.i
        system/login.yaml.i
        system/host-name.yaml.i
        system/name-server.yaml.i
        service/ssh.yaml.i
```

Add other categories, such as `suggestors/`, as fragments become useful. Each
fragment contributes one named mapping, such as `address: {...}` or `rule: {...}`.
The name is defined by the fragment rather than repeated around every include.
The complete static-route fragments contribute `route` and `route6` respectively;
`protocols/static.yaml.i` includes them without modifications.

`configuration.yaml` contains only root metadata and a list of section includes:

```yaml
kind: node
description: Router configuration
children:

  include_schema:
  - file: interfaces.yaml.i
  - file: vrf.yaml.i
  - file: firewall.yaml.i
  - file: system.yaml.i
  - file: protocols.yaml.i
  - file: policy.yaml.i
  - file: service.yaml.i
  - file: nat.yaml.i
  - file: container.yaml.i
```

Each section file declares its node, description, any section-wide script ownership,
and a list of feature includes. For example, `firewall.yaml.i` composes global
options, groups, zones and the address-family trees. `interfaces.yaml.i` includes
Ethernet, dummy, loopback, virtual Ethernet and bridge definitions.

To add a feature within an existing section, create a complete named `.yaml.i`
file in that section's directory and add its `file` entry to the section's
`children.include_schema` list. To add a new top-level section, create its named
include and add it to `configuration.yaml`. Keep script ownership and priority on
the node that manages the feature. Regenerate and check the runtime JSON afterward.

Label each `children` mapping with its parent node in an inline comment, such as
`children: # route` or `children: # next-hop`. Root schemas use their schema name;
shared child fragments use `interface (shared)` or `rule (shared)`. These comments
are visual navigation aids and do not appear in the generated JSON.

Separate sibling node definitions with one blank line. Keep `include_schema`
entries together without blank lines between files. Also leave one blank line between `children:` and its first explicit
child node; an initial `include_schema` stays directly beneath `children:`.
Keep each node's related properties together.

Prefer explicit definitions when customization would rewrite several descendants
or supply most of a node. Keep include edits for small variations, such as a
description, validator, extra choice, or removal of an inapplicable child. A little
duplication is preferable to a long sequence of edits to another feature's tree.

IPv4, IPv6 and raw firewall rules explicitly define their address/protocol fields
and feature-specific children. NAT likewise defines its translation subtree
directly. These rules compose the family-independent fields from
`nftables/common.yaml.i`, including the complete specialized rule-description leaf.
Raw rules reuse their family rule definitions and add `notrack`. Hook-specific
includes omit outbound-interface matching before routing and inbound-interface
matching on output. Keep those restrictions in the hook-specific composition.

Ethernet and dummy include `interfaces/common.yaml.i` for their shared children.
It composes the address, MAC, and MTU fragments with the generic description and
disable leaves. The generic leaves impose no interface-specific behavior: the
common interface fragment supplies Linux-alias validation, description hints, and
interface-specific help text. MTU retains its direct default of `1500`.

`interfaces/address.yaml.i` defines multi-value static IPv4/IPv6 addresses.
`interfaces/address_dhcp.yaml.i` extends it with the `dhcp` choice and named list
validator. Ethernet replaces its common address child with this DHCP-capable
fragment using a contents-only include in the replacement value; dummy retains
static addresses.
Each interface type keeps its own tag-name validation, discovery prefix, hints,
and script ownership in its own `interfaces/ethernet.yaml.i` or
`interfaces/dummy.yaml.i` file.

The expanded files in `src/nvyr/schemas/` are generated snapshots, kept in the
repository for direct source use and review. Do not edit them directly. The builder
is build-only tooling outside the `nvyr` package. The runtime continues to read
complete JSON files and does not interpret includes.

After includes and modifications are resolved, the builder checks validator
keyword arguments against the registered Python function signatures. Unknown
validators, unsupported or misspelled keywords, and missing required arguments
fail generation before any output is written. Errors identify the source file,
command-tree path, validator and argument. For example, `regex: {pattren: 'x'}`
reports the unsupported `pattren` keyword. Argument values and validator behavior
retain their existing runtime checks.

The standalone builder loads `src/nvyr/helpers/validators.py` from this checkout
for these signature checks. That module uses only the Python standard library,
so building does not require installing nVyR or importing its runtime services.

After resolving includes and modifications, the builder appends `(default: VALUE)`
to each defaulted node's description in `configuration.json`. Source descriptions
remain unchanged. Strings display directly, multiple values use JSON array notation,
and a valueless leaf's implicit default displays as `true`. Other runtime schemas
are not decorated. This describes the schema default even when an operator has
configured a different value; it does not make the default explicit configuration.

## Build and check

From the repository root, with Python 3.11 or later and PyYAML 6.x installed:

```sh
python -m pip install 'PyYAML>=6,<7'

python -m build_tools.schema_builder
python -m build_tools.schema_builder --check
```

The builder regenerates every top-level source `.yaml` into a same-stem `.json`
in `src/nvyr/schemas/`; `--check` fails if any snapshot is missing or differs. After
editing sources or fragments, regenerate before running the CLI or tests. Editable
installation also regenerates the snapshots, but later source edits need an explicit
rebuild. CI checks snapshots before installation can regenerate them.

`python -m build` generates schemas for the source archive and its wheel.
`pip install .` and `pip install -e .` invoke the appropriate setuptools hook.
`scripts/build-deb.sh` generates schemas directly into the Debian staging tree, and
the ISO build calls that script. Wheels and Debian packages contain the standalone
runtime JSON only; the source archive includes the source trees, fragments, and
builder so rebuilding a wheel from that archive also works.

PyYAML is a build/test dependency, not a runtime dependency. Isolated Python
package builds install it through `build-system.requires`; direct Debian builds
need `python3-yaml`. The ISO builder image includes that package. Rebuild an older
builder image after this change. The standalone builder also supports
`--source DIRECTORY` and `--output DIRECTORY`; all includes are rooted in
`DIRECTORY/includes` under the selected source directory. Source and output must
be different directories. All sources resolve successfully before any files are
written. Outputs use deterministic UTF-8 JSON and individual atomic replacements;
unchanged files are left untouched. This is not a transaction across the output
directory, so build consumers must wait for a successful build.

## Negatable values

Add `negatable: true` to a valued leaf or tag to accept `not` before its value:

```yaml
destination-port:
  kind: leaf_node
  multi: true
  negatable: true
  validators:
    port: {allow_range: true}
```

`destination-port not 443` uses the same validator, hints, choices, suggestors,
and multi-value behavior as `destination-port 443`. Completion offers `not`
alongside the usual values, then offers those values again after `not`.
Joined leaves also accept `connection status not confirmed and snat`.

The separate `not` keyword keeps negation discoverable and preserves normal Tab
completion and `?` help. With the conventional `!value` spelling, the punctuation
is attached to the value, so completion must specially handle that prefix. Here,
the parser knows that `not` is a keyword and that the next token is still the
original field's value. For example, `source-address not ` shows the same address
hints and suggestions as `source-address `.

Positive values keep their ordinary configuration shape. Negative values reside
in a `not` dictionary at the field's parent, for example
`{"destination-port": ["80"], "not": {"destination-port": ["443", "8443"]}}`.
The engine derives the negative branches from this metadata; do not add a second
YAML definition. Defaults are not duplicated into negative values. Configuration
scripts must explicitly implement the meaning of exclusions for their fields.

Deleting one negative value preserves the other values of either polarity.
Deleting the whole field removes both polarities. Command export and configuration
diffs use the public `field not value` syntax. A literal value named `not`
must be quoted. The bare keyword is reserved before a negatable value.

## Joined leaf values

Use `joinable: true` on a valued leaf to accept `and` between components of
one comma-separated value. This works with scalar and multi leaves:

```yaml
connection-status:
  kind: leaf_node
  multi: true
  joinable: true
```

For example, `connection status confirmed and snat and dnat` stores the single
value `confirmed,snat,dnat`. Repeating `connection-status` starts a separate
multi-leaf entry. The existing validator checks the assembled value; the engine
does not assign boolean meaning to the components.

After a value, completion offers `and` and the available anchored siblings.
After `and`, it offers the leaf's choices, hints and suggestions again, omitting
already-selected components. A trailing `and` is incomplete and cannot be
submitted. Ordinary leaves do not acquire this syntax. `and` is reserved as the
continuation keyword immediately after a joined value.

The `and` keyword preserves completion for every component of a combination.
A conventional comma-separated token such as `confirmed,snat,dnat` requires
completion to split the token and identify which component is being entered.
With `connection status confirmed and `, Tab and `?` immediately offer the
remaining status choices with their descriptions. Users can discover and complete
each value instead of memorizing names and typing a comma-separated string.

Command output renders these values with `and`, including commands for removing
multi-leaf entries. JSON configuration and configuration-script input retain
comma-separated strings. Valueless leaves, tag nodes, grouping nodes and opaque
operational `rest` arguments cannot declare `joinable`.

For expressions that negate individual components, use
`joinable: {negatable: true}` instead. For example, `tcp-flags syn and not ack`
stores `syn,not ack`. Completion offers `not` before each component, then the
normal choices after it. Already selected flags are omitted in either polarity.
A trailing `not` is incomplete. This is distinct from `negatable: true`, which
negates the entire leaf value and stores it in the parent's `not` dictionary.
The field's validator remains responsible for interpreting the joined expression.

## Registered objects and references

Declare a provider with `dependency` and a consumer with `depends`, using the
same type name:

```yaml
dummy:
  kind: tag_node
  dependency: interface

inbound-interface:
  kind: leaf_node
  multi: true
  depends: interface
```

The tag instance name or leaf value is the registered identity. Multi leaves
register each value independently. Both properties accept a nonempty type name
without whitespace on valued tags or leaves; invalid declarations fail the build.
Declarations are not inherited by children. Includes preserve them as ordinary
node metadata in generated JSON.

Nested providers can declare `dependency-format: '{parent}.{value}'` to compose
their identity from the nearest ancestor tag and their own tag value. For example,
`interfaces ethernet eth1 vif 10` registers `eth1.10`, not `10`. This requires a
dependency tag beneath another tag. Both full-tree and candidate-journal checks
use the composed identity, including removal of the containing parent.

Configd rejects candidate changes that remove a registered identity while a
reference remains, listing the consumer paths. References may point to missing
objects; any prerequisite existence checks belong in the consuming script's
`verify()`. Remove references before deleting or renaming a provider. Renames do
not rewrite reference values. Deleting a parent containing both objects and their
references is allowed. JSON merge/replacement loads and replacement `load set`
are checked as complete resulting trees before changing the session candidate.
Ordinary pastes and nonreplacement `load set` retain per-line validation.

Ethernet and dummy tags provide `interface`. The shared inbound/outbound-interface
leaves consume it in firewall and NAT rules, including named chains and raw rules.
Named firewall chains provide `firewall-chain-ipv4` or `firewall-chain-ipv6`;
their family's `jump-target` leaves consume that type. Identical chain names in
different address families are independent identities.
Only explicitly configured values participate, independently of runtime existence.

### Reapplying consumers when provider fields change

An owned reference can opt into watching fields relative to its provider:

```yaml
inbound-interface:
  kind: leaf_node
  multi: true
  depends: interface
  reapply-on-change:
    - vrf
```

The build checks that each path exists on at least one provider of that dependency
type. Providers without that field, such as loopback without `vrf`, are valid; an
absent field cannot trigger a change.
Paths use space-separated schema names relative to the provider instance; they
do not contain particular tag values. Configd compares the previous and proposed
effective values and looks up consumers by dependency type and identity. Changes
to other fields, or to unreferenced providers, do not select extra scripts.

Selected consumers run once after the changed provider owners, alongside normal
changed owners. `commit check` also verifies them. `context.reapply_paths` contains
the absolute reference paths responsible for the extra run; it does not invent
changes in `context.get_changed()`. The firewall uses these paths to replace entire
affected chains and their dependent callers, retaining unrelated native objects.

The affected provider/consumer owners form a consistent commit unit: if one fails,
their changes remain pending and already-applied members are restored. Independent
owners can still succeed. Recovery failure retains the transaction journal for
restart recovery. Commit-confirm restoration and ordinary recovery also expand
watched references. Cyclic reapply ordering is rejected before applying changes.

This is opt-in metadata, separate from the deletion guard provided by `depends`.
It does not require every referenced object to exist or infer dependencies from
Python script names.

### Reference inspection and saved metadata

In configuration mode, `show references <tag-instance path>` lists the full paths
and values that reference a configured provider. It inspects running configuration
with this session's pending changes applied: staged additions appear and staged
deletions disappear. Paths are relative to the current `edit` context; reported
references always use full paths so consumers outside that context remain clear.

For example, use `show references interfaces dummy dum0` or
`show references firewall ipv4 name CUSTOM`. Under `edit interfaces`, use
`show references dummy dum0`. Only tag instances with a `dependency` declaration
can be inspected; normal nodes, leaves, incomplete tags, unregistered tags and
missing instances receive descriptive errors. Unused providers show
`No references found.` The command does not modify configuration or rewrite references.

On `save`, configd writes a derived registrar to `_nvyr.dependencies` in the saved
configuration document. Each type/value entry lists `providers` and `references`
as arrays of path tokens. This is configd-owned metadata, excluded from CLI
configuration output, mutations, and configuration-script inputs. Loading never
trusts the stored registrar: checks derive it from the actual configuration and
current schema. Per-session reference caches are invalidated when references or
running configuration change and released when the session closes or expires.

The dependency deletion guard itself does not order scripts, require referenced
objects to exist, or propagate apply failures. Those behaviors require explicit
watch metadata or feature verification as described above.

### Script-level watches

Configuration scripts can declare absolute configuration paths to watch:

```yaml
script:
  name: dhcp-server
  priority: 55
  register:
    vrf: default
  watch:
    - interfaces
```

When a watched subtree changes, a configured consumer runs after its changed
provider owners even if the consumer's own configuration did not change. Use `*`
to cross a tag instance: `vrf name * table` watches each VRF table assignment
without watching its nested routing protocols. The engine
exposes the trigger paths in `context.reapply_paths` and retains the affected
provider/consumer component if application fails. Reference-level
`reapply-on-change` remains available for narrower named-object watches.

Use `watch-before` instead of `watch` when the script prepares runtime state that
must exist before the changed providers apply. It accepts the same paths and
participates in the same failure/rollback component. For example, automatic VRF
conntrack maps must be installed before interfaces acquire addresses:

```yaml
script:
  name: vrf_conntrack
  priority: 4
  watch-before:
    - vrf name * table
    - interfaces
    - container network
```

Both forms use the proposed configuration. Contradictory ordering dependencies
are rejected before application, including a script watching the same provider
with both forms.

## Command access

Use `access: net-admin`, `access: sys-admin` or `access: dev-admin` on restricted command
nodes. Omitted access inherits from the parent, with `read-only` as the root
default. A child may explicitly override the inherited policy. The builder
validates role names and preserves declarations in JSON; schema loading resolves
inheritance for dispatch and completion. See [operational permissions](opmode.md#command-access).

## Privacy metadata

Use `strip_kind` on a valued leaf or tag node to mask it in configuration displays
requested with `| strip-private`:

```yaml
encrypted-password:
  kind: leaf_node
  strip_kind: password
```

Supported kinds are `ipv4`, `ipv6`, `ip` (either family), `mac`, `password`, and
`private` (other sensitive text). On tag nodes this masks instance names, while
children retain their own metadata. Multi-value leaves mask each value. Unknown
kinds and annotations on structural nodes or valueless leaves fail schema loading.
Includes and add/replace/remove operations preserve this metadata in runtime JSON.

Masking copies structured configuration before rendering. Per-display aliases
such as `<ipv4-1>` keep distinct tag keys and changed values distinct, including
password changes, without exposing source data or hashes. Aliases are shared
between the sides of one comparison and are not persistent identifiers.

The modifier supports `show`, running/candidate views, saved/history comparisons,
edit scopes, and `| commands`. It runs before formatting and other text modifiers,
so both `| strip-private | commands` and `| commands | strip-private` work.
Running, candidate, saved configuration and history remain unchanged. Masked
command output is for sharing and inspection, not configuration restoration.

## Including named nodes

Any source mapping can contain an `include_schema` list. Each entry has a `file`
and optional per-file edits. For example, `generic/disable.yaml.i` defines:

```yaml
disable:
  kind: leaf_node
  description: Disable this configuration object
  valueless: true
```

It can be combined with other fragments directly under `children`:

```yaml
children:

  include_schema:
    - file: interfaces/address.yaml.i
    - file: generic/disable.yaml.i
      replace:
        /description: Administratively disable this interface
    - file: interfaces/mac.yaml.i
    - file: interfaces/mtu.yaml.i
    - file: generic/description.yaml.i
      replace:
        /description: Linux interface alias
      add:
        /validators:
          interface-description: {}
        /hints:
          text: Interface description; quote spaces
```

File names always resolve from the include root, including references inside
other fragments. Use `/` as the separator. Absolute paths, `..`, paths escaping
through symlinks, and extensions other than `.yaml.i` are rejected. Files must
contain one YAML mapping with string keys. Comments are supported;
duplicate keys, non-string keys, unsafe tags and values that cannot be represented
in JSON are errors.
Include cycles and missing files fail with the source/include chain in the error.

Each included file is recursively expanded first and must resolve to exactly one
nonempty node name with mapping contents. The builder applies that entry's edits
to those contents, then inserts the named result at the `include_schema` location.
For example, `/description` edits the description inside `disable`, not a sibling
or a field of the combined parent. Do not prefix it with `/disable`.

Entries expand in list order. Local fields retain their written order around the
include declaration. Duplicate names between entries, or between an include and
a local field, fail regardless of ordering; there is no silent overwrite or deep
merge. Customize the relevant include entry instead. An empty list is a no-op.
The old single-object `include_schema: {file: ...}` form is rejected.

Names can also identify structural mappings: the common interface and nftables
fragments contribute `children`. Their edits are relative to those mappings:
`/address/description` for the interface fragment or `/disable/description` for
the nftables fragment. Include them at the node-definition level to contribute
`children`, or use `as: null` inside an existing `children` mapping to insert
their contents alongside explicit children.

For reuse under a different keyword, set `as: custom-name` on the entry. Edits still
target the original node's contents; renaming does not change their scope.

For an add/replace value that needs a node definition rather than a named child
mapping, `as: null` imports just the contents. For example, the Ethernet consumer
customizes the shared `children` mapping without introducing a second `address`
wrapper:

```yaml
include_schema:
  - file: interfaces/common.yaml.i
    replace:
      /address:
        include_schema:
          - file: interfaces/address_dhcp.yaml.i
            as: null
```

This explicit contents-only form also permits composing fields of a node. It has
the same edit scoping and collision checks as named imports. Normal child lists
should omit `as` and use the names supplied by their files.

A derived fragment may itself contain only an include list. For example,
`interfaces/address_dhcp.yaml.i` includes `interfaces/address.yaml.i`, customizes
its contents, and still contributes the single name `address`.

## Modifications

`include_schema` supports `remove`, `replace`, and `add`. Paths are non-root JSON
Pointers, relative to the included node's contents. For example:

```yaml
include_schema:
  - file: firewall/action.yaml.i
    remove:
      - /choices/reject
      - /choices/jump
      - /choices/continue
      - /choices/return
    replace:
      /validators/list/values: accept drop
```

This illustrates narrowing an included action definition. Its choices and
validator values both describe the same two-action vocabulary. The DHCP address
include demonstrates `add`: it adds the `dhcp` list validator and choice to the
static-address leaf, with explicit OR composition.

### Validator and suggestor edits

Validator keys name the registered Python validators directly, not aliases or list
positions. Adding or reordering a validator cannot redirect an edit such as
`/validators/network/version`. Removing or renaming a targeted validator causes a
build error instead of silently editing a different check.

```yaml
validators:
  mode: AND
  integer-range: {minimum: 1, maximum: 999999}
  length: {maximum: 6}
```

Omit `mode` for a single validator: AND is implicit. For multiple validators,
explicitly specify `mode: AND` or `mode: OR`. When an include adds a second validator,
add the mode in that include's edits (for example, `/validators/mode: OR` in the
DHCP address include). Each remaining entry is a validator name mapped
to its keyword arguments; `{}` means no arguments. Short argument mappings can be
inline, while longer ones can use normal YAML block formatting. Aliases, lists of
calls and the old `checks`/`name`/`args` wrappers are not source syntax. Duplicate
keys are rejected by the YAML loader. An empty validator mapping adds no restriction.

Normalization happens **after** all recursive includes and modifications, and only
on schema nodes. The generated JSON still uses `mode` and `checks`, with each check
containing `name` and optional `args`. Suggestors also use registered names as keys:

```yaml
suggestors:
  interfaces: {prefix: eth}
```

Use `interfaces: {}` or `commit-history: {}` when no arguments are needed. Multiple
suggestors can be listed as separate keys in the same mapping; they have no mode.
The builder preserves their order and emits the existing runtime list of `name`
and optional `args` references. Include edits use paths such as
`/suggestors/interfaces/prefix`, before normalization. Runtime callback
lookup, argument binding, prepared validators and configuration validation remain
in the existing runtime schema loader.

### Edit ordering and pointer rules

- `remove` is a list of existing paths to delete.
- `replace` maps existing paths to new values. The entire selected value is replaced,
  including an entire object or list when targeted.
- `add` maps absent object keys to values. Parents must already exist. For lists,
  use the final path component `-` to append; insertion at a numeric index is not
  supported. Existing list elements can be replaced or removed by zero-based index.

Operations always run in the order **remove, replace, add**, regardless of YAML
field order, independently for each file entry. Within each operation, edits run
in their written order. Removing
list elements shifts subsequent indexes. Paths can reach values supplied by any
level of nested include, including named validator checks.

In JSON Pointer components, encode literal `/` as `~1` and literal `~` as `~0`.
For example, `/hints/x.x.x.x~1x` selects the hint key `x.x.x.x/x`. Ordinary strings
inside replacement values need no such escaping. The empty root pointer is not
supported; `/` targets an actual empty object key.

Objects used as add/replace values can themselves contain `include_schema`, and
those are expanded before insertion. Do not add a bare `include_schema` key by
path; compose an object containing it instead. Each consumer gets an independent
expansion, so changing the IPv6 instance cannot change the IPv4 instance.

Unknown operations, incorrect operation types, missing targets, and collisions
fail the build instead of silently changing behavior. The builder validates
composition, YAML syntax and JSON-compatible value types; the existing runtime
schema checks and tests continue to validate node kinds, callbacks, defaults,
and other nVyR semantics.

## Operational mapping checks

Operational commands use `command: ['executable', 'argument', '@3']` with every
argument explicitly quoted. The builder rejects unquoted strings and non-string
arguments. Put `timeout` and `stream` beside `command`, not inside it. The builder
lowers command lists to the existing runtime JSON; see [operational scripts](opmode.md)
for placeholders, optional values, internal commands and executable installation.

Mappings to bundled `.nvyr.op` scripts are checked against their Python source
signatures at build time: missing scripts, unexposed/misspelled function names,
unknown flags, missing arguments and invalid literal argument types fail with
the affected command-tree path. The checker does not import or execute scripts.
It shares runtime argument registration, including repeated list arguments.
Placeholder contents remain runtime values. Arbitrary external programs are not
introspected; their options remain the responsibility of the command author.

## Scalar types and quoting

The safe YAML loader uses JSON-style implicit scalar resolution rather than
PyYAML's YAML 1.1 defaults. Lowercase `true` and `false` are booleans, `null` is
null, and decimal numbers in JSON notation are numbers, including exponents.
Other plain scalars remain strings: `on`, `off`, `yes`, dates, `0123`, `0x10`,
`12:34:56`, `~`, and an empty value do not silently become booleans, timestamps,
octal numbers or null. Write `null` explicitly when that is intended.

Quote numeric or boolean-looking values when they must remain strings. Mapping
keys must also remain strings, so quote numeric choice keys. For example:

```yaml
anchor: true

script:
  name: ethernet
  priority: 10

default:
  mode: direct
  value: '1500'

validators:
  regex: {pattern: '^eth\d+$'}
```

Single quotes are convenient for regular expressions because backslashes remain
literal. YAML double-quoted strings interpret escape sequences; escape backslashes
there as needed. Block scalars may be used for longer descriptions, with `|-`
when a trailing newline is not wanted. Lists and nested mappings retain their
order. Nonrecursive YAML aliases are accepted and expanded independently, but
recursive aliases are rejected. Use `include_schema` for composition and edits;
YAML merge-key semantics are not enabled. Explicit non-JSON types (timestamps,
binary data, sets) and non-finite numbers are rejected.

## Nested anchors

In configuration commands, an anchored `node` or `tag_node` inside an anchored object
creates a local option group. Its children take precedence over identically named
outer options. Keywords available only on the outer anchor return to that level.
For example, `fib lookup source-address inbound-interface log` selects two FIB
lookup flags, then returns to the rule's `log` option. An anchored VIF keeps its
address, description and other options scoped to that VIF. Unanchored nested tags
return to the enclosing anchor after a completed leaf. An `edit` context prevents
returning above the selected edit path.
