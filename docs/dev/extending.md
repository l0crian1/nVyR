# Schema and module authoring

Use this guide when adding commands or connecting a configuration feature to its
implementation. The schema defines syntax, completion and value validation;
configuration scripts verify relationships and apply the resulting state.

## Development workflow

1. Define commands in the YAML sources and reuse existing fragments where useful.
2. Add value validators, choices, hints and suggestions as appropriate.
3. Register the configuration owner or operational handler in trusted code.
4. Implement verification, generation, application and recovery for the feature.
5. Add focused tests, live smoketests and user documentation. Regenerate both the
   runtime schemas and [command tree](../users/command-tree.md).

See [schema composition](schema-builder.md) for includes and overrides,
[operational scripts](opmode.md) for command dispatch, and the
[script guide](scripts.md) for where implementations belong.

## Python conventions

Python code uses absolute `nvyr` package imports throughout the project, including
CLI, daemons, helpers, configuration/operational scripts and tests. Use
`from nvyr.helpers import interfaces` or `from nvyr.tree import lookup` rather
than relative imports. This also applies to new modules and documentation examples.
Keep intentional function-local imports in place; use the installed package in
existing execution contexts rather than adding `sys.path` workarounds.

## Schema sources and node kinds

Edit YAML schema sources in `schemas/`; `src/nvyr/schemas/` contains generated runtime
snapshots. See [the schema builder](schema-builder.md) for named reusable fragments,
multi-file include lists, per-file modifications, and build commands. `configuration.yaml`
contains root metadata and top-level section includes. Each section lists feature includes
under its own `children`; edit those files to add or extend configuration features.
`operational.yaml` defines executable operational paths; `control.yaml` defines
configuration mode commands and routes configuration paths into the shared tree.
`pipelines.yaml` describes modifier arguments and sink status.

```yaml
kind: tag_node
description: Interface name

script:
  name: ethernet
  priority: 10

validators:
  regex: {pattern: 'eth[0-9]+'}

suggestors:
  interfaces: {}

children:

  description:
    kind: leaf_node
    description: User description

  address:
    kind: leaf_node
    multi: true
    validators:
      address: {}

  disable:
    kind: leaf_node
    valueless: true
```

This is a *named* tag node: if its key is `ethernet`, the tokens are `ethernet eth0`.
After the tag value, its children are available. Setting a tag instance itself is valid;
setting a plain node or tag collection also preserves that empty container. A valued leaf needs exactly one token, and a flag
needs none. Lists are reserved for `multi`; flags must be boolean true. Children of leaves
and multi+valueless combinations are rejected.

### Renaming tag instances

Tag nodes allow renaming by default. Set `rename: false` on a tag node to reject
renaming its instances in configd, including commands relative to an `edit` context.
The property must be a boolean and is only valid on `tag_node`. It does not restrict
copying, deletion, or renaming child tag instances; their existing checks still apply.

## Anchored set commands

Add `anchor: true` to a `node` or `tag_node` to allow several descendant settings in one
`set` command. The flag is optional (off by default), must be a boolean, and is
rejected on leaf nodes. The bundled firewall `rule` and interface `dummy`
nodes enable it. For example:

```text
set firewall ipv4 forward filter rule 10 action accept protocol tcp destination-port 22 log
set interfaces dummy dum0 address 192.0.2.1/24 description "WAN Interface" disable
```

### Traversal and nested anchors

The rules are deliberately deterministic:

- The first anchored node or tag **instance** reached in the command becomes the
  return point. A tag requires its instance name before anchoring starts.
- An explicitly anchored **node or tag instance** inside that object creates a local option group,
  retaining the outer return point. Local children and their prefixes take precedence;
  an outer-only keyword returns to the outer anchor. For example,
  `fib lookup source-address inbound-interface log` sets two lookup flags, then the
  rule's logging flag. Repeat `fib lookup` to enter that local group again.
- Each valued leaf consumes exactly one token; quoted strings are one token even
  when they contain spaces, keywords or pipes. A value is never reinterpreted as a
  keyword to rescue an incomplete or invalid command.
- A valueless leaf completes as soon as its keyword is consumed. Multi-value leaves
  add one value per occurrence: `address 192.0.2.1/24 address 192.0.2.2/24`.
- After a leaf completes, the next token starts another path relative to the anchor.
  Normal intermediate nodes must be repeated: `settings mtu 1500 settings speed 1000`.
  Plain nodes and tag collections can end a command to ensure their presence; they
  do not create an anchor-return boundary in the middle of a command.
- An anchored nested tag keeps subsequent options local. For example,
  `interfaces ethernet eth1 vif 10 address 10.0.10.1/24 description Users` sets both
  properties on `eth1.10`. Unanchored nested tags return to the outer anchor after
  a completed leaf. Use a separate command for a shadowed parent option.
- A childless nested tag completes immediately. After a nested tag with children,
  the next keyword may select a child or start another operation at the anchor.
  Nested child names and their prefixes take precedence, preserving existing
  shorthand. Ambiguous prefixes within the selected section fail. Returning to the anchor preserves the nested instance even when it is empty.
  For example, `source-address 192.0.2.1 mask 255.255.255.0` enters the child,
  while `source-address 192.0.2.1 destination-address 198.51.100.1` returns to the rule.
- Exact keywords and unique keyword prefixes follow the existing resolver rules at
  every segment. Values use their configured validators; ambiguous keyword
  prefixes fail. Repeated scalar writes retain the last value, exactly as separate sets.

### Edit contexts

Inside `edit firewall ipv4 forward filter`, use `set rule 10 action accept protocol tcp`.
Inside `edit ... rule 10`, use `set action accept protocol tcp`. If the edit root is an
anchor instance, it is the return point. Otherwise anchors are discovered only below
the edit root; completion and execution never escape to an anchor above it. Editing
directly into a nested anchor selects that instance as the return point.

### Completion and consumed options

Space expansion, inline suggestions, Tab, and `?` consume the same `SetCursor` grammar
as execution. After a complete value followed by a space they offer anchor-relative
children and, for explicit help, `<Enter>`. During a value they still offer values.
Unclosed quotes or escapes do not offer `<Enter>`. External discovery participates in
all completion modes. Pending text is not staged by asking for completion.

Within an anchored line, completed single-value leaves and valueless flags stop
appearing in help, Tab completion and inline suggestions. Multi-value leaves and
tag nodes remain available; normal grouping nodes remain while they have unused
descendants. Consumption follows the full path, including tag values, so a `mask`
used for one address remains available for another. This applies to configuration
and operational anchors, resets on each new line, and follows edits to the current
line. Explicitly typed repeats still use the existing parsing and execution rules.

### Staging and serialization

`Schema.set_paths()` expands the command into ordinary absolute path cursors. The
engine validates the whole line before appending ordinary `set`, `add`, or `ensure`
intents: an invalid suffix leaves the entire candidate journal untouched. This is
line-level staging atomicity, not a change to independent-owner commit semantics.
There are no anchor fields in candidate trees, scripts, history, saved JSON or RPC
mutations. `| commands` continues to emit one conventional `set` per setting, so
exports use the ordinary single-path syntax. Pasted and loaded set commands
use the same expansion; loaded paths remain absolute and errors remain per-line.

Anchoring currently applies only to `set`. `delete` retains its optional-value and
subtree deletion grammar; `edit`, `show`, and `rename` retain single-path behavior.

## Values and callbacks

Choices and suggestions help users enter values. Hints describe their shape.
Validators decide which values are accepted; none of the other three replaces
validation.

### Choices

`choices` supplies literal completion candidates and per-value help; it never validates:

```yaml
choices:
  accept: Accept matching traffic
  drop: Silently drop matching traffic
```

Object keys are suggested values; other values may be accepted by validators. Existing
string-list definitions remain supported, with generic help. Descriptions in choice
objects take precedence over configured-value or suggestor labels for the same value.
Common completion sorting orders unsigned decimal values numerically before other
tokens, which remain alphabetically sorted; this covers tags, choices and suggestors.
Leading-zero spellings remain distinct, with shorter equal-value spellings first.

### Hints

Hints describe a value format without inserting a literal completion:

```yaml
hints:
  x.x.x.x/x: IPv4 address with mask
```

The CLI displays `<x.x.x.x/x>`. Keep the label unwrapped in YAML. Hints appear
before choices and suggestions in their completion context, but do not affect
Tab replacement, common-prefix calculation, inline prediction or validation.
Only valued leaves and tags accept hints.

### Validators

The YAML `validators` mapping uses registered validator names as keys and argument
mappings as values. Omit `mode` for one validator (implicit AND); explicitly specify
`mode: AND` or `mode: OR` when combining multiple validators. No validators means no
additional predicate restriction. Add reusable predicates to `validators.py`
with `@register(name, operator_label)`: examples cover interface names, IPv4 addresses,
IPv4/IPv6 prefixes, positive/nonnegative integers, ports and text. The registries
load once, not per keypress; schemas bind callbacks without parser/CLI changes.
Tests can supply overrides through `Schema(..., validators={...}, suggestors={...})`.

#### Suggestions after validation fails

Validators return `True` for accepted values and `False` or a false-valued
`ValidationFailure` for rejected values. A validator can attach suggestions to
that failure itself; there is no separate suggestion callback. The shared
`suggest_values()` helper uses `difflib.get_close_matches`, with a default limit
of one and cutoff of `0.8`:

```python
@register('time-zone', 'an installed IANA time zone')
def time_zone(value):
    from nvyr.helpers import timezones

    if timezones.valid_name(value):
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, timezones.available(), mangles=[['-', '_']], ignore_case=True,
    ))
```

The handler combines results using the existing `AND`/`OR` rules and includes
suggestions only if validation fails. Secret values retain the generic credential
error without the entered value or suggestions. Validators without suggestions
can continue returning plain Booleans. The prepared `list` validator uses its
existing permitted values and corrects components separately when a separator is
configured. Valid inputs skip suggestion matching.

Named protocols, ICMP types, container capabilities, BGP communities and remote-AS
keywords also suggest corrections. BGP community candidates respect the `large`
and `modifiers` arguments; CPU policy candidates come from the current hardware's
supported settings. Joined TCP and log flags suggest a complete valid expression,
preserving negation and rejecting corrections that introduce duplicates or
contradictions. Country codes suggest only case corrections, avoiding guesses
that could select another country.

`mangles` is an ordered list of replacement pairs applied **only to the input**;
for example, `[['-', '_'], ['.', ',']]`. Candidates are not mangled.
`ignore_case` independently enables case-insensitive comparison, while returned
choices keep their original spelling. Both options are off by default. A failed
time-zone value such as `america/new-york` suggests `America/New_York`; it remains
invalid until the user corrects it. No sufficiently close match means no added
suggestion. This does not change autocomplete or schema syntax.

#### Validator arguments

Validator arguments sit directly beneath the validator name. Use `{}` when no
arguments are needed. Prefer inline mappings for short argument sets and block
mappings for longer ones. No aliases, `checks`, `name` or `args` wrapper is needed
in validator sources. Suggestors use the same name-to-arguments mapping, without a mode:

```yaml
validators:
  mode: AND
  text: {}
  regex: {pattern: 'dum[0-9]+'}

suggestors:
  interfaces: {prefix: dum}
```

For discontiguous inclusive integer bounds, use the generic `integer-ranges`
validator, for example `integer-ranges: {ranges: [[100, 251], [256, 4294967295]]}`.
It accepts a single integer in either interval and checks bounds without expanding
them into individual values. Each interval must be an integer minimum/maximum pair.

Include edits target stable function names, for example `/validators/regex/pattern`
or `/suggestors/interfaces/prefix`.
After expanding includes and applying edits, the builder converts validators to the
existing runtime `checks` representation and suggestors to a list of `name` and
optional `args` references. Programmatic runtime schemas use these same objects;
YAML sources use the compact format exclusively. Do not repeat keys or add aliases to invoke a validator twice.
Use the appropriate reusable validator instead.

Use `ipv4-address: {}` for a plain IPv4 address, `ipv6-address: {}` for a plain IPv6
address, or `inet-address: {}` when either family is accepted. These reject prefixes,
zone identifiers and hostnames; use `address` for interface addresses/prefixes or
`network` for strict network prefixes. The former `ip-address` callback is removed.
`length` defaults to counting characters; `byte-length` measures UTF-8 bytes, allowing
both limits to be expressed together without aliases.

Validators receive `function(value, **args)`; suggestors receive
`function(context, **args)`. The context is supplied by the registry, not the schema.
Unknown names, missing/unsupported arguments and malformed reference objects fail at
schema load. `regex` uses full-string matching and compiles its pattern once at load;
invalid patterns also fail at load. Custom validators may register a `prepare`
function to bind expensive static arguments once and return a value predicate.
AND/OR combinations, defaults and native imports use the same validation path.

For an allowed-value list, use the source YAML form:

```yaml
validators:
  list: {values: 'accept drop return continue'}
```

Whitespace separates exact, case-sensitive values. With `separator: ','`, each
comma-separated member must be allowed; empty and unknown members are rejected.
For example, `list: {values: 'snat dnat confirmed', separator: ','}` accepts
`snat,dnat,confirmed` as one value. A DHCP-capable address leaf can instead combine
literal and address validation:

```yaml
validators:
  mode: OR
  list: {values: 'dhcp'}
  address: {}
```

Tag validation applies to execution and imports, but does not prevent completion
from exploring descendants of a typed tag. Invalid tags do not offer `<Enter>`.

### Suggestions

Add discovery functions to `suggestors.py` with `@register(name)`. They receive
a bound `Context` and return strings or `Suggestion(value, description)` objects.
Handle discovery failures in the suggestor; a missing suggestion does not make a
value invalid. Use validators or script verification for acceptance checks.

The bundled dummy-interface suggestor requests names starting with `dum`.
Calling `interfaces` without arguments still discovers all interfaces. This discovery
filter does not constrain accepted configuration values or hide configured tag names.
Live interfaces show their kernel interface alias as the suggestion description;
interfaces without an alias, including names not yet created, keep a blank description.

#### Configured objects

Use `config-path` to suggest configured tag instances from another absolute
configuration path:

```yaml
suggestors:
  config-path: {path: 'firewall flowtable'}
```

In configuration mode, the lookup includes the current session's pending additions
and deletions; operational mode uses the running configuration. Paths are rooted
at the configuration root, even under `edit`. Missing paths return no suggestions.
The lookup projects only the requested branch, without materializing the full
candidate. These are completion suggestions, not a requirement that a value exist;
validators, dependencies and script verification remain responsible for that.

Registered suggestors run for inline prediction, Tab, Space expansion and explicit help.
They should be fast and bounded; expensive discovery should cache results within the suggestor. `list_on_empty_tab` requests a list
instead of inserting a static hint when an argument is empty. Compare and rollback
both use `commit-history`, which reads actual retained snapshot timestamps from Store;
only compare adds the nonbinding `saved` hint. Numeric values remain commit-ID offsets.

### Defaults

Leaf defaults use `{"mode":"direct", "value":"accept"}` or
`{"mode":"always", "value":"accept"}`. A valueless default omits `value`; a multi
default supplies a list. See [defaults](architecture.md#defaults) for exact
activation semantics.

In YAML, a multi-value leaf uses a nonempty list of distinct strings under
`default.value`. Each entry passes the leaf's validators, and list order is
preserved:

```yaml
values:
  kind: leaf_node
  description: Example values
  multi: true
  validators:
    list: {values: 'one two three'}

  default:
    mode: direct
    value:
      - 'two'
      - 'one'
```

With only the parent configured, scripts receive both defaults in their effective
configuration. An explicitly configured list replaces the entire default list;
deleting its last explicit value restores the defaults while the parent remains.
Use `mode: always` for the existing broader branch activation behavior. Neither
mode writes defaults into candidates, running configuration, history, or saved
configuration. Script read-only views expose multi-value lists as tuples, just as
they do for explicit multi-values. Scalar and valueless defaults are unchanged.

### Negation and joined values

Use `negatable: true` to offer `not` before a value. Use `joinable: true` to
offer `and` between components while preserving completion for each component.
These are parser features; the consuming script defines their match semantics.
See [negatable values](schema-builder.md#negatable-values) and
[joined values](schema-builder.md#joined-leaf-values) for storage and validation.

## Operational command mappings

`command` identifies a trusted handler; it is not a shell string. Operational Enter is
valid only on a resolved node with a command and satisfied arguments. A leaf/tag's
`optional_value` makes a command valid without a value; `choices_hint` supplies nonbinding
argument hints. Control `path` routes into another schema or a structured command form.
`Controller.register_operation(name, handler)` registers an output handler receiving the
resolved cursor (including its path and argument value); it is shared by operational
execution and `run`, without changing the parser.

For an external command, source YAML uses an explicitly quoted argv list:

```yaml
command: ['vtysh', '-c', 'show ip route']
timeout: 15
```

The builder converts this to the runtime command object. Put `timeout` and
`stream` beside `command`, not inside an argv entry. Trusted argv definitions
never use `shell=True`; the installed schema selects the executable. Interactive
host shell access is a separate client event using the user's terminal.

For separate operational scripts, use `nvyr.opmode` and `src/nvyr/op_scripts`.
Public `@opmode.command` functions get signature-derived parsers through `run()`.
Use `command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3']`; all arguments
must be explicitly quoted strings. `@1`, `@2`, etc. and `@line` bind original
input to whole argv entries. An absent optional value omits the placeholder for
its position and its adjacent option. Positional numbering excludes the `run`
wrapper; `@line` retains command text before the first unquoted pipe. Packaging installs `.nvyr.op` symlinks for standard PATH lookup. Put
`timeout` and `stream` beside `command`. See [operational scripts](opmode.md)
for signatures, quoting, exposure rules and complete mapping examples.

## Configuration module contract

Register a module object by script name in the dictionary passed to `Engine`. Keep this
registry in trusted application code. The `nvyr.modules.registry()` factory explicitly
binds schema owners to their configuration scripts and rejects unregistered owners.
`protocols_static.py` uses the shared FRR reload manager; see [FRR integration](frr.md)
before adding another FRR-backed owner. The context's `state_directory` provides its
private recovery metadata location, separate from the explicit configuration tree.
Add each implementation there before referencing its owner in the schema.

Feature scripts live together under `src/nvyr/config_scripts/`; future interface,
WireGuard or routing-protocol scripts belong in that package. Shared helpers live in
`src/nvyr/helpers/`: `interfaces.py` groups interface discovery and the Netlink daemon client;
`netlink.py` registers extensible interface drivers, `link_manager.py` reconciles their
desired state, and `dhcp.py` handles DHCP client/lease integration;
`process.py`, `template.py`, `validators.py`, and `suggestors.py` retain their logical
groupings in that package. Import them through `nvyr.helpers.<module>`. Configuration tree, storage, parser, RPC and
CLI history modules remain with the primary framework because they implement its core
state model and behavior. The trusted registry explicitly connects
schema owner names to implementations; configuration values never select imports.

Name configuration scripts for the area they manage, without a redundant `config_`
prefix: `firewall.py`, `interface_dummy.py`, `interface_ethernet.py`,
`protocols_static.py`, and `service_ssh.py`. Owner identifiers in the schema are stable
registry keys; renaming a Python file does not change the stored configuration.

The bundled registry connects the firewall owner to `config_scripts/firewall.py` directly.
The configuration script
returns `context.effective` itself, passes the full shared read-only view through
verify/generate, renders `firewall/filter.nft.j2` with the shared Jinja2 pipeline in
generate, and loads it through `helpers/nftables.py` in apply. Verification checks
rule actions, protocol-specific fields, group references and hook restrictions
where the configuration uses those features. Errors identify the full rule path
and stop that owner's lifecycle before generation. Scripts may inspect configuration owned
by other subsystems, such as interfaces, via normal `lookup` helpers. `context.root`
identifies the first declared schema location (tag slots are `None`); it is not a
read boundary or an inventory of dynamic instances. Use registrations for multi-location owners. `context.report`
routes text back to the committing CLI; recovery routes it to daemon logging. It does
not reconnect to configd or copy the full tree. See [firewall configuration](firewall.md)
for atomic loads, chain ownership and recovery.

### Nonfatal warnings

Use `Warning` from `nvyr.errors` for an advisory that should be shown without
failing verification:

```python
from nvyr.errors import Warning

context.report(Warning("Traffic on interfaces not assigned to a zone may be allowed."))
```

This is a message object, not an exception. Do not raise it or return early from
`verify()`; subsequent checks must still run. The reporting pipeline adds the
`Warning:` prefix for `commit check` and commits, and records unattended recovery
warnings at warning level. Existing plain-text reports remain supported.

### Script registrations

One owner may be declared at several locations. Use the same priority at every
location. Ownership stops at nested declarations for another owner; editing only
that nested configuration does not rerun its parent script.

The default static-routing include declares:

```yaml
script:
  name: static
  priority: 40
  register:
    vrf: default
```

Its inclusion beneath `vrf name <name>` replaces just the registered value:

```yaml
include_schema:
- file: protocols/static.yaml.i
  replace:
    /script/register/vrf: {tag: name}
```

A tag reference resolves the nearest enclosing tag with that schema keyword (or
the declaration's own tag). Registration keys are generic: another script can add
fields besides `vrf`, with literal strings or tag references. Build-time checks
reject invalid declarations, unknown enclosing tags and conflicting priorities.

Every lifecycle stage can read:

```python
vrfs = context.scripts.get(context.owner, {}).get('vrf', ())
previous_vrfs = context.previous_scripts.get(context.owner, {}).get('vrf', ())
```

These read-only dictionaries contain deduplicated values for the complete effective
configuration, including unchanged instances. The previous dictionary comes from
the previous effective configuration. A removed instance is absent from `scripts`
and remains visible through `previous_scripts` and `context.get_deleted()`.
`get_deleted()` covers all concrete locations owned by the current script, excluding
sections owned by nested scripts. Registration does not add defaults or metadata to
the explicit running/saved configuration.

### Verification-only commits

`commit check` runs only `get_config()` and `verify()` for changed owners, with
`context.check_only=True`. Ordinary commits and recovery use `False`. A script
may assign `cc = context.check_only` at the start of `verify()`. Always run
configuration-consistency checks; selectively defer checks that require host
state established by an unapplied candidate. Report any deferred check with
`context.report("Skipped ...; checked during commit.\n")` so success is not
mistaken for validation of the live apply. Host reads that remain meaningful,
such as checking a physical Ethernet interface exists, still run.

`get_config()`, `verify()` and `generate()` must not change host state. Generate
configuration in memory; install files, change services and modify kernel state
only in `apply()`. A native syntax checker may require private temporary files;
remove those files after checking and never install them during generation.
A successful check does not guarantee a subsequent apply will
succeed, and does not replace verification during the actual commit.

### Lifecycle implementation

Keep feature behavior in its configuration script. Gather everything later stages
need in `get_config()`, check configuration relationships in `verify()`, and perform
all required transformation and rendering in `generate()`. `apply()` consumes the
completed result without changing its configuration dictionary. Prepare any
rollback files or operations during generation as well.

Validate standalone values through schema validators, including names, ranges,
paths and reserved words. Those validators also run when configuration is loaded;
do not repeat them in `verify()`. Keep checks that need multiple settings in
`verify()`, such as required children, conflicting options and overlapping subnets.
Filesystem existence, ownership and symlink checks still need to inspect the actual
runtime objects when they are used.

Place supporting functions immediately above the stage that uses them, and keep
`apply()` last. Use ordinary functions; a configuration script does not need a
second runtime class, another lifecycle hidden in a helper, or its own `main()`.
Share genuinely reusable operations such as safe filesystem access. Use Jinja for
native file structure, with small formatters for complex values, rather than a
template that merely calls a function to produce the entire file.

```python
def get_config(context):
    # context.effective: shared read-only full intended configuration with defaults
    # context.previous: read-only prior explicit running configuration
    # context.previous_effective: prior configuration with schema defaults, for compensation
    # context.root: first declared schema path; context.owner: registry name
    # context.recovery: idempotent reconciliation instead of a user commit
    # context.check_only: verification-only run, with no generate or apply
    # Return the whole view if later stages need cross-subsystem information.
    return context.effective


def verify(configuration, context):
    # Raise nvyr.errors.ValidationError for expected user configuration failures.
    ...


def generate(configuration, context):
    # Return an in-memory object; no host changes or config RPC.
    return configuration


def apply(generated, context):
    # Return only after successful live application. Implement atomic application
    # or compensation yourself, and make recovery safe to repeat after crashes.
    ...
```

Every affected owner executes once. The same effective root survives all stages;
`get_config` can return the whole view or extract a subtree without copying the full
configuration. Defaults are constructed once by the engine. Deletion still runs the
owner, whose owned subtree is absent/empty within that full effective view, so it can
remove live resources. Reading another owner's proposed configuration does not imply
that the other owner successfully applies it; partial-commit semantics are unchanged.

### Reading configuration values

Use `lookup()` for optional configuration reads, including single-level values.
Express a nested path as one tuple instead of chaining `.get()` calls:

```python
from nvyr.tree import lookup

neighbors = lookup(configuration, ('neighbor',), {})
destination = lookup(rule, ('connection', 'original', 'destination-address'), None)
```

Always choose the missing-value behavior deliberately. `lookup()` without a
default returns `MISSING`, not `None`; use an explicit `None`, empty collection,
or other fallback when that is what the caller expects. Do not duplicate schema
defaults in configuration scripts.

Use `configuration['key']` for required values established by earlier stages.
Use membership checks such as `'disable' in configuration` for valueless nodes:
an empty node is present even though its value is false in a Boolean test.
Ordinary `.get()` remains appropriate for native command responses, runtime
inventories, daemon metadata, and temporary bookkeeping dictionaries.

### Deleted configuration

Every lifecycle stage can call `context.get_deleted()` to inspect removals across
all schema locations owned by that script, excluding nested owners. It returns a
read-only mapping from absolute path tuples to previous effective values. The comparison runs only when called; it does not add metadata to
the configuration dict or store a separate deletion journal.

```python
def generate(configuration, context):
    deleted = context.get_deleted()

    for path, previous_value in deleted.items():
        # Build any service-specific cleanup instructions here.
        ...

    return configuration
```

For example, deleting `interfaces dummy dum0` while retaining other dummy interfaces
produces an entry with path `('interfaces', 'dummy', 'dum0')`. Its value contains
the old interface configuration, including effective defaults such as MTU 1500.
Removing the entire `interfaces dummy` subtree instead produces one entry at
`('interfaces', 'dummy')`, containing all its previous interfaces.

- Removed subtrees appear once, without redundant descendant entries. Empty nodes
  and valueless leaves are included; existing empty parents are not deletions.
- For multi-value leaves, only values absent from the new effective list are
  returned, as a tuple in their previous order. Reordering is not deletion.
- Scalar replacements are modifications, not deletions. A removed explicit scalar
  that falls back to a default still exists and is therefore not returned.
- Default lists participate in the same comparison. Deleting an explicit list
  reports only old values that disappear after the default list is restored.
- The final before/after state determines removals. Deleting and restoring a value
  before commit is not reported. A rename reports the removed original path.

These are planned removals for this owner's lifecycle, not proof of successful
application. Failed owners retain their pending changes, and a retry computes
removals against the then-current running configuration. Recovery compares its
previous effective configuration with its recovery target using the same helper.
Keep backend reconciliation: interrupted application can leave runtime resources
that are not represented by a persisted configuration difference.

`context.previous` remains the explicit previous tree. `get_deleted()` uses
`context.previous_effective` and `context.effective` instead, so defaults are
treated consistently. Tests constructing a context manually must supply
`previous_effective` when using this method. Nested results use the existing
`ReadOnlyTree` and immutable tuples; they cannot mutate shared commit state.

### Changed configuration

`context.get_changed()` returns a read-only mapping of absolute paths to
`{'previous': ..., 'effective': ...}`. It includes additions, replacements and
removals across all sections owned by the script, including nested registrations.
An optional tuple scopes the result, for example:

```python
from nvyr.tree import MISSING

changes = context.get_changed(('firewall',))

for path, values in changes.items():
    if values['previous'] is MISSING:
        # The path was added.
        ...
    elif values['effective'] is MISSING:
        # The path was removed.
        ...
    else:
        # The value changed, including changes caused by defaults.
        ...
```

Whole added or removed subtrees appear once; a narrower requested scope clips them
to that scope. Multi-leaves report the complete previous and effective tuples;
use `get_deleted()` for only the removed members. Empty dictionaries are valid
values, distinct from `MISSING`. The comparison is lazy and cached per scope for
this commit context. The underlying trees are not modified. Retries and recovery
get new contexts and compare against their own effective snapshots.

Configd also supplies its schema-indexed dependency registrar as
`context.dependencies`. Consumers can inspect typed providers and references using
`from_tree(configuration, 'dependency')` and `from_tree(configuration, 'depends')`.
The firewall uses it to select complete dependent objects for atomic replacement;
that backend-specific decision is not part of `get_changed()`.

## Service templates

Use `nvyr.helpers.template` for all service configuration rendering. Bundled templates live
under `src/nvyr/templates/` and are included in the Python and Debian packages.
`render(name, variables)` returns text; `write(path, text, mode=0o600)` installs it
using a same-directory temporary file, fsync and atomic replacement. Parent directories
must exist. Existing uid/gid are preserved on Unix; new files belong to the caller.
Scripts set a suitable mode and any new-file ownership for their service.

```python
from nvyr.helpers.template import register, render, write


@register('interface_label')
def interface_label(name):
    return f'Interface {name}'


def generate(configuration, context):
    return render('my_service/config.j2', {'config': configuration})


def apply(generated, context):
    write('/etc/my-service/config.conf', generated, mode=0o640)

    # Validate/reload the service here, including compensation on reload failure.
```

Keep formatting in Python helpers registered by `template.py`. Large formatter
families can live in dedicated modules such as `nftables_formatters.py`; Jinja
should primarily express layout, iteration and calls to those helpers. Separate
logical sections with blank lines in both templates and generated examples.

A template can call `{{ interface_label(name) }}` directly, including from imported
macros. `register('name', callable)` is also supported. Duplicate names (including
Jinja built-ins) are rejected. Register at module initialization; later registration
creates a fresh environment, so cached templates are never modified in place.
`json_text` is a pre-registered JSON serialization helper. The firewall template uses
`nft_rule(family, hook, number, rule)` and `nft_comment(number, description)`. Their common
keymap in `nftables_formatters.py` defines match/statement ordering and multi-value set rendering;
templates consume the effective configuration without an intermediate service dict.
`nft_family_dispatch(firewall, hook)` produces a family-dispatch vmap for configured
filters, keeping that syntax and selection logic out of the template.
`nft_state_policy(policies)` builds the counted state-policy vmap.
`nft_default_rule(family, hook, configuration)` builds the final counter/log/verdict rule.
Rule and default logging share generated prefix construction; hook context is required.

For external trusted template directories, use `TemplateRenderer('/path/to/templates')`;
its `register`, `render`, and `render_to_file` methods use the same pipeline with an
isolated function registry. `render_to_file(name, path, variables, mode=...)` renders
completely before writing. Prefer separate generate/apply calls in configuration scripts.

Following the [Jinja environment API](https://jinja.palletsprojects.com/en/stable/api/),
the pipeline supports includes/macros, uses `StrictUndefined` to fail on missing
variables, preserves trailing newlines and disables HTML escaping for service text.
Context is local to each render. Templates and Python helpers are trusted code;
service-specific validation and quoting remain the script's responsibility.
`RenderingError` is a `RouterError`, so missing/invalid templates and file-write errors
become lifecycle failures. Atomic file replacement does not make a multi-file update
or daemon reload transactional; scripts still own validation, reload and compensation.

## Pipeline extension

`Pipelines.register(name, definition, handler)` adds a modifier without changing the
lexer. Definitions use the same node kinds. A handler receives `(Output, argument)` and
returns `Output`. Set `sink: true` in a terminal definition. Preserve typed before/after
data only when the transformation still has configuration semantics; ordinary line
filters intentionally discard it. `match` and `except` use Python `re.search()`;
patterns are compiled and checked before execution. Quote alternation and spaces,
and escape regex metacharacters when literal matching is intended. Streaming
operational commands reject pipe modifiers before launch.
`Output.scope` records a resolved absolute configuration path while before/after retain
full root references. The commands modifier starts serialization at that scope; it
cannot collapse deletion to a parent outside the requested subtree.
The lookup scope and emitted command prefix are separate: descendant commands omit
the scope prefix. Selected leaves and creation/deletion of the selected object itself
retain a target relative to the nearest editable parent. `diff_commands()` accepts
an optional `prefix` for this presentation behavior; callers that omit it retain
absolute paths, including configuration loading and mutation replay.

## Verification and tests

Comment each check in `verify()` and its helpers with what it checks and why.
Keep schema validation for individual values separate from checks requiring
related configuration or live state. Enter feature-specific verification only
when that feature is present.

Use tests for parser behavior, owner assignment, deletion, defaults, failure at every
lifecycle stage, and recovery when adding or changing a subsystem.

## Kernel settings

`nvyr.helpers.kernel_settings_map` registers native path components, conversions,
defaults and bounds. Paths containing `{interface}` preserve interface names such
as `eth0.100` as a single component. Never turn arbitrary dotted names into paths.
Each entry declares its owner; the firewall schema generator only includes entries
owned by firewall. Other sections can reuse the manager with their own profile
path and registered settings without exposing them under the firewall CLI.

The configuration owner resolves the desired values and keeps
`kernel_settings.Manager.transaction()` open through its remaining apply steps.
The helper snapshots native values, writes only changes and restores them on
failure. Failed compensation raises `RecoveryError`; it must not be suppressed.
Kernel writes are not an atomic batch, and restoring values cannot undo packets
already processed or other irreversible effects of a tunable.

Interface-capable settings declare their `all` combination semantics explicitly.
The planner supports an override dictionary keyed by interface and setting; no
per-interface CLI overrides are exposed yet. Settings such as conntrack capacity
are global and cannot accept an interface override.

The keymap is the single source for configurable defaults. After changing it, run:

```bash
python -m build_tools.kernel_settings
python -m build_tools.schema_builder
python -m build_tools.command_tree
```

The first generator updates the packaged boot sysctl file and the firewall schema
fragment. That fragment contains ordinary CLI choices, validation and defaults,
not metadata that executes kernel writes. `--check` detects stale outputs and is
also enforced by the package build.

Only the keymap's explicit `BOOT_SETTINGS` selection is included alongside the
fixed routing baseline in the packaged sysctl file. Adding a configurable setting
does not automatically add it to early boot policy. The firewall helper applies
the full set of defaults during startup, even without a firewall configuration.

Only firewall-owned kernel settings are included in the runtime sysctl.d profile.
Fail-safe firewall configuration cannot define a competing copy of these options.

CPUFreq uses sysfs instead of procfs. `helpers/cpu_settings.py` discovers policy
capabilities and applies ordered governor/EPP writes with compensating rollback;
the `system_cpu` script owns configuration verification and target generation.
Its lifecycle runs during boot even without an explicit CPU subtree.
Its boot performance policy is deliberately not a schema default. Explicit CPU
values use shared dynamic validation and suggestions, and pre-management values
are retained in `/run/nvyr-kernel-settings/cpu.json` for override removal.
