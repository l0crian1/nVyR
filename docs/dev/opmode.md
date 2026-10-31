# Operational scripts

Command usage is documented separately in [network diagnostics](../users/network-diagnostics.md)
for ping and traceroute, and [power management](../users/power-management.md) for reboot
and poweroff. This guide describes the shared operational-script pipeline.

For firewall and NAT displays, use the shared
[nftables JSON normalizer](nftables-operational-data.md) to work with installed
rules and groups without unpacking nftables expression trees in each script.

Operational scripts live in `src/nvyr/op_scripts`, separately from configuration
lifecycle scripts. `nvyr.opmode.run()` builds an argument parser from explicitly
exposed Python functions and dispatches the selected function:

```python
#!/usr/bin/env python3
from nvyr import opmode


@opmode.command
def show(intf_name: str | None = None, detail=False, statistics=False):
    """Show interface information."""
    return f"Interface: {intf_name}; detail={detail}; statistics={statistics}"


if __name__ == '__main__':
    opmode.run()
```

Debian/ISO packaging discovers public `op_scripts/*.py` files, makes them executable,
and installs relative symlinks in `/usr/bin` named `<script-name>.nvyr.op`. Private
modules (names starting with `_`, including `__init__.py`) are not commands. Every
public script must start with `#!/usr/bin/env python3` using an LF line ending;
packaging rejects a missing shebang. No per-script packaging entry is needed.

```sh
interfaces.nvyr.op show --intf_name eth0
interfaces.nvyr.op show --help
```

For a development checkout installed into a virtual environment, install the same
symlinks into that environment's bin directory:

```sh
python3 build_tools/op_scripts.py --source src/nvyr/op_scripts --bin "$VIRTUAL_ENV/bin"
```

Activate that environment so both the commands and Python are found through `PATH`.
Module invocation (`python3 -m nvyr.op_scripts.interfaces`) remains available.
Underscore spellings such as `--intf_name` and hyphen spellings such as `--intf-name`
both work. There is no per-script argparse setup or duplicate argument definition.

## Function contract

- Only public, locally defined `@opmode.command` functions are exposed. Undecorated
  helpers, names starting with `_`, imported functions and classes are excluded.
- Required ordinary parameters become positional arguments. Defaulted parameters
  become named options. Keyword-only parameters always become named options and
  remain required when they have no default. Positional-only parameters retain
  positional invocation, with optional positions when defaulted.
- `str`, `int` and `float` annotations select conversions. Optional scalar annotations
  such as `str | None` work. Without an annotation, a non-None default supplies the
  type; otherwise the argument is text.
- Boolean parameters must have `True` or `False` defaults. They produce `--flag`
  and `--no-flag`; they do not accept strings such as `--flag false`.
- `list[str]`, `list[int]`, and `list[float]` accept multiple values. Named options
  repeat their flag; positional lists consume consecutive arguments. Optional
  lists can default to `None` or a list of the declared element type. Explicit
  values replace defaults, and each invocation receives its own default list.
- Function docstrings appear in help. Unknown functions, invalid arguments and
  unsupported signatures report argparse usage errors with exit status 2. Variadic,
  asynchronous and generator functions are intentionally unsupported.
- A function may print output and return `None`, or return text for the runner to
  print. `RouterError` reports a concise operational error with exit status 1.
  Unexpected programming errors retain their traceback for diagnosis.

For example, `def show(interface: list[str] | None = None)` accepts
`show --interface eth0 --interface eth1` and receives `['eth0', 'eth1']`.
A required keyword-only `interface: list[str]` requires at least one occurrence.
A required positional `def show(interface: list[str])` accepts `show eth0 eth1`.

`run(argv=None, namespace=None)` normally reads `sys.argv[1:]` and `__main__`.
Tests or explicit embedded callers may pass an argument list and a module globals
dictionary. CLI command/schema definitions remain trusted installed code. These
captured and streaming commands both run with configd's privileges. Their `cmd()`
children inherit those privileges without `sudo`. Configd authorizes the logged-in
account before dispatch; privileged execution does not give that account shell or
configuration access beyond its role. Expose only operations appropriate for every
role allowed to execute the mapped command. Directly launching a script outside the
nVyR CLI still uses the invoking account's privileges.

## Private output

`| strip-private` requests masking before formatting. For an operational script,
configd supplies `--strip-private` to the selected function through the existing
signature-based argument parser. Add `strip_private: bool = False` to functions
that support it, and mask values before building tables or other output:

```python
from nvyr.helpers.strip_private import strip_ip, strip_mac


@opmode.command
def show(strip_private: bool = False):
    address = strip_ip('192.0.2.1/24', strip_private)
    mac = strip_mac('00:11:22:33:44:55', strip_private)

    return f'{address} {mac}'
```

Helpers also include `strip_ipv4`, `strip_ipv6`, `strip_password`, and
`strip_value` (other sensitive text). False returns the original value; true
returns an opaque marker such as `<ipv4>` or `<password>`. IP helpers retain
non-address choices such as `dhcp` and interface names, and support prefixes
and address ranges. They mask public as well as private addresses.

The framework never rewrites operational text. `interfaces.py` masks a copy of
its kernel data before table layout, including detail and raw displays. Functions
without the parameter report an unsupported argument; direct system-command
mappings reject the modifier. Add explicit masking support to each new script.
Like other pipe modifiers, this requires a captured command; streaming commands
reject pipes. `@line` contains only the command before the first unquoted pipe.

## Schema mapping

Operational YAML uses one command syntax: a nonempty list of explicitly quoted
strings. Numeric-looking values must also be quoted. Plain unquoted strings,
numbers, booleans and nested argument objects are rejected by the builder.
`script`, `argv` and `value_argv` are not operational YAML fields.

```yaml
interfaces:
  kind: tag_node
  optional_value: true
  description: Interface display
  command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3']
```

Bundled operational YAML uses the execution defaults: captured commands have a
15-second timeout; streaming commands have no timeout unless explicitly supplied.
`stream` is a sibling of `command`. Executables are resolved through
standard `PATH` lookup without a shell. Internal CLI actions also use lists, such
as `command: ['configure']` and `command: ['version']`; these reserved names retain
their existing in-process dispatch and permission checks, and do not accept arguments.

On an `optional_value` node, a placeholder for that node's value position is
omitted when no value was supplied, along with its immediately preceding option
(for example, `--intf_name` or `-i`). Thus `@3` is omitted for `show interfaces`
and `show interfaces detail`; `detail` is a child keyword, not an interface name.
A positional argument without an option is omitted on its own. Keep an option
and its value adjacent; unrelated flags remain. An explicitly supplied empty
string remains a supplied value. Other missing positional indices produce errors.

The builder lowers these lists to the existing runtime command representation,
while the parser tracks whether an optional value was actually consumed. Runtime
command objects contain `argv` and optional `stream` and `timeout` properties.
The CLI and configuration daemon do not interpret the YAML authoring syntax.

For `.nvyr.op` executables, the builder checks that the script exists, the named
function is public and decorated with `@opmode.command`, and its argument names,
required values, flags and literal value types match the Python signature. It
reads source signatures without importing scripts or executing their code, and
uses the same argument registration as runtime `opmode`. Use the supported builtin
annotations (including list/optional forms) and literal defaults in these public
signatures. External executables such as `vtysh` are not inspected. Placeholder
contents are validated at runtime; they cannot be type-checked during a build.

Each placeholder occupies a complete argv entry:

- `@1`, `@2`, Ã¢â‚¬Â¦ select 1-based tokens from the original command **before the first
  output pipe**. Token values retain the original spelling, without shorthand
  expansion; quotes and escapes are decoded by the shared CLI lexer. When used in
  configuration mode, the `run` wrapper is excluded: `@3` still selects `eth0`
  in `run show interfaces eth0`.
- `@line` contains the command before the first unquoted pipe, retaining original
  quoting, internal whitespace and any `run` prefix. Whitespace separating the
  command from that pipe is removed. Quoted or escaped literal pipes are retained.
  It is passed as **one argument**. Without a pipe, the input is preserved exactly.
- `@line-N` removes token position N; `@line-N-M` removes positions N through M
  inclusive. Positions follow `@1` indexing, excluding the `run` wrapper and
  output pipes. Only the selected source span is removed; all surrounding text,
  whitespace, quotes and any `run` prefix remain unchanged. Output modifiers are
  excluded, just as for plain `@line`.
  The result is still one argument. For example, `@line-1-2` with
  `show interfaces "WAN Interface"` passes ` "WAN Interface"` (including the
  leading space and quotes). Positions must exist and ranges must be ascending.
- `@@text` emits literal `@text`. Other entries remain literal; embedded forms such
  as `--name=@3` are not interpolated. Expansion is never recursive.

Multiple placeholders can be used in one definition. For the original input
`show interfaces ethernet eth0 vif 200`, this passes `eth0` and `200` separately:

```yaml
command: ['interfaces.nvyr.op', 'show', '--intf_name', '@4', '--vif', '@6']
```

This is an illustrative mapping; it requires adding the corresponding Python
argument before it can pass the build checks. It does not add VIF support.
`command: ['static.nvyr.op', 'show', '--cmd', '@line']` would pass the complete
command text before any output modifiers as one argument to a static operational
script implementing that signature.

Missing indices/values and invalid placeholders produce a CLI error before any
subprocess starts. An executable or function name must be fixed in the schema;
user tokens cannot select it. Argument vectors use the text-returning `cmd()` helper,
including timeouts and native stdout/stderr capture. No shell is invoked, and
rendered values are never split again. Output modifiers still run in nVyR after
the script finishes.

## Reusable operational leaves

The interface tree uses ordinary path traversal. `detail` and `statistics` are
terminal commands, available under both `interfaces` and `ethernet`. Their shared
include contains only node kinds, descriptions and valueless metadata. Each use
adds its complete commands with existing include operations:

```yaml
children: # interfaces

  include_schema:
  - file: operational/interface_options.yaml.i
    as: null
    add:
      /detail/command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3', '--detail']
      /statistics/command: ['interfaces.nvyr.op', 'show', '--intf_name', '@3', '--statistics']
```

The Ethernet include uses `@4` and adds `--intf_type ethernet` to each command.
A tag with `optional_value: true` offers both its optional name and its children.
Declared child keywords (including unambiguous abbreviations) take precedence over
an optional name. The name must immediately follow its tag keyword. A typed
subcommand such as `ethernet` precedes the name. Optional-name omission is retained
when selecting a descendant command, so `detail` never becomes an interface name.

```text
show interfaces
show interfaces detail
show interfaces eth0 statistics

show interfaces ethernet
show interfaces ethernet detail
show interfaces ethernet eth0 statistics
```

Each leaf ends the command; `detail statistics` is not a combined interface command.

## Command access

Commands default to `access: read-only`, allowing all four nVyR roles. Declare
`access` only where a higher minimum role is required:

```yaml
refresh:
  kind: node
  access: net-admin
  children: # refresh

    routes:
      kind: node
      command: ['routes.nvyr.op', 'refresh']
```

The minimum role is inherited by descendants unless a child explicitly overrides
it. Dev-admins can run every command. Sys-admin adds account management to
net-admin router administration; read-only permits inspection and diagnostics. Invalid role names fail schema generation. Ordinary
commands do not need an explicit access setting.

Configd enforces the resolved policy before execution, including configuration-mode
`run` and `shellcmd`, and rechecks the authenticated account before attaching a
streaming command. Completion hides inaccessible commands while allowing navigation
to explicitly accessible descendants. Anchored commands also enforce the policy of
each supplied option. YAML permissions do not grant Linux shell privileges to
restricted roles or replace configd's configuration and account-management checks.

## Anchor traversal

The anchoring framework remains available for operational schemas that explicitly use
`anchor: true`. After a complete leaf, traversal returns to the first active anchor;
normal nodes and nested tags retain their own boundaries. Validation, abbreviation,
completion, quoted values and configuration mode's `run` use the same traversal.
Configuration anchoring expands ordinary mutations through `set_paths()` and also
supports nested anchored node groups; see the configuration authoring guide.

Operational execution uses explicit `command` definitions and their placeholders.
Ordinary traversal executes the final node's command; an explicitly anchored path
executes the anchor's command after a complete descendant path. The existing `@line` placeholder
can pass the original invocation as one string. Traversal does not synthesize Python
options or append flags to the command vector.

Scripts may explicitly call `opmode.command_arguments(line, mapping)` to translate
anchored options. It returns `(anchor_path, argv)`: the canonical anchor path
(including tag values), and an ordered list of translated option arguments.
The script places tag values/positional arguments wherever its program requires.

```python
OPTIONS = {
    'count': '-c',
    'numeric': '-n',
    'do-not-fragment': ['-M', 'do'],
}

path, options = opmode.command_arguments(line, OPTIONS)
argv = ['ping', *options, '--', path[-1]]
```

The helper uses the existing schema's anchors, validators, abbreviations and
quoting. Valued leaves append their value; valueless leaves append only their
mapping. Repeated multi leaves repeat the mapped flag and value in input order.
Keys are direct child names, or tuples such as `('transport', 'port') for leaves
under normal grouping nodes. Missing mappings produce an error. Strings are
single argv elements and lists are multiple elements; strings are never split
on spaces. Programs requiring a different multi-value encoding can handle that
in their script. The helper requires a complete anchor and handles a `run` prefix.

A mapping may also be a Python function receiving the validated value (`True` for
a valueless flag) and returning the complete list of arguments. For example,
`'dscp': lambda value: ['-t', str(int(value) * 4)]` converts DSCP to TOS. The helper
does not append the value again. A function may return an empty list when the
script collects a positional value to place later, as traceroute does for `size`.

This parsing is opt-in. A simple vtysh wrapper can keep using
`cmd(['vtysh', '-c', line])` directly; `@line` always arrives as text.

## Administrator system commands

For command usage, see [dev-admin host commands](../users/cli.md#host-commands-for-dev-admins).

Configd checks the authenticated account's dev-admin role before dispatch and again
after terminal attachment, immediately before launch. Other roles cannot bypass
this through abbreviations, `run`, or output modifiers.

`op_scripts/shellcmd.py` receives `@line`, uses the existing lexer to recover the argv,
and calls `call(..., new_process_group=False)`. Quoted
spaces, empty arguments and literal shell characters keep their argument boundaries.
There is no implicit shell expansion. Unquoted `|` retains nVyR's output-modifier
meaning; an explicit shell command such as `shellcmd /bin/sh -c "..."` is needed for
shell syntax. Interactive programs use the shared PTY relay, including input,
Ctrl-C, resizing and exit statuses. Execution inherits configd's root identity,
environment and systemd service restrictions.

The schema defines a valued operational leaf with `rest: true`. Its first value
is required; subsequent tokens are opaque command arguments consumed by that leaf,
not additional nVyR keywords. The original input remains available through `@line`
and positional placeholders. Ordinary leaves and anchored commands retain their
existing parsing behavior. The shared shellcmd include contains:

```yaml
shellcmd:
  kind: leaf_node
  access: dev-admin
  description: Execute a system command as root (dev-admin only)
  rest: true
  command: ['shellcmd.nvyr.op', 'execute', '@line']
  stream: true
```

The schema's dev-admin restriction is enforced in trusted controller/daemon code, not
in client command visibility or the script's inherited root identity. Directly
invoking `shellcmd.nvyr.op` outside nVyR grants no privileges.

## Possible completions

Help displays `<Enter>` first when execution is available. When anchored contexts
are grouped, outer contexts appear first and the current context appears last,
closest to the prompt. Each context puts informational hints before its choices
and suggestions. Whole-number candidates sort numerically before words, which
sort alphabetically. Joined-value `and` belongs to the current value context.
This is presentation ordering: hints never become literal completion candidates.
See [using the CLI](../users/cli.md#help-completion-and-command-history) for user examples.

## Command execution helpers

Import helpers from `nvyr.helpers.process`. `cli_cmd()` is their shared subprocess
implementation; application code uses `cmd()`, `run()`, `call()`, or `rc_cmd()`.
All take an argv sequence; none invokes
an implicit shell. A shell is possible only by explicitly putting one in that argv.

```python
from nvyr.helpers.process import cmd, run, call, rc_cmd

output = cmd(['ip', 'link', 'show'])
rc = run(['ip', 'link', 'show'])
rc, output = rc_cmd(['ip', 'link', 'show'])
rc = call(['ip', 'link', 'show'])  # Live terminal output and exit code
```

`cmd()` returns captured stdout plus stderr as text on success. It does not
print or log the output. A nonzero exit raises `CommandError`, carrying the
native diagnostic and the exit code in `error.details['returncode']`.

```python
text = cmd(['ip', 'link', 'show'])  # Quiet on success; raises on failure.
print(text, end='')                # Display only when requested.
```

An operational `show()` function returns the string when it should be displayed
by `opmode`. For commands where nonzero exits are expected, use `rc_cmd()`:

```python
status, text = rc_cmd(['shutdown', '--show'])
# The caller chooses how to handle the status and display the native message.
```

`run()` quietly returns only the program's exit code; `rc_cmd()` returns
`(status, output)`. `call()` displays live terminal output and returns the exit
code. These three helpers do not raise or log just because the program returned
nonzero. No `check` flags are needed.

All support `timeout`, `cwd`, and `env`. Captured helpers default to 15 seconds;
`call()` defaults to no timeout. `None` disables the timeout. Spawn failures and
timeouts remain execution errors: the
program could not start or finish, so there is no completed result to return.
Signal statuses use shell conventions, e.g. SIGINT
becomes 130. Streaming wrappers use `call()` and propagate that status without
turning ordinary command diagnostics or cancellation into exception messages.

`cmd()`, `run()`, and `rc_cmd()` also accept `stream=True`. In that mode,
stdin/stdout/stderr are inherited directly. Output is displayed
as the program produces it; Python scripts should flush partial-line progress output
just as they would at a shell. Streaming does not also accumulate output: `cmd()`
returns `''`, `rc_cmd()` returns `(rc, '')`, and `run()` returns the exit code.
`call()` uses streaming automatically. The process group receives terminal signals and terminal ownership is restored on
exit, interrupt or timeout. Normal captured execution remains noninteractive.

An operational script that wraps a streaming utility can propagate its exit code:

```python
@opmode.command
def probe(destination, count: int = 5):
    raise SystemExit(call(['ping', '-c', str(count), destination],
                          new_process_group=False))
```

For live output **through the nVyR CLI**, also set `stream: true` alongside `command`
in its YAML schema. Configd validates the full input and launches the resolved argv
under its own privileged identity, just as for captured commands. A dedicated PTY
relays output, input, window size and Ctrl-C over the authenticated socket after
prompt_toolkit releases the local terminal. The CLI keeps its edit session, records
the exit status and restores its terminal settings when the command ends.

Clients cannot supply an executable, arbitrary argv, credentials or environment for
privileged execution. The installed command tree supplies the executable and maps
validated input to arguments. Terminal controls carry only input, dimensions, a
terminal type and interruption/finish messages. Account authorization is checked
again before launching after the terminal attaches. The existing dev-admin-only
Linux `shell` command remains separate and is not executed as root by this relay.

Streaming creates a foreground process group by default. A script wrapping another
utility should use `new_process_group=False` for that inner invocation, as above,
so the script and utility stay in the daemon-managed group. Configd stops that group
on completion, timeout or disconnect, including descendants.

Omit the schema timeout for an unlimited streaming command, or specify a positive
number of seconds. Output modifiers (`| match`, `| count`, `| export`,
`| strip-private`, etc.) are rejected before launching a streaming command.
They work on captured commands and do not switch a terminal command to capture.
`protocol.Client` handles the terminal exchange. The final `command` event reports
`returncode`; it no longer asks the client to execute argv. CLI and configd must use
protocol version 2 together. Ordinary captured text replies remain unchanged.

## Interface script and testing

`op_scripts/interfaces.py` contains interface reporting with `intf_name`, `raw`,
`detail` and `statistics` Python options. Its reporting implementation is independent
of YAML command lowering and executable installation. The operational tree maps
interface names to `--intf_name` and shared flags to `--detail` and `--statistics`.
The Ethernet branch passes `--intf_type ethernet`.

`tests/test_operational_sources.py` covers quoted command arguments, source include
edits, optional values, multiple substitutions and executable symlink installation.
`tests/test_opmode.py` covers function registration and placeholders;
`tests/test_operational_anchors.py` covers option orders, boundaries, validation,
completion and dispatch. `tests/test_process.py` uses real PTYs to exercise immediate
output, stdin, Ctrl-C, terminal restoration, timeouts and exit codes.
