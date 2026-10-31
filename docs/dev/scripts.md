# Script and module guide

This is a quick map of the project's maintained scripts, Python modules and their
callers. Paths link to source files. Most Python files are **imported components**,
not commands to run individually. Examples below assume the repository root and an
installed development environment (`python -m pip install -e '.[test]'`). Router
services and image tooling run on Linux; the WSL test launcher runs in PowerShell.

## CLI engine: start here

The two CLI engine entry points are `nvyr` (the terminal client) and `configd` (the
authoritative daemon). The client sends commands and completion requests through a
Unix socket; the daemon owns parsing, candidate state, commits and recovery.

For a submitted `set` followed by `commit`, the main flow is:

1. `cli.py` submits text through `protocol.py` to `daemon.py`.
2. `controller.py` dispatches the command. `lexer.py` identifies tokens, while
   `schema.py` resolves paths, shorthand, values and anchors.
3. `engine.py` stages ordinary mutations using `tree.py`; `set` does not apply
   the configuration to the host.
4. On `commit`, `engine.py` invokes the affected owners registered in `modules.py`:
   `get_config()` → `verify()` → `generate()` → `apply()`.
5. Successful owner changes are published and persisted through `storage.py`;
   results return to the CLI. `save` separately records the boot configuration.

Completion takes the same client/daemon route to `Controller.completion()`, using
the schema, candidate projection and suggestors. It does not execute feature scripts.
See [architecture](architecture.md) for concurrency and partial-commit semantics.

### Terminal and transport

- [interface_naming.py](../../src/nvyr/interface_naming.py): separate boot/hotplug service
  for physical Ethernet naming. Run via `nvyr-interface-naming.service`; its
  `--udev-properties SYS_PATH` mode is the read-only udev handoff helper. `--state`,
  `--runtime` and `--timeout` support isolated deployment/testing; `--debug` logs
  physical naming events. See
  [persistent naming](interface-naming.md) before changing machine-wide assignments.
- [cli.py](../../src/nvyr/cli.py): implements the prompt, key bindings, Tab/`?`, inline
  suggestions, pasted commands, confirmations, local load/export files and shell
  handoff. Run `nvyr`; use `--socket PATH` for another daemon and
  `--history-directory DIR` for another navigation-history location.
- [daemon.py](../../src/nvyr/daemon.py): starts configd, recovers configuration before
  accepting clients, authenticates local socket peers and handles RPC requests and
  rollback timers. Normally run through `nvyr-configd.service`. Direct invocation is
  `configd --socket PATH --state DIR --group GROUP`; defaults are
  `/run/nvyr/configd.sock`, `/var/lib/nvyr` and 20 retained revisions, with no default
  group argument. This is a real router daemon: startup can reconcile host services.
  Configure retention with `set system configuration commit-revisions N`.
  `--session-timeout SECONDS` sets the default total session lifetime (28800,
  eight hours); activity does not reset it.
- [protocol.py](../../src/nvyr/protocol.py): shared length-prefixed JSON transport,
  request/reply handling, errors and streamed output. Import `Client` when writing
  another local client; use its `request()` API rather than accessing daemon state.
  See [protocol reference](protocol.md).
- [config_session.py](../../src/nvyr/config_session.py): local Python automation API.
  `ConfigurationSession` supports full `set`/`delete` commands, commits (optional
  confirmation deadline in seconds), configuration snapshots, dict replacement or
  merge loads, explicit lock requests/takeover, confirm, discard, save and context cleanup.
  It uses configd's existing engine and permissions with a default five-minute
  total lifetime. See [Python configuration sessions](config-session.md).
- [history.py](../../src/nvyr/history.py): separate operational/configuration Up/Down
  histories, used by `cli.py`. Defaults to `$XDG_STATE_HOME/nvyr/history` or
  `~/.local/state/nvyr/history`. It is neither commit history nor a prediction source.

### Parsing, completion and display

- [helpers/config_feedback.py](../../src/nvyr/helpers/config_feedback.py): formats
  commit progress, summaries and the Presto `show config-status` table. Configd
  retains structured results for Python callers; the controller uses these
  formatters for interactive output.
- [controller.py](../../src/nvyr/controller.py): command dispatcher and completion
  coordinator. `execute()` routes operational and configuration commands; `load()`
  handles imports; `completion()` supplies every completion mode. Start here for
  command behavior or completion-flow changes. `register_operation()` adds trusted
  operational handlers.
- [opmode.py](../../src/nvyr/opmode.py): shared parser/runner for explicitly exposed
  operational Python functions. Derives positional arguments, options and boolean
  flags and repeated list arguments from signatures. Scripts call `opmode.run()`
  rather than defining argparse parsers. `command_arguments()` translates anchored
  options through a script-owned map; see [operational scripts](opmode.md).
- [op_scripts/interfaces.py](../../src/nvyr/op_scripts/interfaces.py): interface
  reporting script. `show interfaces` and `show interfaces eth0` dispatch its
  `show()` function through the installed `interfaces.nvyr.op` executable.
- [op_scripts/ping.py](../../src/nvyr/op_scripts/ping.py): streams Linux ping output.
- [op_scripts/traceroute.py](../../src/nvyr/op_scripts/traceroute.py): streams traceroute
  output, translates anchored options and checks incompatible probe settings.
  `ping 1.1.1.1 count 5 interval 0.5 numeric` passes the original command through
  `ping.nvyr.op`; the shared anchor parser resolves options in any order.
- [op_scripts/shellcmd.py](../../src/nvyr/op_scripts/shellcmd.py): executes arbitrary system
  argv through `call()`. Use `shellcmd vtysh -c "show ip route"` in the nVyR
  CLI. Configd enforces dev-admin access before privileged execution; this
  script has no independent elevation or password prompt.
- [op_scripts/shutdown.py](../../src/nvyr/op_scripts/shutdown.py): runs `shutdown` for
  reboot, poweroff, cancel, and `shutdown --show`. It drops the text after the
  first comma in scheduling responses so the CLI does not repeat `shutdown -c`.
  Show and cancel return native command text, including no pending shutdown.
- [build_tools/op_scripts.py](../../build_tools/op_scripts.py): discovers public
  operational scripts, checks their shebangs, sets executable permissions, and
  installs relative `.nvyr.op` symlinks. Debian/ISO packaging runs it automatically;
  development checkouts can target their virtual environment's bin directory.
- [lexer.py](../../src/nvyr/lexer.py): quote-aware tokenization, source positions,
  pipeline splitting, value quoting and load-argument parsing. Use it wherever CLI
  text is interpreted so spaces, quotes and pipes keep consistent meanings.
- [schema.py](../../src/nvyr/schema.py): runtime JSON-tree loading, schema checks,
  keyword resolution, node/value validation, candidates, hints and effective defaults.
  `Cursor` handles ordinary paths; `SetCursor`/`set_paths()` expand anchored commands
  into ordinary paths. Completion can traverse invalid tag values while execution
  still validates them. Import `Schema`; schema construction itself belongs in the
  separate build tool below.
- [render.py](../../src/nvyr/render.py): CLI-facing configuration, candidate and diff
  formatting, including serialization to `set`/`delete` commands. Called by the
  controller and pipelines; service-file rendering belongs in `helpers/template.py`.
- [pipeline.py](../../src/nvyr/pipeline.py): parses and runs `commands`, `match`,
  `except`, `count`, `export`, `more` and `no-more` modifiers. `Output` retains structured configuration
  references where appropriate. Extend through `Pipelines.register()`; final export
  file writing happens in the CLI process. The controller handles `strip-private`
  before rendering or dispatching scripts.
- [strip_private.py](../../src/nvyr/helpers/strip_private.py): reusable IP, MAC,
  password and sensitive-text masks; schema-directed configuration copies with
  per-display aliases. Operational scripts call the helpers before formatting.
- [errors.py](../../src/nvyr/errors.py): shared expected-error classes and serialized
  error context. Raise `ValidationError` for invalid configuration and
  `RecoveryError` when live state cannot safely be reconciled or compensated.

### State, commits and feature dispatch

- [engine.py](../../src/nvyr/engine.py): owns sessions, candidate mutation journals,
  edit context, locks, commits, save/rollback and crash recovery. `mutate()` stages
  changes; `commit()` applies affected owners; `tick()` handles confirmed-commit
  expiry. Start here for transaction or configuration-state behavior.
- [tree.py](../../src/nvyr/tree.py): copy-on-write lookup/update/removal, mutation
  overlays, branch projections, structural changes and `ReadOnlyTree`. These are
  the shared configuration primitives; deleting a child preserves empty parents.
- [storage.py](../../src/nvyr/storage.py): atomic durable JSON records and historical
  snapshots through `Store`. Under the daemon state directory it manages `state.json`,
  `transaction.json`, `confirmed.json` and `history/`; the system saved file is
  `/config/nvyr-saved-config` (custom development state directories retain `boot.json`). Use this layer for
  engine persistence rather than writing those files directly.
- [op_scripts/images.py](../../src/nvyr/op_scripts/images.py): operational image commands
  and the PTY handoff to a transient installer service outside configd's sandbox.
- [helpers/installation.py](../../src/nvyr/helpers/installation.py): guided confirmations,
  downloads, disk selection, partitioning and BIOS/UEFI GRUB installation.
- [helpers/images.py](../../src/nvyr/helpers/images.py): ISO manifests, payload verification,
  installed-image catalogs and atomic GRUB menu publication.
- [helpers/image_migration.py](../../src/nvyr/helpers/image_migration.py): persistent file,
  saved configuration and daemon-state transfer; extension point for future services.
- [build_tools/image_manifest.py](../../build_tools/image_manifest.py): hashes the final
  live-build payload before ISO mastering. The initramfs `nvyr` hook/root script under
  `packaging/initramfs/` mounts each installed image's overlay and configuration.
- [helpers/script_schema.py](../../src/nvyr/helpers/script_schema.py): shared build/runtime
  validation and indexing of script locations and generic registration declarations.
- [helpers/ownership.py](../../src/nvyr/helpers/ownership.py): collects script metadata,
  identifies changed owners across nested/dynamic locations, and merges successful
  sections during partial commits. Individual pasted commands do not build snapshots.
- [modules.py](../../src/nvyr/modules.py): defines `CommitContext` and explicit
  owner-to-script registration.
  `registry()` installs the real combined firewall/NAT, Ethernet, dummy, static-routing,
  DNS, hostname, login and SSH implementations; missing owner registrations are errors. Add a feature here
  and declare its owner in the source schema. `context.get_deleted()` computes a
  read-only mapping of removed effective values under that owner on demand; see
  [deleted configuration](extending.md#deleted-configuration). `context.get_changed(path=None)`
  additionally reports effective additions and modifications, with previous/effective
  values, cached lazily for each requested scope.

## Configuration scripts

All files in `src/nvyr/config_scripts/` are invoked by the engine through
`modules.py`, including removal and recovery. Do not execute them directly. Their
common interface is `get_config`, `verify`, `generate`, `apply`; see
[module authoring](extending.md). The commands below stage configuration; `commit`
applies it and `save` makes it the boot configuration.

- [firewall.py](../../src/nvyr/config_scripts/firewall.py): manages `firewall` and `nat`.
  Validates maps, match-groups and enabled rules, renders the shared effective configuration to nftables
  and applies it atomically. Example: `set firewall ipv4 forward filter rule 10 action accept`.
- [firewall_failsafe.py](../../src/nvyr/config_scripts/firewall_failsafe.py): verifies
  and stages early-boot protection using the shared firewall implementation.
  Live configuration does not activate the fail-safe table; normal firewall
  application removes it during boot handover. See [fail-safe](firewall-failsafe.md).
- [nat.py](../../src/nvyr/config_scripts/nat.py): verifies IPv4 source/destination NAT for
  the firewall owner. NAT rules and map consumers are rendered and applied in the
  shared firewall transaction. Example: `set nat source rule 10 outbound-interface eth0 translation address masquerade`.
  See [NAT configuration](nat.md).
- [interface_ethernet.py](../../src/nvyr/config_scripts/interface_ethernet.py): manages
  `interfaces ethernet`. `get_config()` gathers Ethernet profiles, VRFs and bridge
  membership. `verify()` checks naming readiness, device existence, membership
  and VIF constraints before native preflight. `generate()` prepares parent/VIF
  definitions, and `apply()` submits them unchanged to netlinkd. Recovery permits
  temporarily absent ports. Example: `set interfaces ethernet eth0 address dhcp`.
- [interface_dummy.py](../../src/nvyr/config_scripts/interface_dummy.py): manages
  `interfaces dummy`. `get_config()` gathers dummy interfaces, VRFs and bridge
  membership; `verify()` checks membership and performs native preflight.
  `generate()` prepares the daemon definitions without repeating DHCP/IP
  verification, and `apply()` submits those definitions unchanged. Netlinkd
  validates incoming requests and owns device creation, removal and rollback.
  Example: `set interfaces dummy dum0 address 192.0.2.1/32`.
- [interface_loopback.py](../../src/nvyr/config_scripts/interface_loopback.py): manages
  addresses and description on the existing `lo` device, preserving the kernel's
  loopback addresses. Verification and generation share a definition formatter;
  `verify()` performs native preflight without invoking `generate()`, and `apply()`
  submits the prepared definitions. See [loopback](../users/interfaces.md#system-loopback).
- [interface_virtual_ethernet.py](../../src/nvyr/config_scripts/interface_virtual_ethernet.py):
  manages reciprocal veth pairs and their VLAN children through netlinkd.
  `get_config()` gathers current and previous endpoints, VRFs and bridge membership.
  `verify()` checks membership, VIF constraints and peer changes before native
  preflight. `generate()` prepares endpoint/VIF definitions for `apply()` to submit unchanged.
- [interface_bridge.py](../../src/nvyr/config_scripts/interface_bridge.py): manages
  bridges, port membership, VLAN switching and spanning-tree attributes through
  the shared link lifecycle. `get_config()` gathers bridges, configured interfaces
  and VRFs; `verify()` owns bridge relationship checks and requests read-only
  native validation. `generate()` prepares the link definitions, and `apply()`
  submits them unchanged to netlinkd for transactional application and rollback.
  The shared bridge helper contains native option conversion only. See [bridges](bridges.md).
- [vrf.py](../../src/nvyr/config_scripts/vrf.py): manages `vrf name`, requires unique
  table IDs, and creates/removes VRF devices through netlinkd. Existing table IDs
  require explicit deletion and commit before replacement. `get_config()` gathers
  current/previous VRFs and firewall zones; verification checks relationships and
  requests native ownership preflight. Generation prepares the link definitions
  submitted unchanged by `apply()`. Example: `set vrf name BLUE table 100`.
- [vrf_conntrack.py](../../src/nvyr/config_scripts/vrf_conntrack.py): gathers VRFs,
  interface/container-network membership, and one boot/allocation-ledger snapshot.
  Verification checks identity completeness, ledger integrity and remaining zone
  capacity without allocating IDs. Generation assigns stable IDs, resolves map
  membership and renders the dedicated nftables table through Jinja. Application
  reserves IDs before the shared nftables loader runs; reservations survive a
  failed application and are reclaimed only after reboot.
- [protocols_static.py](../../src/nvyr/config_scripts/protocols_static.py): manages
  `protocols static`, checks next hops, renders native commands and applies owned
  routes through the shared reload manager. `get_config()` gathers the registered
  VRF subtrees; verification checks path relationships and live next-hop addresses.
  Jinja defines family, prefix, source-specific and path iteration, with focused
  formatters for native operands and options. `generate()` prepares sorted command
  lists, and `apply()` submits them to the shared manager without changing them.
  Example: `set protocols static route 192.0.2.0/24 next-hop 198.51.100.1`.
- [protocols_bgp.py](../../src/nvyr/config_scripts/protocols_bgp.py): verifies unicast
  neighbors and policies, renders BGP instances and reconciles them through the
  same reload manager after policies and static routes. `get_config()` gathers
  registered instances, policy references and configured interface addresses.
  The script owns parameter, peer and family verification; live local-address
  checks run during commit and are deferred during check-only validation.
  Jinja defines instance, peer-group, neighbor and address-family structure,
  with focused helpers for option commands, inheritance and native defaults.
  `apply()` submits the prepared contribution to the shared FRR manager.
  See [BGP](bgp.md).
- [policy.py](../../src/nvyr/config_scripts/policy.py): verifies access lists,
  prefix-lists and route-maps, then applies their native commands through the
  same FRR reload manager while preserving static routes and unrelated policies.
  CLI validators check POSIX expressions and next-hop address types; `verify()`
  checks completeness, references and relationships. `generate()` renders the
  native list and route-map structure with Jinja, using focused formatters for
  filter operands, communities and match/set expressions. `apply()` submits the
  prepared contribution through the shared FRR ownership and rollback pipeline.
- [system_dns.py](../../src/nvyr/config_scripts/system_dns.py): manages `system name-server`,
  sending static resolver addresses and DHCP interface selectors to netlinkd.
  Example: `set system name-server eth0`. See [system DNS](dns.md).
- [system_hostname.py](../../src/nvyr/config_scripts/system_hostname.py): manages
  `system host-name`, applying the kernel hostname, `/etc/hostname` and the local
  hostname mapping in `/etc/hosts`. Removal
  restores `nvyr`; normal save, boot recovery and rollback semantics apply.
  Example: `set system host-name test123`, then `commit` and `save`.
- [system_configuration.py](../../src/nvyr/config_scripts/system_configuration.py):
  registers `system configuration` as a commit unit. Its settings are consumed by
  configd after durable publication rather than configuring an external service.
  `set system configuration commit-revisions 20` controls retained snapshots;
  pruning deliberately runs outside the script lifecycle so it cannot precede
  successful publication.
- [system_cpu.py](../../src/nvyr/config_scripts/system_cpu.py): gathers CPU policy
  capabilities and the boot baseline, verifies driver restrictions, and prepares
  per-policy governor/EPP targets in `generate()`. The runtime helper writes those
  targets, checks EPP after governor changes and restores affected policies on
  failure. Boot selects performance only where supported, without a CLI default.
- [logging.py](../../src/nvyr/config_scripts/logging.py): gathers current and previous
  `system logging` settings, verifies service overrides, and renders collector
  routing and rotation files through Jinja in `generate()`. `apply()` installs the
  prepared files and FRR syslog contribution, restoring the previous collector
  files on failure. Early boot uses the same templates with default settings.
  NFLOG subscription coordination and log reopening remain shared runtime functions.
- [system_login.py](../../src/nvyr/config_scripts/system_login.py): manages local accounts
  under `system login`, verifies required credentials/roles and protects the last
  administrator. Gathers current/previous accounts and developer-access policy
  once, then prepares both application and compensation targets. Disabled
  developer accounts remain in configuration but are excluded from both Linux
  account targets. The account backend retains live identity checks, UID
  reservations, password installation, session revocation and recovery.
- [login.py](../../src/nvyr/login.py): `/usr/bin/nvyr-login` Linux login-shell entry point;
  selects the host CLI for interactive dev-admin logins or an isolated role-specific
  CLI container for other roles. Dev-admin SSH commands execute through host Bash.
- [service_ssh.py](../../src/nvyr/config_scripts/service_ssh.py): manages `service ssh`,
  validates local listen addresses and renders desired/previous SSH configurations
  for application or compensation. `get_config()` gathers both service sections
  and their logging levels; generation uses the OpenSSH Jinja template, and the
  runtime manager owns host keys, listener readiness and rollback.
  `set service ssh` listens on all addresses;
  repeat `set service ssh listen-address ADDRESS` to select several addresses.
- [service_dhcp.py](../../src/nvyr/config_scripts/service_dhcp.py): manages Kea
  servers in the default and named VRFs, including listeners, shared networks,
  pools, reservations and inherited options. Both DHCP service owners use this
  module independently. `get_config()` gathers the selected family's registered
  instances, logging level and conditional live interface inventory. Verification
  owns configuration relationships; generation builds and serializes native JSON
  directly, using focused value formatters. The Kea runtime manager owns service
  application, readiness, lease preservation and compensation.
  See [DHCP servers](dhcp-server.md).
- [system_ntp.py](../../src/nvyr/config_scripts/system_ntp.py): manages the single
  Chrony instance, upstream sources, client access and optional VRF selection.
  Gathers current/previous settings and configured VRFs, verifies listener
  ownership, and renders Chrony directives directly through Jinja. The runtime
  manager handles native parsing, service readiness and compensation.
  See [NTP](ntp.md).
- [container.py](../../src/nvyr/config_scripts/container.py): reconciles managed
  Podman containers, Netavark networks and generated service units, with persistent
  relative mounts beneath `/config/containers/` and explicit absolute host mounts.
  See [containers](containers.md).

## Shared helpers

These are imported from `nvyr.helpers`; none is a standalone command.

- [accounts.py](../../src/nvyr/helpers/accounts.py): provisions Linux users, passwords,
  groups and shells, reserves UIDs, revokes sessions and compensates failures.
  Seeds a fresh system once and preserves committed accounts across boot/upgrade.
- [dependencies.py](../../src/nvyr/helpers/dependencies.py): derives schema-declared
  object/reference registrations, checks candidate removals, and generates saved
  `_nvyr.dependencies` metadata. It does not enforce object existence or schedule commits.
- [access.py](../../src/nvyr/helpers/access.py): current-peer authorization for configd
  and engine mutation boundaries; hides credentials from net-admin and read-only output.
- [passwords.py](../../src/nvyr/helpers/passwords.py): hashes plaintext with libcrypt
  before candidate storage and suppresses credential commands in history/errors.

- [interface_names.py](../../src/nvyr/helpers/interface_names.py): physical-port identities,
  durable `ethN` allocations, staged Netlink renaming and handoff validation. Imported
  by the naming service; interface application uses its readiness check.
- [validators.py](../../src/nvyr/helpers/validators.py): named validation predicates
  and argument preparation, including regex, list, address, network, range and length
  checks. Add reusable predicates with `register()` and reference them in schema
  `validators` mappings; the builder lowers them into runtime `validators.checks`.
- [suggestors.py](../../src/nvyr/helpers/suggestors.py): suggestion registry, contextual
  commit-history discovery and interface discovery with optional prefix filtering.
  Register a callback and reference it from a schema; suggestions do not validate values.
- [nftables_formatters.py](../../src/nvyr/helpers/nftables_formatters.py): stateless
  firewall/NAT rule, map and match-group formatters and their shared field keymap.
  Registered with Jinja by `template.py`.
- [template.py](../../src/nvyr/helpers/template.py): common strict Jinja environment,
  callable registration, rendering, FRR static-route formatting and atomic file
  writing. Use `render(template_name, variables)` during generation, `register()` to
  expose template functions and `write()` during application where needed.
- [system.py](../../src/nvyr/helpers/system.py): host system settings. `apply_hostname()`
  changes the kernel hostname and atomically writes its boot file and local hosts
  mapping, restoring prior host state if application fails.
- [process.py](../../src/nvyr/helpers/process.py): timed subprocess execution through
  the shared `cli_cmd()` implementation. `cmd(argv)` quietly returns command output,
  `run(argv)` returns the exit code, `call(argv)` streams terminal output and
  returns the exit code, and `rc_cmd(argv)` returns
  `(rc, output)`. `cmd()` raises `CommandError` on nonzero exits; the other helpers return
  status for callers to handle. Captured output is not printed or logged. `stream=True` inherits the terminal.
  `interactive_shell()` retains its dev-admin-only shell behavior.
  `operational_argv()` binds original-input placeholders to executable argument
  lists before captured `cmd()` execution or daemon-owned streaming execution.
- [helpers/terminal.py](../../src/nvyr/helpers/terminal.py): privileged operational PTY
  execution and client terminal relay over the authenticated configd socket. Handles
  input, output, resize, interrupts, exit status and timeout/disconnect cleanup.
  Its module entry point acquires the controlling terminal before executing the
  schema-resolved command; it has no setuid permissions or independent elevation.
- [helpers/pager.py](../../src/nvyr/helpers/pager.py): displays completed CLI output
  through secure-mode less, with search, resizing and clean quit handling. Runs
  locally as the invoking user; streaming commands bypass it.
- [build_metadata.py](../../src/nvyr/helpers/build_metadata.py): reads and validates
  `/usr/share/nvyr/build.json` for commands, with an explicit unavailable-date fallback
  outside an ISO. Formats the headerless `show version` table with builder,
  copyright and repository attribution, and reads the packaged `show license` text.
- [interfaces.py](../../src/nvyr/helpers/interfaces.py): device existence/local-address
  lookup, shared `Link`/`Plan` models, and the `NetlinkManager` socket client.
- [netlink.py](../../src/nvyr/helpers/netlink.py): direct kernel operations and extensible
  interface driver registry. `NetlinkKey`/`LINK_KEYMAP` drive generic attribute
  observation, batched writes and baseline restoration.
- [link_manager.py](../../src/nvyr/helpers/link_manager.py): desired-state reconciliation,
  interface ownership and compensating rollback.
- [dns.py](../../src/nvyr/helpers/dns.py): aggregates static and selected lease DNS, journals
  source updates and atomically publishes the system resolver file from netlinkd.
- [dhcp.py](../../src/nvyr/helpers/dhcp.py): udhcpc client launch, lease event hook and
  lease normalization for the reconciler.
- [netlink_daemon.py](../../src/nvyr/netlink_daemon.py): root-only IPC server and kernel
  notification loop; invoked by `nvyr-netlinkd.service`. `system logging service
  netlinkd level debug` enables detailed reconciliation and kernel-operation
  logging; routine work is quiet by default.
- [frr_reload.py](../../src/nvyr/helpers/frr_reload.py): shared native configuration reload,
  scope adapters, readback verification and recovery for static routing, policies and BGP.
- [frr_static.py](../../src/nvyr/helpers/frr_static.py): native static-route formatting and
  ownership within integrated FRR configuration.
- [frr_policy.py](../../src/nvyr/helpers/frr_policy.py): named-policy ownership within
  integrated FRR configuration; policy command formatting lives in `policy_formatters.py`.
- [frr_bgp.py](../../src/nvyr/helpers/frr_bgp.py): BGP instance ownership and native
  configuration integration; [bgp_formatters.py](../../src/nvyr/helpers/bgp_formatters.py)
  supplies the registered template formatting functions.
- [geoip.py](../../src/nvyr/helpers/geoip.py): validates and caches DB-IP generations
  and atomically updates managed country groups through configd. See [GeoIP](../users/firewall-geoip.md).
- [nftables.py](../../src/nvyr/helpers/nftables.py): checks generated nftables text,
  applies a single batch and records the last successful configuration per owner.
  Used by firewall and NAT, including shared transport-port checks; startup's global
  ruleset reset is separate.
- [ssh.py](../../src/nvyr/helpers/ssh.py): creates the persistent host key, validates
  generated SSH configuration, manages an instance service and verifies actual
  listening sockets. Applies removal and compensates failed changes.

## Build, image and installation scripts

- [build_tools/build_metadata.py](../../build_tools/build_metadata.py): resolves and
  validates build versions, fills the staged Debian control version and records
  ISO identity as JSON, including UTC build time, builder attribution and Git state.
  `--project` optionally selects a different `pyproject.toml`.
- [build_tools/image_build.py](../../build_tools/image_build.py): parses ISO build
  options, streams assembly output into a unique log, preserves failure status
  and writes the finished ISO's checksum and companion metadata.
- [build_tools/schema_builder.py](../../build_tools/schema_builder.py): expands source
  named YAML fragments and include lists into runtime JSON, applies per-file
  modifications, adds default values to generated descriptions, and checks
  operational script/function/argument mappings without executing scripts.
  Run `python -m build_tools.schema_builder` after schema edits, or
  append `--check` to detect stale output without writing. `--source DIR` and
  `--output DIR` override the default `schemas/` and `src/nvyr/schemas/` directories.
- [setup.py](../../setup.py): setuptools hooks that generate schemas for wheels,
  editable installs and source distributions. Invoked by `python -m build` or
  `python -m pip install -e .`; normally not run directly.
- [scripts/build-deb.sh](../../scripts/build-deb.sh): stages Python code, generated
  schemas, templates, service units and router baseline files into the Debian package.
  Run `sh scripts/build-deb.sh` on Linux with Python 3.11+ and Debian packaging tools;
  output is `dist/nvyr-router_<version>_all.deb`. Supports `--version`,
  `--output-dir` and `--debug`; the default version comes from `pyproject.toml`.
- [scripts/test-wsl.ps1](../../scripts/test-wsl.ps1): resolves the Windows checkout to
  its WSL path and runs pytest in Ubuntu using the existing
  `~/.local/share/nvyr-router/venv`. Run `./scripts/test-wsl.ps1` in PowerShell; it
  does not create the virtual environment.
- [images/build.sh](../../images/build.sh): the builder-container entrypoint, dispatching
  to the Python build runner. See [image build commands](debian.md).
- [images/assemble.sh](../../images/assemble.sh): internal root-only live-build stage.
  Builds the versioned Debian package, downloads pinned dependencies, installs image
  hooks and produces `nvyr-<version>-amd64.iso` and package provenance files in the
  selected output directory. Installs the runner's metadata before invoking live-build.
- [images/fetch-packages.sh](../../images/fetch-packages.sh): downloads dependencies
  from `images/packages.lock`, checking hashes and package metadata. Run
  `sh images/fetch-packages.sh DESTINATION`; the image builder also calls it.
- [build_tools/container_packages.py](../../build_tools/container_packages.py): builds
  the pinned Podman stack for Trixie/amd64, or verifies and stages the builder's
  cached packages with `--cache /opt/nvyr-container-packages DESTINATION`.
- [images/0100-router.hook.chroot](../../images/0100-router.hook.chroot): live-build
  chroot hook that checks dependencies, enables router services/FRR daemons, masks
  stock SSH listeners and removes build-time SSH keys. Invoked by live-build, not
  manually on the development host.
- [packaging/debian/postinst](../../packaging/debian/postinst): dpkg installation hook
  that creates role/access groups and runtime directories, registers the login shell,
  and reloads systemd units.
  Regenerates GRUB when an installed GRUB configuration already exists.
  It does not explicitly start configd; Debian's separate sysctl triggers may apply
  the installed baseline. See [initialization](initialization.md).
- [packaging/debian/prerm](../../packaging/debian/prerm): dpkg removal hook that stops
  configd and nVyR SSH instances before package removal.

Package markers [src/nvyr/__init__.py](../../src/nvyr/__init__.py),
[helpers/__init__.py](../../src/nvyr/helpers/__init__.py),
[config_scripts/__init__.py](../../src/nvyr/config_scripts/__init__.py) and
[build_tools/__init__.py](../../build_tools/__init__.py) identify the Python packages;
they have no command interface or startup work.

## Supporting definitions and templates

These are consumed by the scripts above rather than executed as Python or shell scripts.

- `schemas/{configuration,control,operational,pipelines}.yaml` define configuration
  paths, configuration-mode commands, operational commands and output modifiers.
  `schemas/includes/` holds reusable fragments; generated runtime copies live in
  `src/nvyr/schemas/`. Edit the sources, then run the builder.
- `src/nvyr/templates/firewall/filter.nft.j2` renders firewall chains;
  `nat/ipv4.nft.j2` renders NAT chains in the same table;
  `frr/static.conf.j2` renders native static-routing commands; `ssh/sshd_config.j2` renders
  SSH settings. Interface operations use direct Netlink rather than text templates.
- `packaging/nvyr-configd.service` starts configd after baseline initialization;
  `nvyr-ssh@.service` runs managed SSH instances; `nvyr-network.conf` supplies tmpfiles
  directories. `nvyr-netlinkd.service` runs the interface reconciler and
  `nvyr-dhcp4@.service` runs independent DHCPv4 protocol clients.
- `packaging/nvyr-resolver-init.service` installs the resolver symlink and runtime
  directory before netlinkd, the sole writer of its contents.
- `packaging/nvyr-interface-naming.service` runs the physical-port naming coordinator;
  netlinkd and configd depend on successful naming;
  `70-nvyr-ethernet.rules` stages hotplugged ports and marks device ownership;
  `10-nvyr-ethernet.link` suppresses competing systemd naming policies.
- `packaging/router.nft` resets nftables at startup;
  `20-nvyr-nftables.conf` selects that file for nftables.service;
  `50-nvyr-router.conf` supplies persistent router sysctls.
- `images/bootloaders/` overlays Debian live-build boot menus for serial and VGA;
  `packaging/20-nvyr-console.cfg` supplies installed GRUB defaults and
  `20-nvyr-serial.conf` fixes serial getty to 115200 8N1. See [serial consoles](serial-console.md).
- `images/Dockerfile` defines the ISO builder; `router.list.chroot` selects image
  packages; `packages.lock` pins external dependencies. `packaging/debian/control`
  declares Debian metadata/dependencies. `pyproject.toml` defines Python dependencies
  and entry points; `MANIFEST.in` selects source-distribution files.
- `.github/workflows/test.yml` runs framework tests, schema checks and package builds
  in CI on Python 3.13, matching the router image.

## Test scripts

Run ordinary tests with `python -m pytest -q`; select one file with
`python -m pytest -q tests/test_controller.py`.

After installing `.[test]`, run the isolated framework suite with two workers
and timing output using the same options as CI:

```sh
python -m pytest -q -n 2 --dist loadfile --durations=30
```

The framework suite runs on Linux and uses `iproute2` for read-only interface
observations and `less` for terminal tests. Install these when using a minimal
test container.

CI preserves a JUnit report for each Python version and cancels superseded runs
on the same branch or pull request. Parallel execution is for isolated framework
tests only; live router smoketests share configuration and must run serially.
Framework tests must not require root or contact real service managers. Tests
that exercise privileged storage can model ownership metadata while retaining
real temporary-file operations and separate rejection checks.

The following files each focus on:

- `test_controller.py`: dispatch, completion, imports and output modifiers.
- `test_engine.py`: candidates, locks, partial commits, rollback and recovery.
- `test_tree_schema.py`: tree mutations, path validation, defaults and serialization.
- `test_anchors.py`: anchored grammar, boundaries, relative paths and completion.
- `test_callback_arguments.py`: validator/suggestor arguments and schema checks.
- `test_tag_discovery.py`: completion beneath invalid tag values and interface hints.
- `test_value_hints.py`: informational hints, allowed values and interface attributes.
- `test_empty_paths.py`: preserving empty objects through mutation and persistence.
- `test_structural_diff_and_choices.py`: structural diffs, choices and completion order.
- `test_refinements.py`: candidate display, history, notifications and process helpers.
- `test_regressions.py`: earlier failures in projections, diffs, completion and recovery.
- `test_integration.py`: actual Unix RPC and terminal-client behavior with isolated backends.
- `test_schema_builder.py`: includes, modifications, defaults and reproducible generation.
- `test_build_metadata.py`: UTC build stamping, shared-reader errors and fallback,
  version output in both CLI modes, and ISO staging before live-build.
- `test_serial_console.py`: installed GRUB defaults, real agetty login prompt/line
  settings and interactive CLI completion, history, modes and terminal restoration.
- `test_dns.py`: resolver aggregation, lease changes, restart/recovery, transactional
  failure handling, automatic event-loop updates and configuration lifecycle.
- `test_netlink.py`: mapped attributes, protocol integrity, ownership, reconciliation
  and compensation with isolated kernel/DHCP boundaries.
- `test_templates.py`: helper registration, strict rendering and atomic file writes.
- `test_firewall_validation.py`: firewall verification errors and repair workflows.
- `test_firewall_workflows.py`: firewall lifecycle, scoped output, history and shell workflows.
- `test_nftables.py`: nftables rendering, validation, transaction and persistence behavior.
- `test_nat.py`: NAT schema, rendering, lifecycle verification, completion and artifacts.
- `test_ethernet.py`: Ethernet validation, profiles and backend compensation.
- `test_interface_names.py`: physical naming identities, persistent reservations,
  replacement, collision handling and udev handoff records.
- `test_dummy.py`: dummy-device lifecycle, ownership and profile reconciliation.
- `test_static.py`: static-route validation, templates and VRF-aware plans.
- `test_frr_reload.py`: FRR reload, ownership, readback and recovery.
- `test_policy.py` / `test_policy_live.py`: policy rendering, validation, ownership,
  native reload and failure recovery.
- `test_ssh.py`: SSH schema, templates, host keys, listeners and compensation.
- `conftest.py`: shared fixtures and backend isolation; pytest loads it automatically.

Live tests are opt-in (`NVYR_NETWORK_TEST=1`) and require the disposable privileged
Linux container, not the development host. They affect real services/network state;
some also create nested network namespaces. In that environment, run
`NVYR_NETWORK_TEST=1 python3 -m pytest -q tests/test_initialization_live.py`, for example.

- `test_initialization_live.py`: baseline sysctls/nftables, forwarding and startup dependencies.
- `test_netlink_live.py`: real Ethernet/DHCP and dummy-interface lifecycle; uses
  `NVYR_NETLINK_TEST=1` and does not require systemd as container PID1.
- `test_interface_names_live.py`: real Netlink rename swaps, replacement, conflicts
  and startup blocking when naming fails.
- `test_frr_live.py`: native FRR static reloads, VRFs, policy preservation and recovery.
- `test_nftables_live.py`: actual rule loading, packet filtering, counters and rollback.
- `test_nat_live.py`: actual NAT translation, pools, exclusions, IPv6 bypass and recovery.
- `test_ssh_live.py`: real listening sockets, key authentication, recovery and removal.

`test_console_boot_live.py` is separately enabled with `NVYR_CONSOLE_BOOT_TEST=1`.
It boots tiny BIOS/UEFI ISOs in QEMU to verify serial boot-menu interaction and VGA
output/keyboard input; it does not boot the complete router OS.

When adding or renaming a maintained script, update this guide with its purpose and
whether it is invoked directly, imported, or called by another tool.
