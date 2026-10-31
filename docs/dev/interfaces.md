# Interface configuration and Netlink management: implementation and maintenance

For configuration and command usage, see the [user guide](../users/interfaces.md).

## Interface manager overview

Ethernet, dummy, loopback, virtual Ethernet, bridge and VRF configuration scripts use `helpers.interfaces.NetlinkManager`
to send complete desired link mappings to `nvyr-netlinkd`. The daemon uses
`pyroute2.IPRoute` for direct rtnetlink operations, listens for kernel link/address/
route notifications, and reconciles affected interfaces from fresh kernel snapshots. There are
no generated networkd profiles or networkctl calls. The ISO masks networkd.

## Responsibility and extension boundaries

- `configd` remains authoritative for configuration, save, commits and confirmed
  rollback. Configuration scripts perform feature validation and prepare desired
  state. Their get_config/verify/generate/apply lifecycle is unchanged.
- `helpers/interfaces.py` provides discovery, the Link settings
  model, and a reusable socket client. New scripts can use `manager.replace(owner,
  definitions, recovery=...)` directly without extending the Link dataclass.
- `helpers/netlink.py` owns kernel access and the interface driver registry.
  Register a driver with `register_type(name, driver)` during daemon startup. A
  driver declares a keymap for attribute reads/writes and supplies device-specific
  lifecycle hooks where needed. The common code snapshots original attributes,
  batches changed attributes by Netlink operation, and restores removed settings;
  dependencies specify creation order and reverse removal order. New bridge, VXLAN
  or tunnel attributes belong here, not in new RPC methods or configd branches.
  Ethernet, dummy, loopback, virtual Ethernet, VLAN, bridge and VRF drivers are
  implemented today.
- `helpers/link_manager.py` owns claims, reconciliation, the actuation journal and
  compensation. It handles common addresses, administrative state and DHCP leases.
- `netlink_daemon.py` owns serialization, authenticated IPC, kernel notifications
  and retry scheduling. Notifications select affected links; a slower full audit
  catches missed changes and settings without Netlink notifications.
- `helpers/dhcp.py` adapts udhcpc lease events and independent client services.

The version-1 IPC uses the project's bounded length-prefixed JSON framing. The
socket is `/run/nvyr-netlink/control.sock`, mode 0600, with root-only SO_PEERCRED
verification. Interface requests support `validate`, `replace`, and `status`;
`replace-dns` supplies sources for [system DNS management](dns.md). Example:

```python
from nvyr.helpers.interfaces import manager

manager.replace("ethernet", {
    "eth0": {
        "kind": "ethernet",
        "attributes": {"mtu": 1500, "description": "WAN"},
        "addresses": ["192.0.2.1/24"],
        "dhcp4": False,
        "disabled": False,
    }
})
```

Replace supplies the complete mapping for one owner; other owners are retained.
The attribute dictionary is interpreted by its registered driver, so adding driver
attributes does not change the wire protocol. Ownership prevents two scripts from
claiming a name. Driver dependencies support ordering within a mapping; dependencies
in other owners must already exist. Cross-owner commit ordering is still configd's
responsibility.

## Attribute keymaps

`LINK_KEYMAP` maps nVyR attributes to pyroute2 write arguments and kernel observation
paths. For example, `description` maps to `ifalias` on write and `IFLA_IFALIAS` on
read; a missing kernel alias is the empty string. MAC is marked `requires_down`
because some devices require a down transition before a MAC change. Unchanged
attributes do not cause writes or link flaps.

A driver can add attributes without writing a setter, getter or validator for each:

```python
from nvyr.helpers.netlink import LINK_KEYMAP, LinkType, NetlinkKey


class Bridge(LinkType):  # Illustration; bridge configuration is not implemented.
    virtual = True
    kernel_kind = "bridge"
    keymap = LINK_KEYMAP | {
        "ageing-time": NetlinkKey(
            "br_ageing_time", ("IFLA_LINKINFO", "IFLA_INFO_DATA", "IFLA_BR_AGEING_TIME")
        ),
    }
```

Values at this boundary use the units/representation required by the kernel API.
`operation` defaults to `link`; a mapping can select another pyroute2 operation
when needed. Read paths can traverse nested Netlink attributes. The same map drives
observation, baseline capture, comparison, grouped writes and restoration; extending
it requires no new RPC method. Values captured in the baseline must be JSON-safe.

Keymaps contain transport metadata only. Individual value constraints (ranges,
patterns and descriptions) belong in the existing CLI schema and validators. The
IPC boundary still checks message shape, supported types/attributes, safe interface
names and collection types. Ownership, device existence/type, dependency ordering,
DAD and kernel errors remain runtime checks. Address parsing for kernel encoding and
DHCP lease validation are still necessary. Address-set reconciliation, DHCP and
creation/deletion retain specialized handling because they are lifecycle operations,
not scalar attribute assignments.

## VLAN driver extension

The shared `interfaces/vif.yaml.i` fragment can be included by future bond or tunnel
schemas. Config scripts add `vlan_definitions()` to their ordinary owner mapping;
the generic `vlan` Netlink driver declares its parent dependency. No new owner or
parent-type-specific VLAN daemon code is required. Parents and children participate
in one journaled transaction, with parent-first creation and child-first deletion.
Paired parents are ordered as a lifecycle unit so all children are removed before
either endpoint. Recovery restores lost parents before children; ordinary edits
preserve interface indices. QinQ and nested VIFs are not part of this interface.

## IP option application

Netlinkd owns these writes, including firewall global settings. It publishes
runtime sysctl profiles before creating links so udev cannot overwrite explicit
policy with boot defaults, applies address-generation controls before addresses,
and restores previous policy when an interface transaction fails. Configuration
scripts validate options and send desired state through the existing daemon API.
Native behavior follows the [Linux IP sysctl documentation](https://docs.kernel.org/6.18/networking/ip-sysctl.html).

Live feature tests: `python3 /usr/lib/nvyr/smoketests/test_interface_ip.py`.

## DHCPv4

The image installs BusyBox `udhcpc`. It handles discovery, renewal, rebinding and
release. Its configured script only records normalized events; it does not execute
the distribution default script or write kernel networking state. ISC dhclient was
not selected because its client maintenance ended in 2022:
https://www.isc.org/blogs/dhcp-client-relay-eom/

Each enabled link has an independent `nvyr-dhcp4@<name>.service`, which survives
netlinkd/configd restarts. Generation tokens, MAC address and ifindex fence client
replacement and stale lease events. Disabling/removing DHCP stops the client and
releases its lease. A MAC change restarts negotiation. DHCP does not require a lease
before a commit can succeed.

Lease files under `/run/nvyr-netlink/leases` provide address, monotonic expiration,
routers/classless routes and DNS information. RFC 3442 classless routes take precedence
over the router option. Only the first router is used when no classless option is
present. Leases expire even if a deconfig event was missed. Address lifetimes are set
in the kernel using `IFA_CACHEINFO` (pyroute2's `cacheinfo` argument); the reconciler
removes expired lease routes. Top-level `valid_lft`/`preferred_lft` arguments are
not used: pyroute2 ignores them, which would leave a permanent address and cause
repeated repair notifications. A potentially aged bulk snapshot is rechecked by
ifindex before deciding that a DHCP lifetime has drifted. Service restart normally
bounds a daemon outage; a prolonged daemon failure prevents applying renewed leases
or cleaning routes until recovery. NTP and hostname offers do not override
router configuration; MTU offers require `dhcp-options mtu`. Selected lease DNS is consumed by
[system DNS management](dns.md); other offers do not change resolver policy.

## DHCP administrative-distance encoding

The default-route distance is a direct default of **210**, configurable from 1 to
254. netlinkd encodes it in the upper byte of the Linux route metric, where FRR
reads it as administrative distance; the lower 24 bits retain the interface's
tie-breaking metric. Thus ordinary static routes (AD 1) win over DHCP defaults.
This applies to defaults from either DHCP's router or classless-route option.
`no-default-route` suppresses both forms but retains nondefault advertised routes.
Nondefault DHCP routes retain their existing metric policy.

## Failure and persistence behavior

Linux interface changes are **not atomic** across a batch. A failed application is
compensated with the previous desired mapping. A failed compensation or an ambiguous
socket disconnect raises RecoveryError, preserving configd's journal and blocking
new commits until recovery. No success is acknowledged before the daemon's actuation
record is durable. Restart recovery is idempotent.

`/var/lib/nvyr-netlink/state.json` contains same-boot desired intent, original
attributes, claims/ifindices, DHCP route ownership and incomplete operations. It is
an actuation cache, not an alternative user configuration database. A new boot drops
this cache before configd supplies saved configuration, so unsaved running changes
cannot silently reappear. Same-boot restarts retain it. Incomplete owners wait for
configd's authoritative recovery target. Do not delete this journal on a live router.

`records.jsonl` beside the checkpoint holds small, fsynced record updates during
application and background repairs. Creating a link no longer serializes the entire
growing configuration. Transaction boundaries publish a full checkpoint and reset
the log. Checkpoint IDs prevent replaying a stale log after an interrupted reset;
an incomplete trailing append is discarded at startup. Both files must be preserved
together. A safety audit compacts logs larger than 1 MiB. Only format-2 checkpoints
with a checkpoint ID are accepted. This internal actuation persistence is separate
from configd's user configuration and the version-1 RPC protocol.

A virtual link found under an owned name with a different ifindex is not adopted or
deleted. A crash between creating a virtual device and durably recording its ifindex
can consequently require operator cleanup of that unclaimed device before recovery.
This fails closed instead of risking deletion of somebody else's link.

Only claimed links have their addresses reconciled. Kernel IPv6 link-local addresses
are preserved on enabled links. DHCP routes have an explicit ledger and protocol 16;
other routes, nexthops and rules (including FRR's) are untouched. Route insertion uses
add rather than replace, so a conflicting foreign route fails rather than being
silently overwritten. Normal kernel withdrawals on device deletion/down still apply.

## Reconciliation scheduling and scale

Configuration requests still apply synchronously and acknowledge only after durable
publication. Kernel notifications are coalesced for 200 ms without postponing work
indefinitely during a burst. Link names/ifindices select the affected configured
interfaces and their dependents. Link statistics and unchanged managed attributes,
unmanaged interfaces, and non-DHCP route updates do not schedule reconciliation.
The attribute comparison uses each driver's existing keymap. Address notifications
still select their interface, including IPv6 DAD changes. Echoes of writes may
cause one extra read-only pass; unchanged state does not generate further writes.

There is no two-second full-interface watchdog. A full audit runs at startup and
every 60 seconds; it also repairs non-notifying changes such as IPv6 sysctls. Lost
or truncated notifications request an earlier audit. This follows the resync
requirement in [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).
Failed interfaces retry every five seconds without blocking healthy siblings.
Interrupted inventory dumps retry up to three times; a sustained failure schedules
another audit after five seconds rather than terminating or spinning the daemon.

Only enabled DHCP interfaces receive the two-second lease maintenance pass, preserving
renewal, expiration and DNS publication without scanning static interfaces. Systemd
restarts failed DHCP clients; the daemon also checks their service startup at most
once every 30 seconds to recover an externally stopped client. Removing/changing
an interface publishes resolver changes immediately through the existing single writer.

Each full pass reads links and addresses in bulk. Small targeted passes query links
by name and request addresses by ifindex, with Linux filtering the dump before
sending it to Python. This applies to IPv4 and IPv6, fresh reads after mutations,
and verification. DHCP polling therefore does not decode addresses belonging to
unrelated interfaces. Targeted route dumps likewise send an output-interface filter;
routes are loaded only when an interface has DHCP route work. The socket enables
strict dump checking, and requests explicitly separate kernel filters from
[pyroute2's userspace filters](https://docs.pyroute2.org/iproute_linux.html#pyroute2.iproute.linux.RTNL_API.get_addr).
Large passes (more than 64 interfaces) retain bulk inventories. Mutations refresh affected link observations, and
address changes are verified together after application. IPv6 DAD begins on all
configured interfaces before waiting, with bulk address reads while waiting. Primary
IPv4 deletion still restores desired secondaries. Virtual deletion relies on the
kernel to remove that device's addresses/routes, avoiding redundant individual deletes.

Independent dummy deletions use at most eight workers, each with its own Netlink
socket. Linux netdevice teardown includes synchronous RCU waits; overlapping those
waits avoids paying the full delay serially for every interface. Workers recheck
the expected name, ifindex and type, and receive an individual acknowledgement for
each deletion. They never write the manager's cache or journal. All workers finish
and affected observations are refreshed before compensation or a response, including
when a deletion fails. The existing durable pending transaction remains authoritative
until the whole batch succeeds; interrupted batches still recover through configd.

Drivers can implement `remove_many(kernel, names)` for independent links; the base
implementation calls `remove()` serially. A driver inheriting an optimized bulk hook
must also override it if its teardown semantics change. Physical releases remain
serial. Dependency-linked devices retain reverse dependency ordering, and types
without a bulk optimization retain their serial teardown behavior.

On the development host (Debian kernel 6.12.111, pyroute2 0.7.7), profiling 250 dummy
deletions attributed 9.80 of 10.15 seconds to Netlink socket sends, with only one
full link dump. The first and last groups of 50 deletes cost about the same; this
sample did not reproduce progressively faster deletion as the inventory shrank.
An unprofiled comparison through the daemon RPC path measured 10.07 seconds before
and 1.95 seconds after this change. A subsequent optimized 4,094-interface run took
13.52 seconds to create and 32.48 seconds to delete. These runs used temporary
dummy-only owners, private journals and a private daemon socket in the host's normal
network namespace. Management Ethernet/DHCP and installed services were untouched;
all test interfaces were removed. These timings are host-dependent, not guarantees.

## Startup, deployment and diagnostics

The startup sequence is sysctl initialization and persistent naming, then
`nvyr-netlinkd.service`, then `nvyr-configd.service`. Named physical devices are
rechecked before application, including hotplug. `ID_NET_MANAGED_BY=io.nvyr.Netlink`
keeps networkd from claiming released devices even if independently started.
The daemon also conflicts with networkd. Do not run other managers on claimed links.

```sh
systemctl status nvyr-netlinkd
journalctl -u nvyr-netlinkd -b

systemctl status 'nvyr-dhcp4@eth0'
journalctl -u 'nvyr-dhcp4@eth0' -b

sudo python3 -c 'from nvyr.helpers.interfaces import manager; print(manager.request("status"))'
```

Routine reconciliation is silent at the default INFO level. Changed failures are
logged at ERROR, recovery from them at INFO, and failed apply/rollback outcomes
are reported without repeating an unchanged failure on every audit.

Enable detailed diagnostics through the shared logging configuration:

```text
set system logging service netlinkd level debug
commit

run show log netlinkd follow
```

No netlinkd restart is needed. DEBUG records interface creation/deletion/recreation,
changed attributes, addresses/routes, administrative state, relevant kernel events,
apply/recovery requests, and reconciliation duration/counts. Delete the service override
to return to quiet operation. Low-level pyroute2 message dumps remain suppressed.

## Validation

Ordinary tests use isolated fake kernel/DHCP boundaries and cover IPC, validation,
ownership, driver extensions, recovery, compensation, hotplug and lease fencing.
`tests/test_netlink_live.py` additionally runs direct kernel operations through a
real daemon and real udhcpc/dnsmasq exchange in a separate network namespace:

```sh
NVYR_NETLINK_TEST=1 PYTHONPATH=src python3 -m pytest -q tests/test_netlink_live.py
```

Run this only in a disposable privileged Docker container without host networking.
It also exercises the real configd lifecycle, commit-confirm rollback and configd
restart, and verifies the management interface is untouched. The DHCP test substitutes process
launch for systemd service launch, so it can run without systemd as PID1; production
lease parsing, hooks and kernel application are exercised. Physical NICs, booting an
ISO, and service lifecycle under systemd require deployment qualification.

The live suite also creates 1,000 dual-stack dummy interfaces through the production
RPC client and its 600-second default timeout, tests deletion recovery, and removes
the entire batch. For timing and idle CPU measurements on a Linux test machine:

```sh
sudo unshare --net env PYTHONPATH=src python3 tests/netlink_benchmark.py 1000 --addresses
```

The benchmark refuses namespaces containing interfaces other than `lo`, uses temporary
journals, and leaves the host namespace and running daemon untouched. It measures
creation, unchanged application, auditing, idle CPU, external drift/deletion/address
repair and removal. Omit `--addresses` to measure empty interfaces. Timings are
machine-dependent; this is an opt-in diagnostic, not a fixed-speed unit test.

That isolated benchmark does not exercise a real management DHCP interface. To
qualify idle CPU on a router, also measure with DHCP active and large numbers of
dummy interfaces in the host's existing namespace. Do not alter the management
interface, its DHCP client, or its lease files. Targeted dump regression coverage
asserts the kernel's `NLM_F_DUMP_FILTERED` response flag and excludes unrelated
interfaces, in addition to testing actual lease renewal, expiration and recovery.

On the development host, a 20-second comparison with 4,000 dual-stack dummy
interfaces measured about 0.5% of one core for updated netlinkd and 0% for updated
naming, versus about 92% and 100% for the installed versions. Targeted dummy drift
and deletion recovery took 0.15â€“0.25 seconds. This used temporary journals and
guarded comparison processes in the existing host namespace: management DHCP
state was read, but address writes, physical renames and DHCP service operations
on the management interface were suppressed/prohibited. The installed services
were not replaced. These figures validate query/event overhead, not a complete
in-place upgrade or physical hotplug qualification; actual DHCP lifetime writes
and renewal/expiration are covered by the disposable-container integration tests.

### Memory after large changes

Deleting configuration removes its ownership records, pending transaction, indexes,
and cached observations. Kernel snapshot caches are released at the end of each
pass. Rebuilding indexes prunes observations and failure messages for deleted
interfaces, while preserving other owners and DNS errors. Dependency sorting also
breaks its recursive closure on exit so it cannot retain a whole configuration
until cyclic garbage collection. Rollback and incomplete transaction records are
still retained whenever recovery requires them.

RSS alone does not measure live configuration data. pyroute2 0.7.7 creates cyclic
objects (including netlink messages and request processors); these can remain
unreachable until cyclic GC runs. Even after collection, Python's
[small-object allocator](https://docs.python.org/3.13/c-api/memory.html#the-pymalloc-allocator)
can retain fragmented arenas. The diagnostics below distinguish those cases from
references retained by nVyR. They do not change production GC or allocator policy.

On the 4 GB development VM, with Python 3.13.5 and pyroute2 0.7.7, untraced RSS
measurements on 2026-10-15 were (before creation / after creation / after deletion /
after restarting the temporary daemon), in MiB:

- 1,000 dummy interfaces: 40.0 / 84.8 / 88.0 / 39.7.
- 4,000 dummy interfaces: 39.6 / 183.2 / 190.9 / 39.9.
- 8,190 dummy interfaces: 39.7 / 332.7 / 336.1 / 39.6.

After the 8,190 deletion, records, pending transactions, observations, claim/index
maps and snapshot caches were empty; the checkpoint was 195 bytes and the record
log was empty. Full GC reclaimed about 1.90 million unreachable objects and lowered
RSS to 310.2 MiB. Allocator diagnostics then showed 254 MiB of reserved Python arenas,
only 15.5 MiB of allocated small-object blocks, and 215.6 MiB of unused pools.
An experimental libc trim lowered RSS further to 280.9 MiB, still far above the
restart baseline. This is primarily allocator fragmentation, not hundreds of MiB
of live deleted-interface configuration. The targeted reference fixes do not solve
that RSS retention: the original 1,000-interface run was already about 88.2 MiB
after deletion. Production does not force trimming, collection or daemon restarts.

Three additional 1,000-interface create/delete cycles under tracemalloc had
post-collection live allocations of 19.004, 19.010 and 19.011 MiB, compared with an
18.085 MiB startup baseline. No ongoing growth proportional to deleted interfaces
was observed in these cycles. Tracemalloc substantially increases RSS; its RSS
numbers must not be compared directly with the untraced measurements above.

Repeat the measurement with a private daemon process, RPC socket and journal:

```sh
sudo env PYTHONPATH=src python3 tests/netlink_memory_benchmark.py --host-dummies --count 1000
sudo env PYTHONPATH=src python3 tests/netlink_memory_benchmark.py --host-dummies --count 1000 --cycles 3 --trace --diagnostics
```

Start with 1,000 interfaces. Only use `--host-dummies` on a test host; otherwise the
tool requires a fresh namespace containing only `lo`. It rejects existing test
names, touches only its own dummy configuration, and restarts only its temporary
daemon. Run one benchmark at a time. Output includes RSS, GC/allocation diagnostics,
state/cache counts and journal sizes. Successful runs clean up their links and
temporary files; a failed run retains its printed journal directory for recovery.
Installed services are not restarted or reconfigured; management Ethernet, DHCP
and resolver configuration remain unchanged.

## Loopback tests

Live feature tests: `python3 /usr/lib/nvyr/smoketests/test_loopback.py`.

## DHCP option tests

`tests/test_dhcp_options_live.py` checks the actual server exchange, MTU handling,
and routing preference in a disposable privileged container. Set
`NVYR_NETLINK_TEST=1`; the FRR competition test additionally requires
`NVYR_RELOAD_TEST=1`, running FRR daemons, and root membership in `frrvty` for the
isolated peer's Zebra process. Configuration checks are in `smoketests/test_ethernet.py`;
lease behavior is in `functionaltests/interfaces/test_ethernet.py`. Lease-dependent checks require `--ethernet-dhcp` and an explicit spare port.
