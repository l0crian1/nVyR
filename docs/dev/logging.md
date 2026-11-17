# Local logging: implementation and maintenance

For configuration and command usage, see the [user guide](../users/logging.md).

## Implementation

Rsyslog routes service messages into section-specific files as they arrive.
Kea includes a family/VRF marker, Python daemons retain their native severity,
and FRR uses its syslog target through the shared reload manager. The journal
forwards service output and is limited to 32 MiB of volatile storage.

Each NFLOG group has a dedicated ulogd subscription. Firewall application waits
for the kernel to report the subscription before installing consuming rules.
Removed collectors are stopped after successful firewall replacement, and
identifier allocations are retained to prevent reuse.

The rotation timer uses logrotate and supported writer reopen mechanisms:
rsyslog/ulogd receive HUP, and Conmon receives its log-reopen control event.
Rotation never uses `copytruncate` or restarts a workload.

## Connection events

The firewall lifecycle verifies event selection, renders
`logging/conntrack.conf.j2`, and applies `nvyr-conntrack-log.service` after the
kernel settings and nftables transaction. ulogd subscribes directly to NFCT;
there is no nVyR connection collector daemon or userspace connection cache.
`hash_enable=0` delivers NEW/DESTROY immediately, and `event_mask` subscribes only
to the configured events. Protocol selection uses `accept_proto_filter`.

The runtime checks `/proc/net/netlink` for the collector PID and requested
multicast subscriptions before returning success. An unchanged configuration
does not restart the collector. Deletion stops it and removes its runtime
configuration, retaining log files. Apply failures enter the existing firewall
recovery boundary; replay installs the prior selection.

PRINTFLOW and LOGEMU provide readable records and HUP-based file reopening.
The pinned Debian ulogd build changes only the two reversed ICMP type/code pairs
in PRINTFLOW. Source, Debian packaging and patch hashes are checked before use;
the build retains Debian's options and native package layout. See
`vendor/ulogd/icmp-printflow.patch` and `images/ulogd-sources.lock`.

Address filtering and UPDATE delivery remain deferred. See the upstream issue
records before exposing either. Tests cover event masks and schema rejection in
smoketests; real IPv4/IPv6 TCP/UDP events, accounting, filters and rotation share
the routed functional scenario. Acceptance exercises fresh records before and
after reboot.

The shared flowtable tests verify `[OFFLOAD]` on actual IPv4/IPv6 connections
before requiring their NEW/DESTROY log records and accounting totals. This does
not provide historical offload identification. In the shipped Linux 6.18.64,
`nft_flow_offload_eval()` sets `IPS_OFFLOAD_BIT` without emitting a conntrack
event, and `flow_offload_teardown()` clears it. Hardware offload has a separate
status bit with the same lifetime limitation. NFCT/PRINTFLOW does not expose
those flags as output fields. Adding a flag to DESTROY formatting alone would
therefore misrepresent previously offloaded connections; offload enrollment
logging would need a separate design.
