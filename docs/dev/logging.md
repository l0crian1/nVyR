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
