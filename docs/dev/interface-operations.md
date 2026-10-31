# Interface diagnostics: implementation and maintenance

For configuration and command usage, see the [user guide](../users/interface-operations.md).

## Hardware data collection

The ethtool 6.14.2 package supplies Netlink-backed JSON for link settings, features,
rings, pause, EEE, FEC and decoded module EEPROM data. The shared Python helper
reads Linux `SIOCETHTOOL` records for driver information, channel counts and
driver-defined statistics, whose ethtool subcommands do not offer JSON.

## Structured hardware output

The operational `hardware` function also accepts `--raw` for structured API use.
Its response is keyed by interface name; unsupported data is `null`. This is not
an additional CLI keyword.

References: [kernel ethtool Netlink API](https://docs.kernel.org/networking/ethtool-netlink.html),
[Linux ethtool UAPI](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/ethtool.h).
