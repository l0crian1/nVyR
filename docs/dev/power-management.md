# Power management: implementation and maintenance

For configuration and command usage, see the [user guide](../users/power-management.md).

## Shutdown command mapping

`shutdown.nvyr.op` uses `-r` or `-P` with the supplied time, `-c` for either cancel command, and
`--show` for both display commands. The operational schema validates the requested
time before the wrapper invokes shutdown.
