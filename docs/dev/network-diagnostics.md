# Network diagnostics: implementation and maintenance

For configuration and command usage, see the [user guide](../users/network-diagnostics.md).

## Ping command mapping

The schema maps the anchor to `command: ['ping.nvyr.op', 'ping', '@line']`
with `stream: true`. The script passes the line and its `OPTIONS` map to
`opmode.command_arguments()`, then places the destination after `--`. The helper
handles the configuration-mode `run` prefix. Output modifiers belong to the CLI.
No shell is involved.

## Ping packaging and testing

Packaging automatically installs `ping.nvyr.op` alongside the other operational
scripts and depends on `iputils-ping`, which is also in the base image.
`tests/test_ping.py` covers option mappings, parsing, completion, installed dispatch,
live PTY output, interrupts, timeout cleanup and IPv4/IPv6 loopback probes.
