# Using the CLI: implementation and maintenance

For configuration and command usage, see the [user guide](../users/cli.md).

## Pager transport boundary

The CLI receives the complete response before opening the pager and removes its
private temporary output file afterwards. Quitting the pager never cancels a
command or leaves unread RPC data. Exported files, redirected/noninteractive
output, and Python API responses are never paged. Commit feedback remains live.
Streaming commands such as ping and traceroute remain live and reject pipe
modifiers, including `more` and `no-more`.
