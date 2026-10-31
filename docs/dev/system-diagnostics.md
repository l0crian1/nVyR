# System diagnostics: implementation and maintenance

For configuration and command usage, see the [user guide](../users/system-diagnostics.md).

## Testing

Live checks are included in `functionaltests/test_system_operations.py`. The archive
test removes its generated archive after checking the manifest and bounds.

## Diagnostic collection boundary

The collector runs in a temporary host service so configd's mount sandbox does
not distort storage or container observations. Collection allows 10 seconds and
1 MiB per report, with 60 seconds and 8 MiB of captured report output in total.
These byte limits exclude the small manifest and archive metadata. The service
also has a 75-second deadline covering collection and archive finalization.
