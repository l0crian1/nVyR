# Container operations: implementation and maintenance

For configuration and command usage, see the [user guide](../users/container-operations.md).

## Testing

Live coverage is in `functionaltests/workloads/test_container.py`. Run on a test router with a
preloaded BusyBox-compatible image:

```sh
python3 /usr/lib/nvyr/functionaltests/workloads/test_container.py --container-image alpine
```

## Structured output

The Python operational functions support `raw=True` for structured callers;
there is no JSON keyword in the CLI. Container log commands are documented
in the [user logging guide](../users/logging.md#container-logs).
