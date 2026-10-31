# Packet trace analysis: implementation and maintenance

For configuration and command usage, see the [user guide](../users/firewall-tracing.md).

## API and testing

The operational script's `raw` argument returns structured JSON for API callers;
it is not a separate CLI keyword. Capture, parsing, analysis, and presentation
are separate helpers. Analysis never queries or modifies the current firewall.

The native regression corpus was captured with Linux 6.18 and nftables 1.1.7.
Render examples from all 26 captured scenarios into `dist/trace-story-examples/`
without connecting to a router:

```bash
PYTHONPATH=src:. python -m tests.trace_examples
```

Each scenario has a plain-text story. The directory also includes a full DNAT
detail view and the capture's trace index. These are actual renderer outputs,
including every observed pass of the selected ID.

The reproducible lab uses isolated namespaces and synthetic LAN/WAN traffic:

```bash
sudo env PYTHONPATH=src:. unshare -n python3 -m tests.trace_lab /tmp/nvyr-trace-lab
```

Use a new output directory for each run. The lab covers both families and multiple
protocols, NAT, rejection and dropping, nested control flow, groups, zone maps,
ingress, notrack, and VRF output. It leaves the real router's configuration,
interfaces, conntrack table, and firewall untouched.
