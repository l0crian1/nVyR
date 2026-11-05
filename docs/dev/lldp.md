# LLDP implementation

`service_lldp.py` follows the normal four stages. `get_config()` selects the
effective service section, `verify()` checks relationships, `generate()` renders
the two Jinja files, and `apply()` installs the generated plan. Configd owns
transaction compensation and recovery; it does not configure LLDP itself.

`helpers/lldp.py` provides native control access and a small installation function.
There is no separate manager, wildcard expansion, or interface watcher. The
service runs after interface and container creation, and watches their
configuration changes through the existing dependency mechanism. Native
permanent-interface patterns preserve exact-port overrides
across link removal/reappearance while lldpd remains running.

## Native service

The image installs Debian trixie's maintained `lldpd` package (minimum 1.0.18),
with the distro unit masked so only `nvyr-lldp.service` owns activation. Upstream
maintenance is led by Vincent Bernat; Debian packages fixes for trixie through
its package/security maintenance. Recheck both sources when updating:

- [Upstream releases and documentation](https://lldpd.github.io/)
- [Debian trixie package](https://packages.debian.org/trixie/lldpd)
- [Debian security tracking](https://security-tracker.debian.org/tracker/source-package/lldpd)

The daemon reads `/run/nvyr-lldp/lldpd.conf` during its native paused startup.
The installer reapplies each idempotent command individually to check its exit
status: the native file loader returns success even for invalid commands. The public
advertisement configuration is mode 0644 because the startup client reads it
without root privileges. The environment file is root-only. The daemon retains
its own privilege separation.

Interface selection is supplied at process launch as well as in the command
file. Exact and prefix selectors, plus exclusions, go to lldpd unchanged. `all`
becomes `*`. An exact entry can coexist with it to select a virtual interface.
Neither wildcard nor `all` tag instances have implicit child defaults.

Changes restart the service, restoring omitted values to native defaults. An
identical plan checks health without restarting. Removal stops the unit and
removes the files. A missing exact override port is an error: native lldpcli
silently ignores unknown ports, so the installer checks the actual interface
inventory after starting. No existence check is applied to selector-only entries.

## Operations and tests

Summary commands consume native `json0`, whose arrays retain a consistent shape
for zero, one, or multiple records. Details and monitoring preserve native text.
`--raw` returns native JSON. Logs use the normal nVyR logging registry.

- `tests/test_lldp.py`: schema/verification, operations and presentation contracts.
- `smoketests/test_lldp.py`: CLI-to-native configuration, selectors, override removal,
  disable and service removal, with one retained veth pair.
- `functionaltests/network/test_lldp.py`: discovery and counters on the existing
  routed-network LANs; the shared fixture starts native peers once.
- `tests/test_lldp_native.py`: an opt-in isolated native lab for quoting, neighbor
  exchange, mode changes, VLAN tagging and expiry. Run with
  `NVYR_LLDP_NATIVE=1 python -m pytest -q tests/test_lldp_native.py` inside a
  disposable privileged Linux container with lldpd installed.
- Acceptance includes native identity, selection and overrides before and after
  reboot; it does not require a physical LLDP peer.

User-facing examples belong in the [LLDP guide](../users/lldp.md).
