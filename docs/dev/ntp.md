# NTP: implementation and maintenance

For configuration and command usage, see the [user guide](../users/ntp.md).

## Testing and references

Run the live tests with:

```sh
sudo python3 /usr/lib/nvyr/smoketests/test_ntp.py
```

References: [Chrony configuration](https://chrony-project.org/doc/4.6/chrony.conf.html),
[Chronyd restart behavior](https://chrony-project.org/doc/4.6/chronyd.html).
Report definitions: [Chronyc clients and serverstats](https://chrony-project.org/doc/4.6/chronyc.html).

Serving activity, client-access behavior and operational views are covered separately:

```bash
sudo python3 /usr/lib/nvyr/functionaltests/network/test_ntp.py
```

## Packaging

The Debian package and ISO require `chrony`. When installing only the nVyR `.deb`,
use a dependency-aware installation such as `apt install ./nvyr-router_0.1.0_all.deb`.

## Chrony restart and persistence

The first successful Chrony launch after boot permits initial clock stepping
(`makestep 1.0 3`). Subsequent launches in that boot use `-R`, preserving gradual
correction during configuration changes. Drift and NTS cookies are stored in
`/config/ntp/`. The control socket is local only; no UDP management port is opened.
Stock Chrony/timesyncd services are masked so they cannot compete with nVyR.
Deleting `system ntp` stops the service, retaining its learned drift data.

## Structured operational output

Operational functions accept `raw=True`. Sources return structured source records;
client activity returns a list, and server statistics returns the complete statistics
dictionary. Counts remain integers and unknown client times remain null.
