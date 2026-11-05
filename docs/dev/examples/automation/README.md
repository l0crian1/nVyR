# Standalone automation helpers

Copy [nvyr_helpers.py](nvyr_helpers.py) beside your Python scripts, for example
under `/config/scripts/`. It is an importable helper file, not an installed nVyR
module or a new CLI command. It uses the nVyR Python package, dnspython, curl,
iputils-ping and `nc` (netcat-openbsd) already available in the router image.

The supplied `ping_targets` dictionary is retained. Nothing probes those
addresses automatically, and their availability has not been revalidated.

## Health checks

```python
from nvyr_helpers import dns_test, http_test, ping_targets, ping_test, port_test

icmp_ok = ping_test(ping_targets['cloudflare'], source_address='eth0')
dns_ok = dns_test(['1.1.1.1'], 'example.org')
ipv6_record_ok = dns_test(['1.1.1.1'], 'example.org', record_type='AAAA')

web_ok = http_test(['https://example.org'], timeout=2)
tcp_ok = port_test(443, 'example.org', timeout=2)
```

Checks return `True` on success and `False` after unsuccessful attempts. `retries`
counts total rounds, not extra attempts. Ping, DNS and TCP wait only between
rounds; HTTP keeps the original helper's immediate retries. An empty target list
cannot succeed. Checking an AAAA record does not itself prove IPv6 connectivity.

Ping, curl and notifications accept a source IP or interface name. DNS and TCP
take a source IP address. A source address does not force a route or select a
VRF; run the caller in the intended routing context when necessary. DNS ignores
the router's resolver list and queries only the supplied servers.

The DNS check requires a successful answer for the requested record type,
including following CNAMEs. DNS errors and missing records try the next server.
HTTP requires both a successful curl exit and a 2xx/3xx status; redirects are not
followed. TCP checks only establish and close a connection; they do not validate
the application protocol or test UDP.

Missing executables and subprocess launch errors remain exceptions. The nVyR
process wrapper also raises `CommandError` if its outer execution deadline is
exceeded. Ping uses the wrapper's 15-second outer deadline, independently of
its 0.5-second reply wait. HTTP and notifications allow two additional seconds
beyond curl's transfer deadline. TCP uses `nc -z` with its connection timeout
rounded up to whole seconds. That timeout applies per resolved address;
hostname resolution and a complete retry sequence can take longer.

## Configuration changes

There is no `configure()` function. Use
[ConfigurationSession](../../config-session.md) directly, retaining the normal
validation, locking, commit and recovery behavior.

```python
from nvyr.config_session import ConfigurationSession
from nvyr_helpers import log_message, ping_targets, ping_test

reachable = ping_test(ping_targets['cloudflare'], source_address='eth0')

if reachable:
    with ConfigurationSession() as config:
        config.request_lock()

        config.set('set interfaces ethernet eth0 description "WAN"')

        config.commit()

    log_message('WAN configuration committed', 'uplink-check')
```

The example performs a description-only change. Call `config.save()` explicitly
if a change should survive reboot; it is not automatic. The helper neither
forces session-lock ownership nor changes accounts or permissions. Run these
scripts on the host through a dev-admin shell or an authorized task-scheduler
`exec` action, not inside a restricted interactive session container.

## Notifications and logging

```python
from nvyr_helpers import log_message, ntfy

log_message('Uplink check completed', 'uplink-check')

ntfy('Uplink check completed', 'https://ntfy.example.org/router-status', timeout=10)
```

`ntfy()` sends the message literally, including quotes, newlines and leading
`@` characters. It returns `None` on success and raises `CommandError` for a
failed transfer or HTTP error. A notification failure can therefore be handled
separately from the configuration commit by the calling script.

`log_message()` uses local syslog. Its custom process name normally appears in
`show log system`, subject to the configured severity threshold.
