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

Ping, HTTP checks and notifications accept a source IP or interface name. DNS and TCP
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
its 0.5-second reply wait. HTTP checks allow two additional seconds
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

## ISP reachability and BGP default advertisement

[ispcheck.py](ispcheck.py) checks the Cloudflare, Google and Quad9 ping targets.
If all checks fail while a default route is being advertised to the configured
BGP peer, it removes `default-originate`. When a target becomes reachable and
the default is not being advertised, it restores `default-originate`. Each
change attempt is logged and sent to the configured ntfy server.

Copy it beside `nvyr_helpers.py`, for example into `/config/scripts/`, and edit
`peer`, `ntfy_server` and `addresses` for your network. As a sys-admin or dev-admin,
configure a [scheduled task](../../../users/tasks.md) with a one-minute interval:

```text
configure
set system task ISPCHECK exec '/usr/bin/python3 /config/scripts/ispcheck.py'
set system task ISPCHECK interval 1m
commit
save
exit
```

Commit arms the task; no separate start is required. Its first run is one minute
later, and subsequent runs wait one minute after the previous execution finishes.
The `save` above preserves the task configuration across reboot.

Check its status and output, or trigger an immediate run:

```text
show system tasks ISPCHECK
show log task ISPCHECK
start system task ISPCHECK
```

The script runs as root on the host in the default routing instance and
deliberately requests the configuration lock with `force=True`, taking ownership
from another session if necessary. Its BGP changes are committed to running
configuration without saving them for reboot.

## Notifications and logging

```python
from nvyr_helpers import log_message, ntfy

log_message('Uplink check completed', 'uplink-check')

ntfy('Uplink check completed', 'https://ntfy.example.org/router-status')
```

`ntfy()` sends the message literally, including quotes, newlines and leading
`@` characters. As in the original helper, it returns `None`, leaves curl's
output visible, and ignores curl's exit status so transfer failures do not
abort the calling script. It imposes no transfer timeout, so an unreachable
endpoint can delay the caller until curl exits. Failure to launch curl still
raises `CommandError`.

`log_message()` uses local syslog. Its custom process name normally appears in
`show log system`, subject to the configured severity threshold.
