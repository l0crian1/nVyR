#!/usr/bin/env python3
"""Standalone health checks and notifications for scripts running on nVyR.

Configuration changes belong in the caller, using ConfigurationSession.
"""

from math import ceil
from syslog import openlog, syslog, closelog, LOG_INFO, LOG_PID
from time import sleep

import dns.exception
import dns.resolver

from nvyr.helpers.process import cli_cmd, run


# Retained from the supplied helper; callers choose which targets suit their uplink.
ping_targets = {
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "opendns": ["208.67.222.222", "208.67.220.220"],
    "level3": ["4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6"],
    "comcast": ["75.75.75.75", "75.75.76.76"],
    "root_servers": [
        "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
        "192.203.230.10", "192.5.5.241", "198.97.190.53", "192.36.148.17",
        "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33",
    ],
    "openresolver_anycast": ["64.6.64.6", "64.6.65.6", "185.228.168.9", "185.228.169.9"],
    "akamai": ["23.62.6.50", "23.43.133.10"],
    "cloudflare_cdn": ["104.16.248.249", "104.17.0.185"],
    "fastly": ["151.101.1.57", "151.101.65.57"],
    "aws": ["13.248.118.1", "52.85.61.52"],
}


def ntfy(message, url, source_address=""):
    """POST a message, leaving curl output visible and ignoring its exit status.

    source_address may be a local address or interface name, as accepted by curl.
    Like the original helper, this returns None and imposes no transfer timeout.
    """
    arguments = ['curl', '--data-raw', message, '--url', url]
    if source_address:
        arguments.extend(['--interface', source_address])

    run(arguments, stream=True, timeout=None)


def log_message(message, process, level=LOG_INFO):
    """Write to local syslog with the supplied process name and severity."""
    openlog(process, LOG_PID)
    try:
        syslog(level, message)
    finally:
        closelog()


def ping_test(addresses, source_address="", retries=3, interval=5):
    """Return True if any target answers a single ICMP echo in any retry round.

    Each probe waits up to 0.5 seconds for its reply. source_address accepts a
    local address or interface name. Wait interval seconds only between rounds.
    """
    addresses = tuple(addresses)
    arguments = ['ping', '-c', '1', '-W', '0.5']
    if source_address:
        arguments.extend(['-I', source_address])

    for attempt in range(retries):
        if any(run([*arguments, '--', address]) == 0 for address in addresses):
            return True
        if attempt < retries - 1:
            sleep(interval)
    return False


def dns_test(servers, query, source_address="", retries=3, interval=5, *, record_type='A'):
    """Return True if a server resolves query to the requested record type.

    Servers and source_address are literal IP addresses. Each server gets a
    one-second resolution attempt, including TCP fallback for truncated replies.
    NXDOMAIN, absent records, DNS errors and network failures try the next server.
    record_type defaults to A; use AAAA to check an IPv6 address record.
    """
    servers = tuple(servers)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 1
    resolver.lifetime = 1

    for attempt in range(retries):
        for server in servers:
            resolver.nameservers = [server]
            try:
                answer = resolver.resolve(query, record_type, source=source_address or None, search=False)
            except (dns.exception.DNSException, OSError):
                continue
            if answer.rrset:
                return True
        if attempt < retries - 1:
            sleep(interval)
    return False


def http_test(urls, source_address="", retries=3, timeout=2):
    """Return True for a completed HTTP request with a 2xx or 3xx status.

    Each URL gets timeout seconds per attempt. Redirects count as reachable but
    are not followed. As in the original helper, retries have no added delay.
    source_address accepts a local address or interface name.
    """
    urls = tuple(urls)
    arguments = ['curl', '--silent', '--show-error', '--output', '/dev/null',
                 '--write-out', '%{http_code}', '--max-time', str(timeout)]
    if source_address:
        arguments.extend(['--interface', source_address])

    for attempt in range(retries):
        for url in urls:
            result = cli_cmd([*arguments, '--url', url], timeout=timeout + 2)
            status = result.stdout.strip()
            # A server may send headers and then stall: a status alone is not success.
            if result.returncode == 0 and len(status) == 3 and status.isdecimal() and 200 <= int(status) < 400:
                return True
    return False


def port_test(port, address, source_address="", retries=3, interval=3, timeout=2):
    """Return True if a TCP connection succeeds; this does not test UDP.

    Uses nc from netcat-openbsd. source_address must be a local IP address,
    not an interface name. timeout is rounded up to whole seconds for nc and
    applies per resolved address, not to hostname resolution or all retries.
    """
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    arguments = ['nc', '-z', '-w', str(ceil(timeout))]
    if source_address:
        arguments.extend(['-s', source_address])
    arguments.extend(['--', address, str(port)])

    for attempt in range(retries):
        if run(arguments, timeout=None) == 0:
            return True
        if attempt < retries - 1:
            sleep(interval)
    return False
