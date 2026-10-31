"""Kernel paths, conversions and nVyR defaults shared by boot and configuration.

This module has no nVyR imports so the package builder can load it before nVyR
is installed. Paths are components: a dot in an interface name is never split.
"""

BOOLEAN = {'enable': '1', 'disable': '0'}
IGNORE = {'enable': '0', 'disable': '1'}
SETTINGS = {}

ARP_IGNORE_CHOICES = {
    '0': 'Reply for any local target address, even on another interface',
    '1': 'Reply only if the target address belongs to the receiving interface',
    '2': 'Require a target on the receiving interface and a sender in that subnet',
    '3': 'Do not reply for host-scope addresses; allow global and link scope',
    '8': 'Never reply to ARP requests for local addresses',
}


def setting(name, path, default, description, *, values=None, kind='integer',
            minimum=1, maximum=2147483647, all_value=None, owner='firewall'):
    """Declare one CLI-relative setting and its native representation."""
    SETTINGS[name] = {
        'path': tuple(path.split('/')), 'default': default, 'description': description,
        'values': values, 'kind': 'choice' if values else kind,
        'minimum': minimum, 'maximum': maximum, 'all_value': all_value,
        'owner': owner,
    }


def interface_setting(name, family, native, default, description, *, values=BOOLEAN,
                      all_value='0'):
    """Global interface defaults have a separate, setting-specific all gate."""
    setting(name, f'net/{family}/conf/{{interface}}/{native}', default, description,
            values=values, all_value=all_value)


setting('ipv4 echo-request', 'net/ipv4/icmp_echo_ignore_all', 'enable',
        'Respond to IPv4 echo requests addressed to this router', values=IGNORE)
setting('ipv4 broadcast-ping', 'net/ipv4/icmp_echo_ignore_broadcasts', 'disable',
        'Respond to IPv4 broadcast and multicast echo or timestamp requests', values=IGNORE)
setting('ipv6 echo-request', 'net/ipv6/icmp/echo_ignore_all', 'enable',
        'Respond to IPv6 echo requests addressed to this router', values=IGNORE)
setting('ipv6 multicast-ping', 'net/ipv6/icmp/echo_ignore_multicast', 'disable',
        'Respond to IPv6 multicast echo requests', values=IGNORE)
setting('ipv6 anycast-ping', 'net/ipv6/icmp/echo_ignore_anycast', 'enable',
        'Respond to IPv6 anycast echo requests', values=IGNORE)

interface_setting('ipv4 receive-redirects', 'ipv4', 'accept_redirects', 'disable',
                  'Accept ICMP redirects; inherited by interfaces', all_value='1')
interface_setting('ipv4 send-redirects', 'ipv4', 'send_redirects', 'disable',
                  'Send ICMP redirects; inherited by interfaces')
interface_setting('ipv4 source-route', 'ipv4', 'accept_source_route', 'disable',
                  'Accept IPv4 source-route options; inherited by interfaces', all_value='1')
interface_setting('ipv4 directed-broadcast', 'ipv4', 'bc_forwarding', 'disable',
                  'Forward IPv4 directed broadcasts; inherited by interfaces', all_value='1')
interface_setting('ipv4 log-martians', 'ipv4', 'log_martians', 'disable',
                  'Log packets with invalid addresses; inherited by interfaces')
interface_setting('ipv6 receive-redirects', 'ipv6', 'accept_redirects', 'disable',
                  'Accept IPv6 redirects; inherited by interfaces', all_value=None)
interface_setting('ipv6 source-route', 'ipv6', 'accept_source_route', 'routing-header-2',
                  'Accept only routing header type 2, or reject routing headers',
                  values={'disable': '-1', 'routing-header-2': '0'}, all_value='0')

setting('ipv4 arp cache-timeout', 'net/ipv4/neigh/{interface}/base_reachable_time_ms', '30s',
        'Base ARP reachable time; actual reachable time is randomized', kind='milliseconds')
interface_setting('ipv4 arp filter', 'ipv4', 'arp_filter', 'disable',
                  'Use routing decisions when answering ARP requests')
interface_setting('ipv4 arp announce', 'ipv4', 'arp_announce', 'any',
                  'Select source addresses for outgoing ARP requests',
                  values={'any': '0', 'subnet': '1', 'best-local': '2'})
interface_setting('ipv4 arp ignore', 'ipv4', 'arp_ignore', '0',
                  'Restrict responses to incoming ARP requests',
                  values={number: number for number in ('0', '1', '2', '3', '8')})
interface_setting('ipv4 arp accept', 'ipv4', 'arp_accept', 'disable',
                  'Create new neighbor entries from gratuitous ARP',
                  values={'disable': '0', 'enable': '1', 'same-subnet': '2'})
interface_setting('ipv4 arp notify', 'ipv4', 'arp_notify', 'disable',
                  'Send gratuitous ARP when a device comes up or changes MAC')
interface_setting('ipv4 arp proxy', 'ipv4', 'proxy_arp', 'disable',
                  'Answer ARP requests on behalf of routed destinations')
interface_setting('ipv4 arp proxy-pvlan', 'ipv4', 'proxy_arp_pvlan', 'disable',
                  'Proxy ARP back through the receiving interface for private VLANs')

setting('ipv4 icmp-rate-limit interval', 'net/ipv4/icmp_ratelimit', '1s',
        'Minimum spacing for rate-limited ICMP responses to a destination; zero disables',
        kind='milliseconds', minimum=0)
setting('ipv4 icmp-rate-limit rate', 'net/ipv4/icmp_msgs_per_sec', '1000',
        'Global rate-limited ICMP messages per second', minimum=0)
setting('ipv4 icmp-rate-limit burst', 'net/ipv4/icmp_msgs_burst', '50',
        'Global ICMP response burst allowance')
setting('ipv6 icmp-rate-limit interval', 'net/ipv6/icmp/ratelimit', '100ms',
        'Minimum spacing for rate-limited ICMPv6 responses; zero disables',
        kind='milliseconds', minimum=0)
setting('syn-cookies', 'net/ipv4/tcp_syncookies', 'enable',
        'Use SYN cookies when a local TCP listening backlog overflows', values=BOOLEAN)

# Hash size is applied before capacity limits; auto restores the initial boot value.
for name, native, description in (
    ('hash-size', 'buckets', 'Connection tracking hash buckets'),
    ('maximum-entries', 'max', 'Maximum tracked connections'),
    ('maximum-expectations', 'expect_max', 'Maximum expected related connections'),
):
    setting(f'connection-tracking {name}', f'net/netfilter/nf_conntrack_{native}',
            'auto', description, kind='auto-integer')

setting('connection-tracking checksum-validation', 'net/netfilter/nf_conntrack_checksum',
        'enable', 'Validate checksums before tracking packets', values=BOOLEAN)
setting('connection-tracking events', 'net/netfilter/nf_conntrack_events', 'auto',
        'Allocate connection event reporting automatically or explicitly',
        values={'auto': '2', 'enable': '1', 'disable': '0'})
setting('connection-tracking timestamp', 'net/netfilter/nf_conntrack_timestamp', False,
        'Record connection creation and destruction timestamps', kind='presence')
setting('connection-tracking log-invalid', 'net/netfilter/nf_conntrack_log_invalid', 'none',
        'Log invalid conntrack packets for one protocol or all protocols',
        values={'none': '0', 'all': '255', 'icmp': '1', 'icmpv6': '58',
                'tcp': '6', 'udp': '17', 'udplite': '136'})
setting('connection-tracking tcp loose', 'net/netfilter/nf_conntrack_tcp_loose', 'enable',
        'Allow tracking connections whose initial handshake was not observed', values=BOOLEAN)
setting('connection-tracking tcp liberal', 'net/netfilter/nf_conntrack_tcp_be_liberal', False,
        'Relax TCP window validation for tracked packets', kind='presence')
setting('connection-tracking tcp ignore-invalid-rst', 'net/netfilter/nf_conntrack_tcp_ignore_invalid_rst',
        False, 'Do not classify out-of-window TCP resets as invalid', kind='presence')
setting('connection-tracking tcp maximum-retransmissions', 'net/netfilter/nf_conntrack_tcp_max_retrans',
        '3', 'Retransmission threshold for the shorter connection timeout')

TIMEOUTS = {
    'tcp': {
        'established': ('established', '5d'),
        'syn-sent': ('syn_sent', '2m'), 'syn-received': ('syn_recv', '1m'),
        'fin-wait': ('fin_wait', '2m'), 'close-wait': ('close_wait', '1m'),
        'last-ack': ('last_ack', '30s'), 'time-wait': ('time_wait', '2m'),
        'close': ('close', '10s'), 'unacknowledged': ('unacknowledged', '5m'),
        'max-retransmissions': ('max_retrans', '5m'),
    },
    'udp': {'unreplied': ('', '30s'), 'stream': ('stream', '2m')},
    'gre': {'unreplied': ('', '30s'), 'stream': ('stream', '3m')},
    'sctp': {
        'closed': ('closed', '10s'), 'cookie-wait': ('cookie_wait', '3s'),
        'cookie-echoed': ('cookie_echoed', '3s'), 'established': ('established', '210s'),
        'shutdown-sent': ('shutdown_sent', '3s'), 'shutdown-received': ('shutdown_recd', '3s'),
        'shutdown-ack-sent': ('shutdown_ack_sent', '3s'), 'heartbeat-sent': ('heartbeat_sent', '30s'),
    },
}
for protocol, states in TIMEOUTS.items():
    for state, (suffix, default) in states.items():
        native = f'net/netfilter/nf_conntrack_{protocol}_timeout'
        if suffix:
            native += '_' + suffix
        setting(f'connection-tracking timeout {protocol} {state}', native, default,
                f'{protocol.upper()} {state} connection tracking lifetime',
                kind='seconds', maximum=2147483)

for protocol, default in (('icmp', '30s'), ('icmpv6', '30s'), ('generic', '10m')):
    description = {
        'icmp': 'ICMP connection tracking lifetime',
        'icmpv6': 'ICMPv6 connection tracking lifetime',
        'generic': 'Connection tracking lifetime for other protocols',
    }[protocol]
    setting(f'connection-tracking timeout {protocol}', f'net/netfilter/nf_conntrack_{protocol}_timeout',
            default, description, kind='seconds', maximum=2147483)

for protocol in ('tcp', 'udp'):
    setting(f'flowtable-timeout {protocol}', f'net/netfilter/nf_flowtable_{protocol}_timeout',
            '30s', f'{protocol.upper()} flow offload idle lifetime', kind='seconds', maximum=2147483)


# Per-interface CLI paths reuse global keys where an inherited policy exists.
INTERFACE_SETTINGS = {}
for name, spec in list(SETTINGS.items()):
    if '{interface}' in spec['path']:
        parts = name.split()
        family = 'ip' if parts[0] == 'ipv4' else parts[0]
        INTERFACE_SETTINGS[(family, '-'.join(parts[1:]))] = name


def link_setting(cli, native, default, description, **options):
    """Register a link-only setting without extending firewall or boot policy."""
    name = 'interface ' + cli
    family, *parts = cli.split()
    protocol = 'ipv4' if family == 'ip' else family
    path = f'net/{protocol}/{native}'
    setting(name, path, default, description, owner='interface', **options)
    INTERFACE_SETTINGS[(family, *parts)] = name


link_setting('ip disable-forwarding', 'conf/{interface}/forwarding', False,
             'Disable IPv4 forwarding on this interface', kind='presence')
link_setting('ip accept-local', 'conf/{interface}/accept_local', False,
             'Accept incoming packets with a local IPv4 source address', kind='presence')
link_setting('ip route-localnet', 'conf/{interface}/route_localnet', False,
             'Allow routing 127.0.0.0/8 through this interface', kind='presence')
link_setting('ip promote-secondaries', 'conf/{interface}/promote_secondaries', False,
             'Retain secondary IPv4 addresses when their primary is removed', kind='presence')
link_setting('ip arp-retransmit-interval', 'neigh/{interface}/retrans_time_ms', '1s',
             'Interval between ARP probes', kind='milliseconds')
link_setting('ip arp-stale-time', 'neigh/{interface}/gc_stale_time', '60s',
             'Interval for checking stale ARP neighbors', kind='seconds', maximum=2147483)

link_setting('ipv6 disable', 'conf/{interface}/disable_ipv6', False,
             'Disable IPv6 and remove its addresses and routes', kind='presence')
link_setting('ipv6 proxy-ndp', 'conf/{interface}/proxy_ndp', False,
             'Enable proxy neighbor discovery; proxy entries are still required', kind='presence')
link_setting('ipv6 hop-limit', 'conf/{interface}/hop_limit', '64',
             'Default IPv6 hop limit', maximum=255)
link_setting('ipv6 autoconf', 'conf/{interface}/autoconf', False,
             'Acquire SLAAC addresses and accept router advertisements while routing', kind='presence')
link_setting('ipv6 accept-router-advertisements', 'conf/{interface}/accept_ra', False,
             'Accept router advertisements while routing, without enabling SLAAC', kind='presence')
link_setting('ipv6 no-default-route', 'conf/{interface}/accept_ra_defrtr', False,
             'Do not learn a default route from router advertisements', kind='presence')
link_setting('ipv6 no-ra-mtu', 'conf/{interface}/accept_ra_mtu', False,
             'Ignore MTU advertised by IPv6 routers', kind='presence')
link_setting('ipv6 address-generation', 'conf/{interface}/addr_gen_mode', 'eui64',
             'Algorithm for automatically generated IPv6 addresses',
             values={'eui64': '0', 'stable-privacy': '2'})
link_setting('ipv6 temporary-addresses', 'conf/{interface}/use_tempaddr', 'disable',
             'Generate temporary SLAAC addresses and select source-address preference',
             values={'disable': '0', 'prefer-public': '1', 'prefer-temporary': '2'})
link_setting('ipv6 maximum-autoconf-addresses', 'conf/{interface}/max_addresses', '16',
             'Maximum automatically configured IPv6 addresses', maximum=65535)
link_setting('ipv6 duplicate-address-detection disable', 'conf/{interface}/accept_dad', False,
             'Disable IPv6 duplicate address detection', kind='presence')
link_setting('ipv6 duplicate-address-detection probes', 'conf/{interface}/dad_transmits', '1',
             'Neighbor solicitations sent during duplicate address detection', maximum=100)
link_setting('ipv6 neighbor-reachable-time', 'neigh/{interface}/base_reachable_time_ms', '30s',
             'Base IPv6 neighbor reachable time; actual time is randomized', kind='milliseconds')
link_setting('ipv6 neighbor-retransmit-interval', 'neigh/{interface}/retrans_time_ms', '1s',
             'Interval between IPv6 neighbor solicitations', kind='milliseconds')
link_setting('ipv6 neighbor-stale-time', 'neigh/{interface}/gc_stale_time', '60s',
             'Interval for checking stale IPv6 neighbors', kind='seconds', maximum=2147483)


def native_value(spec, value):
    """Convert a validated CLI value without touching the host."""
    if spec['values']:
        return spec['values'][value]
    if spec['kind'] == 'presence':
        if spec['path'][-1] in ('forwarding', 'accept_ra_defrtr', 'accept_ra_mtu', 'accept_dad'):
            return '0' if value else '1'
        if spec['path'][-1] == 'accept_ra':
            return '2' if value else '0'
        return '1' if value else '0'
    if value == 'auto':
        return None
    if spec['kind'] in ('seconds', 'milliseconds'):
        if value.endswith('ms'):
            return str(int(value[:-2]))
        units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        scale = 1000 if spec['kind'] == 'milliseconds' else 1
        return str(int(value[:-1]) * units[value[-1]] * scale)
    return str(int(value))


def assignments(spec, value):
    """Yield sysctl.d paths in default, all-gate, existing-interface order."""
    path = '/'.join(spec['path'])
    if '{interface}' not in path:
        return [(path, value)]
    result = [(path.replace('{interface}', 'default'), value)]
    if '/conf/' in path:
        gate = spec['all_value'] if spec['all_value'] is not None else value
        result.append((path.replace('{interface}', 'all'), gate))
    result.append((path.replace('{interface}', '*'), value))
    return result


def sysctl_lines(values):
    """Render exact all/default entries before globs; systemd excludes exact keys."""
    lines = []
    for name, value in values.items():
        if value is None:
            continue
        for path, native in assignments(SETTINGS[name], value):
            lines.append(f'{path} = {native}')
    return lines


# Only these configurable settings are needed before configd starts. New CLI
# tunables must not automatically become boot policy; firewall apply owns them.
BOOT_SETTINGS = (
    'ipv4 echo-request', 'ipv4 broadcast-ping',
    'ipv6 echo-request', 'ipv6 multicast-ping', 'ipv6 anycast-ping',
    'ipv4 receive-redirects', 'ipv4 send-redirects', 'ipv4 source-route',
    'ipv4 directed-broadcast', 'ipv6 receive-redirects', 'ipv6 source-route',
    'syn-cookies',
)


def boot_configuration():
    """Keep forwarding first because changing it resets IPv4 router defaults."""
    lines = [
        '# Generated by build_tools/kernel_settings.py; edit kernel_settings_map.py.',
        '# Forwarding must precede the firewall/interface defaults below.',
        'net/ipv4/ip_forward = 1', 'net/ipv4/conf/default/forwarding = 1',
        'net/ipv4/conf/*/forwarding = 1',
        'net/ipv6/conf/all/forwarding = 1', 'net/ipv6/conf/default/forwarding = 1',
        'net/ipv6/conf/*/forwarding = 1', '',
        '# Source validation is supplied by nftables policy, not rp_filter.',
        'net/ipv4/conf/default/rp_filter = 0', 'net/ipv4/conf/*/rp_filter = 0', '',
        '# Retain the router RA baseline and normal PMTU discovery.',
        'net/ipv6/conf/default/accept_ra = 1', 'net/ipv6/conf/*/accept_ra = 1',
        'net/ipv4/ip_no_pmtu_disc = 0', 'net/ipv4/ip_forward_use_pmtu = 0', '',
        '# Early router baseline; detailed firewall tunables are applied by configd.',
    ]
    values = {}
    for name in BOOT_SETTINGS:
        spec = SETTINGS[name]
        values[name] = native_value(spec, spec['default'])
    lines.extend(sysctl_lines(values))
    return '\n'.join(lines) + '\n'
