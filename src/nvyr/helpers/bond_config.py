"""Translate CLI bond settings to Linux rtnetlink attribute values."""

from ipaddress import ip_address

from nvyr.helpers.validators import duration_seconds
from nvyr.tree import lookup

MODES = ('balance-rr', 'active-backup', 'balance-xor', 'broadcast', '802.3ad', 'balance-tlb', 'balance-alb')
PRIMARY_MODES = {'active-backup', 'balance-tlb', 'balance-alb'}
PROBE_MODES = {'balance-rr', 'active-backup', 'balance-xor', 'broadcast'}


def milliseconds(value):
    return int(value[:-2]) if value.endswith('ms') else duration_seconds(value) * 1000


# Each entry names the Linux attribute and how to encode the configured leaf.
FIELDS = {
    'mode': ('MODE', MODES.index),
    'packets-per-member': ('PACKETS_PER_SLAVE', int),
    'transmit-hash-policy': ('XMIT_HASH_POLICY', ('layer2', 'layer3+4', 'layer2+3', 'encap2+3', 'encap3+4', 'vlan+srcmac').index),
    'deliver-inactive-frames': ('ALL_SLAVES_ACTIVE', 1),
    'primary-reselect': ('PRIMARY_RESELECT', ('always', 'better', 'failure').index),
    'fail-over-mac': ('FAIL_OVER_MAC', ('none', 'active', 'follow').index),
    'peer-notifications': ('NUM_PEER_NOTIF', int),
    'peer-notification-delay': ('PEER_NOTIF_DELAY', milliseconds),
    'resend-igmp': ('RESEND_IGMP', int),
    'learning-packet-interval': ('LP_INTERVAL', duration_seconds),
    'disable-dynamic-load-balancing': ('TLB_DYNAMIC_LB', 0),
    'link-monitor mii interval': ('MIIMON', milliseconds),
    'link-monitor mii up-delay': ('UPDELAY', milliseconds),
    'link-monitor mii down-delay': ('DOWNDELAY', milliseconds),
    'link-monitor probe interval': ('ARP_INTERVAL', milliseconds),
    'link-monitor probe ipv4-target': ('ARP_IP_TARGET', lambda items: sorted({str(ip_address(item)) for item in items})),
    'link-monitor probe ipv6-target': ('NS_IP6_TARGET', lambda items: sorted({str(ip_address(item)) for item in items})),
    'link-monitor probe missed-max': ('MISSED_MAX', int),
    'link-monitor probe validate': ('ARP_VALIDATE', ('none', 'active', 'backup', 'all', 'filter', 'filter-active', 'filter-backup').index),
    'link-monitor probe target-policy': ('ARP_ALL_TARGETS', ('any', 'all').index),
    'lacp passive': ('AD_LACP_ACTIVE', 0),
    'lacp rate': ('AD_LACP_RATE', ('slow', 'fast').index),
    'lacp min-links': ('MIN_LINKS', int),
    'lacp aggregator-select': ('AD_SELECT', ('stable', 'bandwidth', 'count', 'actor-port-priority').index),
    'lacp system-priority': ('AD_ACTOR_SYS_PRIO', int),
    'lacp system-mac': ('AD_ACTOR_SYSTEM', str.lower),
    'lacp user-port-key': ('AD_USER_PORT_KEY', int),
    'lacp strict': ('LACP_STRICT', 1),
    'lacp independent-control': ('COUPLED_CONTROL', 0),
    'lacp broadcast-neighbor': ('BROADCAST_NEIGH', 1),
}


def options(values):
    result = {}
    for path, (key, encode) in FIELDS.items():
        parts = path.split()
        parent = lookup(values, tuple(parts[:-1]), {}) if len(parts) > 1 else values
        if parts[-1] in parent:
            result[key] = encode(parent[parts[-1]]) if callable(encode) else encode
    return result


def member_options(values):
    return {'PRIO': int(lookup(values, ('priority',), 0)), 'QUEUE_ID': int(lookup(values, ('queue-id',), 0)),
            'ACTOR_PORT_PRIO': int(lookup(values, ('lacp', 'port-priority'), 255))}
