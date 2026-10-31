"""Read connection tracking without losing tuple, status, or accounting data."""

import ipaddress
import socket
from contextlib import closing

from pyroute2 import Conntrack
from pyroute2.netlink import NetlinkError, nla
from pyroute2.netlink.nfnetlink.nfctsocket import NFCTAttrTuple, nfct_msg

from nvyr.errors import OperationalError


STATES = {
    6: ('none', 'syn-sent', 'syn-recv', 'established', 'fin-wait', 'close-wait',
        'last-ack', 'time-wait', 'close', 'syn-sent2'),
    33: ('none', 'request', 'respond', 'partopen', 'open', 'closereq', 'closing', 'timewait'),
    132: ('none', 'closed', 'cookie-wait', 'cookie-echoed', 'established',
          'shutdown-sent', 'shutdown-recd', 'shutdown-ack-sent', 'heartbeat-sent', 'heartbeat-acked'),
}
STATUS_FLAGS = (
    'expected', 'seen-reply', 'assured', 'confirmed', 'snat', 'dnat', 'seq-adjust',
    'snat-done', 'dnat-done', 'dying', 'fixed-timeout', 'template', 'untracked',
    'helper', 'offload', 'hw-offload',
)
PROTOCOL_NAMES = {1: 'icmp', 6: 'tcp', 17: 'udp', 33: 'dccp', 47: 'gre',
                  58: 'ipv6-icmp', 132: 'sctp', 136: 'udplite'}


class ConnectionMessage(nfct_msg):
    """Decode tuple zones and the nested kernel helper-name attribute."""

    nla_map = tuple((name, 'cta_help' if name == 'CTA_HELP' else datatype)
                    for name, datatype in nfct_msg.nla_map)

    class cta_help(nla):
        nla_map = (('CTA_HELP_UNSPEC', 'none'), ('CTA_HELP_NAME', 'asciiz'), ('CTA_HELP_INFO', 'hex'))

    class cta_tuple(nfct_msg.cta_tuple):
        nla_map = nfct_msg.cta_tuple.nla_map + (('CTA_TUPLE_ZONE', 'be16'),)


# pyroute2 subclasses inherit their parent's compiled attribute cache. Compile
# our extended maps explicitly, regardless of whether another socket used nfct_msg first.
ConnectionMessage.cta_tuple().compile_nla()
ConnectionMessage.cta_help().compile_nla()
ConnectionMessage().compile_nla()


def _attr(message, name, default=None):
    """Accept Netlink attribute records without leaking their encoding to callers."""
    if message is None:
        return default
    for attribute in message.get('attrs', []):
        if attribute[0] == name:
            return attribute[1]
    return default


def _tuple(message):
    address = _attr(message, 'CTA_TUPLE_IP', {})
    protocol = _attr(message, 'CTA_TUPLE_PROTO', {})
    result = {}
    for version in (4, 6):
        for name, suffix in (('source-address', 'SRC'), ('destination-address', 'DST')):
            value = _attr(address, f'CTA_IP_V{version}_{suffix}')
            if value is not None:
                result[name] = value

    for name, suffix in (('source-port', 'SRC_PORT'), ('destination-port', 'DST_PORT'),
                         ('icmp-id', 'ICMP_ID'), ('icmp-type', 'ICMP_TYPE'), ('icmp-code', 'ICMP_CODE'),
                         ('icmp-id', 'ICMPV6_ID'), ('icmp-type', 'ICMPV6_TYPE'), ('icmp-code', 'ICMPV6_CODE')):
        value = _attr(protocol, 'CTA_PROTO_' + suffix)
        if value is not None:
            result[name] = value

    zone = _attr(message, 'CTA_TUPLE_ZONE')
    if zone is not None:
        result['zone'] = zone
    return result


def normalize(message):
    """Return one plain record; missing accounting is different from a zero count."""
    original = _attr(message, 'CTA_TUPLE_ORIG', {})
    protocol = _attr(_attr(original, 'CTA_TUPLE_PROTO'), 'CTA_PROTO_NUM', 0)
    status = _attr(message, 'CTA_STATUS', 0)
    result = {
        'family': 'ipv6' if message['nfgen_family'] == socket.AF_INET6 else 'ipv4',
        'protocol': PROTOCOL_NAMES.get(protocol, str(protocol)),
        'protocol-number': protocol,
        'original': _tuple(original),
        'reply': _tuple(_attr(message, 'CTA_TUPLE_REPLY', {})),
        'status': [name for bit, name in enumerate(STATUS_FLAGS) if status & (1 << bit)],
        'status-mask': status,
        'timeout': _attr(message, 'CTA_TIMEOUT'),
        'mark': _attr(message, 'CTA_MARK', 0),
        'zone': _attr(message, 'CTA_ZONE', 0),
        'id': _attr(message, 'CTA_ID'),
    }

    if protocol in STATES:
        name = PROTOCOL_NAMES[protocol].upper()
        information = _attr(_attr(message, 'CTA_PROTOINFO'), 'CTA_PROTOINFO_' + name)
        state = _attr(information, f'CTA_PROTOINFO_{name}_STATE')
        if state is not None:
            names = STATES[protocol]
            result['state'] = names[state] if state < len(names) else f'unknown ({state})'

    for direction, suffix in (('original', 'ORIG'), ('reply', 'REPLY')):
        counters = _attr(message, 'CTA_COUNTERS_' + suffix)
        if counters is not None:
            result[direction]['packets'] = _attr(counters, 'CTA_COUNTERS_PACKETS')
            result[direction]['bytes'] = _attr(counters, 'CTA_COUNTERS_BYTES')

    labels = _attr(message, 'CTA_LABELS')
    if labels is not None:
        if isinstance(labels, dict):
            labels = labels['value']
        result['labels'] = [bit for bit in range(128) if labels & (1 << bit)]

    helper = _attr(_attr(message, 'CTA_HELP'), 'CTA_HELP_NAME')
    if helper is not None:
        result['helper'] = helper

    result['nat'] = [name for name in ('snat', 'dnat') if name in result['status']]
    return result


def _protocol_number(name):
    if name is None:
        return None
    try:
        return socket.getprotobyname(name)
    except OSError:
        raise OperationalError(f'Unknown IP protocol: {name}.') from None


def read(*, family=None, protocol=None, state=None, source_address=None, destination_address=None):
    """Narrow the kernel dump by family/protocol, then compare original addresses and state."""
    # Restrict the socket family to the two supported IP address families.
    if family not in (None, 'ipv4', 'ipv6'):
        raise OperationalError('Choose ipv4 or ipv6.')

    number = _protocol_number(protocol)
    # State names belong to transport protocols, not firewall connection-state matches.
    if state is not None and state not in {name for names in STATES.values() for name in names}:
        raise OperationalError(f'Unknown connection state: {state}.')
    if state is not None and number is not None and state not in STATES.get(number, ()):
        raise OperationalError(f'State {state} is not valid for protocol {protocol}.')

    families = [family] if family else ['ipv4', 'ipv6']
    addresses = {}
    for field, value in (('source-address', source_address), ('destination-address', destination_address)):
        if value is None:
            continue
        try:
            address = ipaddress.ip_address(value)
            address_family = 'ipv' + str(address.version)
        except ValueError:
            raise OperationalError(f'Invalid IP address: {value}.') from None
        # Both tuple filters must belong to the selected family, or to the same inferred family.
        if address_family not in families:
            raise OperationalError('Address filters must use the same address family.')
        families = [address_family]
        addresses[field] = str(address)

    records = []
    try:
        for selected in families:
            native_family = socket.AF_INET if selected == 'ipv4' else socket.AF_INET6
            with closing(Conntrack(nfgen_family=native_family)) as client:
                client.register_policy({0x100: ConnectionMessage})
                arguments = {}
                if number is not None:
                    arguments['tuple_orig'] = NFCTAttrTuple(family=native_family, proto=number)
                for message in client.dump(**arguments):
                    record = normalize(message)
                    # Compare original addresses explicitly. Some kernels invert IPv6 tuple dump
                    # comparisons; local comparison also canonicalizes alternate IPv6 spellings.
                    if any(record['original'].get(field) != value for field, value in addresses.items()):
                        continue
                    if state is not None and record.get('state') != state:
                        continue
                    records.append(record)
    except (OSError, NetlinkError) as error:
        raise OperationalError(f'Cannot read connection tracking: {error}') from None
    return records


def statistics():
    """Combine per-CPU diagnostics; table occupancy is a separate global value."""
    try:
        with closing(Conntrack()) as client:
            current = client.count()
            maximum = client.conntrack_max_size()
            totals = {}
            for cpu in client.stat():
                for name, value in cpu.items():
                    if name != 'cpu':
                        totals[name] = totals.get(name, 0) + value
    except (OSError, NetlinkError) as error:
        raise OperationalError(f'Cannot read connection tracking statistics: {error}') from None

    return {'entries': current, 'maximum': maximum,
            'utilization': current * 100 / maximum if maximum else None, 'counters': totals}
