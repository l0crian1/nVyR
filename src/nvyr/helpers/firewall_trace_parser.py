"""Decode native trace evidence without interpreting expressions as matched fields.

Only packet events describe observed packet values. Rule text describes the rule
being evaluated, and can contain addresses which never existed in the packet.
Unknown fields stay in the native event instead of being guessed.
"""

import re
import shlex

from nvyr.helpers.validators import TCP_FLAGS


PROTOCOLS = {'1': 'icmp', '6': 'tcp', '17': 'udp', '33': 'dccp', '58': 'ipv6-icmp',
             '132': 'sctp', '136': 'udplite'}
FIELDS = {
    'iif': 'inbound-interface', 'oif': 'outbound-interface',
    'iifname': 'inbound-interface', 'oifname': 'outbound-interface',
    'sdif': 'slave-interface', 'sdifname': 'slave-interface',
    'mark': 'mark', 'nfproto': 'family',
    'ether saddr': 'source-mac', 'ether daddr': 'destination-mac',
    'ether type': 'ether-type', 'vlan id': 'vlan-id',
}
for header in ('ip', 'ip6'):
    for native, name in (('saddr', 'source-address'), ('daddr', 'destination-address'),
                         ('ttl', 'ttl'), ('hoplimit', 'hop-limit'), ('length', 'length'),
                         ('dscp', 'dscp'), ('ecn', 'ecn'), ('id', 'ip-id'),
                         ('flowlabel', 'flow-label'), ('protocol', 'protocol'), ('nexthdr', 'next-header')):
        FIELDS[f'{header} {native}'] = name
for header in ('tcp', 'udp', 'udplite', 'sctp', 'dccp'):
    for native, name in (('sport', 'source-port'), ('dport', 'destination-port'),
                         ('flags', 'tcp-flags'), ('window', 'tcp-window')):
        FIELDS[f'{header} {native}'] = name
for header in ('icmp', 'icmpv6'):
    for native in ('type', 'code', 'id', 'sequence'):
        FIELDS[f'{header} {native}'] = 'icmp-' + native

VERDICT = re.compile(r'\(verdict ([^)]+)\)\s*$')
HANDLE = re.compile(r'# handle (\d+)(?:\s+\(verdict [^)]+\))?\s*$')
CT_FIELDS = re.compile(r'\bct (direction|state|status|id|zone|mark) ([^ ]+)')
CT_STATES = {1: 'invalid', 2: 'established', 4: 'related', 8: 'new', 64: 'untracked'}
CT_STATUS = ('expected', 'seen-reply', 'assured', 'confirmed', 'snat', 'dnat', 'seq-adjust',
             'snat-done', 'dnat-done', 'dying', 'fixed-timeout', 'template', 'untracked',
             'helper', 'offload', 'hw-offload')


def packet_fields(text):
    """Read IPv4/IPv6 and transport observations, retaining numeric native values."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return {}

    fields = {}
    index = 0
    while index < len(tokens):
        pair = ' '.join(tokens[index:index + 2])
        key = pair if pair in FIELDS else tokens[index]
        width = 2 if pair in FIELDS else 1
        value_index = index + width
        if key not in FIELDS or value_index >= len(tokens):
            index += 1
            continue

        # Some native printers include an equality token before flags.
        if tokens[value_index] == '==':
            value_index += 1
        if value_index >= len(tokens):
            break
        value = tokens[value_index]
        if value == '{':
            end = value_index + 1
            while end < len(tokens) and tokens[end] != '}':
                end += 1
            value = ' '.join(tokens[value_index + 1:end])
            value_index = min(end, len(tokens) - 1)
        fields[FIELDS[key]] = value

        header = key.split()[0]
        if header in ('ip', 'ip6'):
            fields['family'] = 'ipv4' if header == 'ip' else 'ipv6'
        if header in ('tcp', 'udp', 'udplite', 'sctp', 'dccp', 'icmp', 'icmpv6'):
            fields['protocol'] = 'ipv6-icmp' if header == 'icmpv6' else header
        index = value_index + 1

    protocol = fields.get('protocol', fields.get('next-header'))
    if protocol is not None:
        fields['protocol'] = PROTOCOLS.get(protocol, protocol)
    flags = fields.get('tcp-flags', '')
    if flags.startswith('0x') or flags.isdecimal():
        number = int(flags, 0) if flags.startswith('0x') else int(flags)
        fields['tcp-flags-value'] = flags
        fields['tcp-flags'] = ', '.join(name for name, bit in TCP_FLAGS.items() if number & bit) or 'none'
    return fields


def _bits(value, names):
    """Decode numeric flag lists and retain unknown bits instead of discarding them."""
    result = []
    for word in value.split(','):
        try:
            number = int(word, 0)
        except ValueError:
            result.append(word)
            continue
        for bit, name in names.items():
            if number & bit:
                result.append(name)
                number &= ~bit
        if number:
            result.append(hex(number))
    return result


def connection_fields(text):
    """Decode the conntrack observations added to recent native trace output."""
    fields = dict(CT_FIELDS.findall(text))
    if 'direction' in fields:
        fields['direction'] = {'0': 'original', '1': 'reply'}.get(fields['direction'], fields['direction'])
    if 'state' in fields:
        fields['state'] = _bits(fields['state'], CT_STATES)
    if 'status' in fields:
        fields['status'] = _bits(fields['status'], {1 << bit: name for bit, name in enumerate(CT_STATUS)})
    return fields


def event_fields(kind, detail):
    """Extract actual verdicts separately from conditional rule expressions."""
    if kind == 'packet':
        return {'packet': packet_fields(detail)}
    if kind == 'conntrack':
        return {'connection': connection_fields(detail)}

    fields = {}
    match = VERDICT.search(detail)
    if match:
        fields['verdict'] = match[1]
    elif kind in ('policy', 'verdict'):
        fields['verdict'] = detail.strip()
    handle = HANDLE.search(detail)
    if handle:
        fields['handle'] = int(handle[1])
    if kind == 'rule':
        expression = VERDICT.sub('', detail).strip()
        expression = re.sub(r'\s+# handle \d+\s*$', '', expression)
        expression = re.sub(r'\s+comment "(?:[^"\\]|\\.)*"\s*$', '', expression)
        fields['expression'] = expression
    return fields
