"""Reusable value validators, registered by schema name."""

from difflib import get_close_matches
from functools import lru_cache
import ipaddress
import re
import math
import shlex
import subprocess


TCP_FLAGS = {
    'fin': 0x01, 'syn': 0x02, 'rst': 0x04, 'psh': 0x08,
    'ack': 0x10, 'urg': 0x20, 'ecn': 0x40, 'cwr': 0x80,
}


DSCP_VALUES = {'be': 0, 'le': 1, 'va': 44, 'ef': 46}
for _class in range(8):
    DSCP_VALUES[f'cs{_class}'] = _class * 8
for _class in range(1, 5):
    for _drop in range(1, 4):
        DSCP_VALUES[f'af{_class}{_drop}'] = _class * 8 + _drop * 2


def tcp_flag_requirements(value):
    """Return (bits tested, bits required set) for one joined expression."""
    mask = 0
    required = 0
    for term in value.split(','):
        negative = term.startswith('not ')
        name = term[4:] if negative else term
        if name not in TCP_FLAGS:
            raise ValueError(f'Unknown TCP flag {name!r}')

        bit = TCP_FLAGS[name]
        if mask & bit:
            raise ValueError(f'TCP flag {name!r} is repeated or contradictory')
        mask |= bit
        if not negative:
            required |= bit

    return mask, required


def tcp_flags_mask(values):
    mask = 0
    for value in values:
        mask |= tcp_flag_requirements(value)[0]
    return mask


def tcp_flag_values(value, mask=255):
    """Expand unspecified bits within a lookup mask, at most 256 values."""
    tested, required = tcp_flag_requirements(value)
    return [bits for bits in range(256)
            if bits & mask == bits and bits & tested == required]


def tcp_flag_expression(mask, required):
    """Describe a native masked value using the same per-flag not grammar."""
    return ','.join(name if required & bit else 'not ' + name
                    for name, bit in TCP_FLAGS.items() if mask & bit)


def connection_quantity(value, kind):
    """Parse short connection-accounting units into the native integer."""
    units = {'': 1}
    maximum = (1 << 64) - 1
    if kind == 'bytes':
        units.update({'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3})
    elif kind == 'expiration':
        units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        maximum = 4294967
    elif kind != 'packets':
        raise ValueError('Unknown connection quantity')

    match = re.fullmatch(r'([0-9]+)([a-z]*)', value)
    if match is None or match[2] not in units:
        raise ValueError('Invalid connection quantity or unit')
    number = int(match[1]) * units[match[2]]
    if number > maximum:
        raise ValueError('Connection quantity exceeds native field capacity')
    return number


def connection_label_mask(value):
    """Label identifiers are bit positions, not the native mask value."""
    bits = 0
    for part in value.split(','):
        if not part.isascii() or not part.isdecimal() or not 0 <= int(part) <= 127:
            raise ValueError('Connection labels must be bit positions 0–127')
        bit = 1 << int(part)
        if bits & bit:
            raise ValueError('Repeated connection label')
        bits |= bit
    return bits


REGISTRY = {}
LABELS = {}
PREPARERS = {}


class ValidationFailure:
    """A false validator result carrying optional canonical spelling suggestions."""

    def __init__(self, *, suggestions=()):
        self.suggestions = tuple(suggestions)

    def __bool__(self):
        return False


LOG_FLAGS = {
    'tcp-sequence': 'tcp sequence', 'tcp-options': 'tcp options',
    'ip-options': 'ip options', 'skuid': 'skuid', 'ether': 'ether', 'all': 'all',
}


IP_PROTOCOLS = frozenset({
    'ip', 'icmp', 'igmp', 'ggp', 'ipencap', 'st', 'tcp',
    'egp', 'igp', 'pup', 'udp', 'hmp', 'xns-idp', 'rdp',
    'iso-tp4', 'dccp', 'xtp', 'ddp', 'idpr-cmtp', 'ipv6', 'ipv6-route',
    'ipv6-frag', 'idrp', 'rsvp', 'gre', 'esp', 'ah', 'skip',
    'ipv6-icmp', 'ipv6-nonxt', 'ipv6-opts', 'rspf', 'vmtp', 'eigrp', 'ospf',
    'ax.25', 'ipip', 'etherip', 'encap', 'pim', 'ipcomp', 'vrrp',
    'l2tp', 'isis', 'sctp', 'fc', 'mobility-header', 'udplite', 'mpls-in-ip',
    'manet', 'hip', 'shim6', 'wesp', 'rohc', 'ethernet',
})

# Supported nftables type names, wire values and assigned codes.
# Sources: https://www.iana.org/assignments/icmp-parameters/
#          https://www.iana.org/assignments/icmpv6-parameters/
# ICMPv6 MLDv2 report code is zero (RFC 9777, section 5.2).
ICMP_KEYMAP = {
    'ipv4': {
        'echo-reply': {'number': 0, 'codes': frozenset({0})},
        'destination-unreachable': {'number': 3, 'codes': frozenset(range(16))},
        'source-quench': {'number': 4, 'codes': frozenset({0})},
        'redirect': {'number': 5, 'codes': frozenset(range(4))},
        'echo-request': {'number': 8, 'codes': frozenset({0})},
        'router-advertisement': {'number': 9, 'codes': frozenset({0, 16})},
        'router-solicitation': {'number': 10, 'codes': frozenset({0})},
        'time-exceeded': {'number': 11, 'codes': frozenset({0, 1})},
        'parameter-problem': {'number': 12, 'codes': frozenset({0, 1, 2})},
        'timestamp-request': {'number': 13, 'codes': frozenset({0})},
        'timestamp-reply': {'number': 14, 'codes': frozenset({0})},
        'info-request': {'number': 15, 'codes': frozenset({0})},
        'info-reply': {'number': 16, 'codes': frozenset({0})},
        'address-mask-request': {'number': 17, 'codes': frozenset({0})},
        'address-mask-reply': {'number': 18, 'codes': frozenset({0})},
    },
    'ipv6': {
        'destination-unreachable': {'number': 1, 'codes': frozenset(range(10))},
        'packet-too-big': {'number': 2, 'codes': frozenset({0})},
        'time-exceeded': {'number': 3, 'codes': frozenset({0, 1})},
        'parameter-problem': {'number': 4, 'codes': frozenset(range(11))},
        'echo-request': {'number': 128, 'codes': frozenset({0})},
        'echo-reply': {'number': 129, 'codes': frozenset({0})},
        'mld-listener-query': {'number': 130, 'codes': frozenset({0})},
        'mld-listener-report': {'number': 131, 'codes': frozenset({0})},
        'mld-listener-done': {'number': 132, 'codes': frozenset({0})},
        'mld-listener-reduction': {'number': 132, 'codes': frozenset({0})},
        'nd-router-solicit': {'number': 133, 'codes': frozenset({0})},
        'nd-router-advert': {'number': 134, 'codes': frozenset({0})},
        'nd-neighbor-solicit': {'number': 135, 'codes': frozenset({0})},
        'nd-neighbor-advert': {'number': 136, 'codes': frozenset({0})},
        'nd-redirect': {'number': 137, 'codes': frozenset({0})},
        'router-renumbering': {'number': 138, 'codes': frozenset({0, 1, 255})},
        'ind-neighbor-solicit': {'number': 141, 'codes': frozenset({0})},
        'ind-neighbor-advert': {'number': 142, 'codes': frozenset({0})},
        'mld2-listener-report': {'number': 143, 'codes': frozenset({0})},
    },
}

ICMP_TYPES = {
    family: {name: entry['number'] for name, entry in types.items()}
    for family, types in ICMP_KEYMAP.items()
}


def register(name, label, *, prepare=None):
    """Register a validator and an operator-facing description once at import."""

    def decorate(function):
        REGISTRY[name] = function
        LABELS[name] = label

        if prepare is not None:
            PREPARERS[name] = prepare

        return function

    return decorate


DURATION_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
RATE_UNITS = {'s': 'second', 'm': 'minute', 'h': 'hour', 'd': 'day'}
BYTE_UNITS = {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}


def limit_amount(value):
    """Parse a validated packet count or compact byte quantity."""
    match = re.fullmatch(r'([0-9]+)([kmg])?', value)
    amount, unit = match.groups()
    return int(amount) * BYTE_UNITS[unit or '']


@register('geoip-country', 'an uppercase ISO country code, XK (Kosovo), or ZZ (unlocated/reserved)')
def geoip_country(value):
    from nvyr.helpers.geoip_config import COUNTRIES

    if value in COUNTRIES:
        return True

    # Two-letter typos could select a different country; suggest case fixes only.
    return ValidationFailure(suggestions=suggest_values(value, COUNTRIES, ignore_case=True, cutoff=1))


@register('quota-bytes', 'whole bytes with optional k, m or g suffix, from 0 through 9223372036854775807 bytes')
def quota_bytes(value):
    if re.fullmatch(r'[0-9]{1,19}[kmg]?', value) is None:
        return False
    return limit_amount(value) <= (1 << 63) - 1


@register('limit-rate', 'positive whole rate per s, m, h or d; packets: 10/s; bytes: optional k, m or g suffix, within kernel capacity')
def limit_rate(value, unit='packets'):
    parts = value.split('/')
    if len(parts) != 2 or parts[1] not in RATE_UNITS:
        return False
    pattern = r'[0-9]{1,20}[kmg]?' if unit == 'bytes' else r'[0-9]{1,10}'
    if re.fullmatch(pattern, parts[0]) is None:
        return False

    amount = limit_amount(parts[0])
    # Kernel byte buckets multiply their quantity by the period in nanoseconds.
    maximum = (2**64 - 1) // (DURATION_UNITS[parts[1]] * 10**9) if unit == 'bytes' else 2**32 - 1
    return 0 < amount <= maximum


@register('limit-burst', 'positive whole packet count or nonnegative bytes with optional k, m or g suffix (maximum 4294967295)')
def limit_burst(value, unit='packets'):
    pattern = r'[0-9]{1,10}[kmg]?' if unit == 'bytes' else r'[0-9]{1,10}'
    if re.fullmatch(pattern, value) is None:
        return False
    amount = limit_amount(value)
    return (0 if unit == 'bytes' else 1) <= amount <= 2**32 - 1


def duration_seconds(value):
    """Convert a schema-validated single-unit duration into whole seconds."""
    return int(value[:-1]) * DURATION_UNITS[value[-1]]


@register('kernel-duration', 'a whole duration in the supported units and kernel range')
def kernel_duration(value, minimum, maximum, milliseconds=False):
    """Validate kernel durations without losing subsecond ICMP rate intervals."""
    if len(value) > 32:
        return False
    pattern = r'[0-9]+(?:ms|[smhd])' if milliseconds else r'[0-9]+[smhd]'
    if re.fullmatch(pattern, value) is None:
        return False
    if value.endswith('ms'):
        amount = int(value[:-2])
    else:
        amount = duration_seconds(value) * (1000 if milliseconds else 1)
    return minimum <= amount <= maximum


@register('auto-integer', 'auto or a whole number in the supported range')
def auto_integer(value, minimum, maximum):
    """Capacity controls can restore their kernel-selected boot value."""
    return value == 'auto' or (len(value) <= 10 and value.isascii() and value.isdigit()
                               and minimum <= int(value) <= maximum)


@register('dhcp-domain', 'a DNS hostname or domain, without spaces or empty labels')
def dhcp_domain(value):
    name = value.removesuffix('.')
    return (0 < len(name) <= 253 and all(
        re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part)
        for part in name.split('.')))


@register('dns-name', 'an exact DNS hostname or domain, without wildcards or IP literals')
def dns_name(value):
    if not dhcp_domain(value):
        return False
    try:
        ipaddress.ip_address(value.removesuffix('.'))
    except ValueError:
        return True
    return False


@register('dhcp-identifier', 'colon-separated hexadecimal bytes within the identifier length limit')
def dhcp_identifier(value, minimum, maximum):
    return (bool(re.fullmatch(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*', value))
            and minimum <= len(value.split(':')) <= maximum)


@register('duration', 'positive duration in s, m, h or d, within the supported maximum')
def duration(value, maximum):
    if re.fullmatch(r'[0-9]+[smhd]', value) is None:
        return False

    try:
        seconds = duration_seconds(value)
    except ValueError:
        return False

    return 0 < seconds <= maximum


def prepare_regex(pattern):
    """Compile once when the schema loads; malformed patterns are schema errors."""
    if not isinstance(pattern, str):
        raise ValueError("Regex pattern must be a string")

    try:
        compiled = re.compile(pattern)
    except re.error as error:
        raise ValueError(f"Invalid regular expression: {error}") from error

    return lambda value: compiled.fullmatch(value) is not None


@register("regex", "a value matching the configured regular expression", prepare=prepare_regex)
def regex(value, pattern):
    return re.fullmatch(pattern, value) is not None


@register('as-path-sequence', 'a space-separated sequence of AS numbers from 1 to 4294967295')
def as_path_sequence(value):
    parts = value.split(' ')
    return bool(parts) and all(re.fullmatch(r'[0-9]{1,10}', part) and 1 <= int(part) <= 4294967295
                               for part in parts)


BGP_COMMUNITY_NAMES = {
    'graceful-shutdown': '65535:0', 'accept-own': '65535:1',
    'route-filter-translated-v4': '65535:2', 'route-filter-v4': '65535:3',
    'route-filter-translated-v6': '65535:4', 'route-filter-v6': '65535:5',
    'llgr-stale': '65535:6', 'no-llgr': '65535:7', 'accept-own-nexthop': '65535:8',
    'blackhole': '65535:666', 'no-export': '65535:65281',
    'no-advertise': '65535:65282', 'local-AS': '65535:65283', 'no-peer': '65535:65284',
}


@register('bgp-community', 'a valid BGP community or supported modifier')
def bgp_community(value, large=False, modifiers=True):
    if value in ('additive', 'none'):
        return modifiers
    if not large and value in BGP_COMMUNITY_NAMES:
        return True

    parts = value.split(':')
    maximum = 4294967295 if large else 65535
    if len(parts) == (3 if large else 2) and all(
            re.fullmatch(r'[0-9]{1,10}', part) and int(part) <= maximum for part in parts):
        return True

    choices = [] if large else list(BGP_COMMUNITY_NAMES)
    if modifiers:
        choices.extend(('additive', 'none'))

    return ValidationFailure(suggestions=suggest_values(
        value, choices, mangles=[['_', '-']], ignore_case=True,
    ))


@register('bgp-policy-adjustment', 'an unsigned value or signed adjustment through 4294967295')
def bgp_policy_adjustment(value, allow_zero_adjustment=True):
    if not re.fullmatch(r'[+-]?[0-9]{1,10}', value) or abs(int(value)) > 4294967295:
        return False
    return allow_zero_adjustment or value[0] not in '+-' or int(value) != 0


@register('bgp-policy-peer', 'a peer IP address, interface or peer-group name')
def bgp_policy_peer(value):
    try:
        address = ipaddress.ip_address(value)
        return not address.is_multicast and not address.is_unspecified
    except ValueError:
        return re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.:-]{0,127}', value) is not None


@register('frr-policy-regex', 'a valid single-line FRR regular expression')
@lru_cache(maxsize=1024)
def frr_policy_regex(value):
    if not value.strip() or value != value.strip() or any(not 32 <= ord(char) < 127 for char in value):
        return False

    # FRR uses POSIX ERE and expands underscores into AS-path boundaries.
    # Cache compilation across CLI entry and full configuration validation.
    expanded = value.replace('_', '(^|[,{}() ]|$)')
    result = subprocess.run(['grep', '-E', '--', expanded], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, env={'LC_ALL': 'C'}, timeout=5)
    if result.returncode not in (0, 1, 2):
        raise RuntimeError(f'Cannot validate FRR regular expression: {result.stderr.strip()}')
    return result.returncode in (0, 1)


@register('static-interface', 'an interface name (1-15 characters); Null0, blackhole and reject are reserved by FRR')
def static_interface(value):
    # FRR treats these identifiers as discard actions instead of interfaces.
    return (re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}', value) is not None
            and value.lower() not in {'null0', 'blackhole', 'reject'})


@register('frr-password', 'a secret without leading, trailing or repeated whitespace')
def frr_password(value):
    # FRR's LINE parser must preserve the exact authentication secret.
    return bool(value) and value == ' '.join(value.split())


def prepare_list(values, separator=None):
    if not isinstance(values, str) or not values.split():
        raise ValueError('List validator requires a nonempty space-separated values string')

    if separator is not None and (not isinstance(separator, str) or not separator):
        raise ValueError('List validator separator must be a nonempty string')

    permitted = frozenset(values.split())

    def validate(value):
        if separator is None:
            if value in permitted:
                return True
            items = [value]
        else:
            items = value.split(separator)
            if all(item in permitted for item in items):
                return True

        # Correct individual components, retaining valid parts of a joined value.
        corrected = []
        for item in items:
            if item in permitted:
                corrected.append(item)
                continue
            matches = suggest_values(item, permitted, ignore_case=True)
            if not matches:
                return ValidationFailure()
            corrected.append(matches[0])

        suggestion = separator.join(corrected) if separator is not None else corrected[0]
        return ValidationFailure(suggestions=[suggestion])

    return validate


@register('list', 'one of the configured permitted values', prepare=prepare_list)
def listed(value, values, separator=None):
    return prepare_list(values, separator)(value)


@register('ip-protocol', 'a supported IP protocol name (numeric values are not accepted)')
def ip_protocol(value):
    if value in IP_PROTOCOLS:
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, IP_PROTOCOLS, mangles=[['_', '-']], ignore_case=True,
    ))


@register('icmp-type', 'a supported IPv4 ICMP type name (numeric values are not accepted)')
def icmp_type(value):
    if value in ICMP_TYPES['ipv4']:
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, ICMP_TYPES['ipv4'], mangles=[['_', '-']], ignore_case=True,
    ))


@register('icmpv6-type', 'a supported IPv6 ICMP type name (numeric values are not accepted)')
def icmpv6_type(value):
    if value in ICMP_TYPES['ipv6']:
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, ICMP_TYPES['ipv6'], mangles=[['_', '-']], ignore_case=True,
    ))


def prepare_integer_range(minimum, maximum, allow_range=False):
    if type(minimum) is not int or type(maximum) is not int or minimum > maximum:
        raise ValueError('Integer range requires integer minimum <= maximum')

    if not allow_range:
        return lambda value: bool(re.fullmatch(r'-?[0-9]+', value)) and minimum <= int(value) <= maximum

    # Canonical decimal endpoints avoid nft interpreting leading zeros as octal.
    pattern = re.compile(r'(0|-?[1-9][0-9]*)(?:-(0|-?[1-9][0-9]*))?')

    def validate(value):
        match = pattern.fullmatch(value)
        if match is None:
            return False

        lower = int(match[1])
        upper = int(match[2]) if match[2] is not None else lower

        return minimum <= lower <= upper <= maximum

    return validate


@register('integer-range', 'an integer within the configured bounds, or an allowed ascending range', prepare=prepare_integer_range)
def integer_range(value, minimum, maximum, allow_range=False):
    return prepare_integer_range(minimum, maximum, allow_range)(value)


@register('firewall-mark', 'an unsigned 32-bit mark in decimal or hexadecimal (0x prefix)')
def firewall_mark(value):
    if re.fullmatch(r'0[xX][0-9a-fA-F]+', value):
        return int(value, 16) <= 4294967295
    return integer_range(value, 0, 4294967295)


@register('firewall-dscp', 'a DSCP name or decimal value from 0 to 63')
def firewall_dscp(value):
    return value in DSCP_VALUES or integer_range(value, 0, 63)


def prepare_integer_ranges(ranges):
    if not isinstance(ranges, list) or not ranges:
        raise ValueError('Integer ranges requires a nonempty list of [minimum, maximum] pairs')

    checks = []
    for bounds in ranges:
        if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
            raise ValueError('Each integer range must be a [minimum, maximum] pair')

        checks.append(prepare_integer_range(*bounds))

    return lambda value: any(check(value) for check in checks)


@register('integer-ranges', 'an integer in one of the configured inclusive ranges', prepare=prepare_integer_ranges)
def integer_ranges(value, ranges):
    return prepare_integer_ranges(ranges)(value)


def _ip_address(value, version=None):
    try:
        if '%' in value:
            return False

        parsed = ipaddress.ip_address(value)

        return version is None or parsed.version == version
    except ValueError:
        return False


@register('network', 'a network prefix of the configured address family, without host bits')
def network(value, version):
    try:
        return '/' in value and '%' not in value and ipaddress.ip_network(value, strict=True).version == version
    except ValueError:
        return False


@register('bgp-listen-prefix', 'an IPv4 or IPv6 network prefix without host bits')
def bgp_listen_prefix(value):
    if '/' not in value or '%' in value:
        return False

    try:
        ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False

    return True


@register('ip-range', 'an ascending IP address range of the configured address family')
def ip_range(value, version):
    try:
        if '%' in value:
            return False

        lower, upper = (ipaddress.ip_address(part) for part in value.split('-'))

        return lower.version == upper.version == version and int(lower) <= int(upper)
    except ValueError:
        return False


@register('mac', 'a MAC address (nonzero unicast unless unrestricted), such as 00:11:22:33:44:55')
def mac(value, unicast=True):
    return (bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value))
            and (not unicast or (value != '00:00:00:00:00:00' and not int(value[:2], 16) & 1)))


@register('mtu', 'an MTU from 1280 to 65535 bytes')
def mtu(value):
    return value.isascii() and value.isdecimal() and 1280 <= int(value) <= 65535


@register('interface-match', 'interface name or nonempty prefix followed by * (at most 15 name characters)')
def interface_match(value):
    """Allow nftables prefix matching, not shell glob expressions."""
    return re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}\*?', value) is not None


@register('interface-description', 'single-line interface alias of at most 255 UTF-8 bytes')
def interface_description(value):
    return text(value) and len(value.encode('utf-8')) <= 255


@register("address", "IPv4 or IPv6 interface prefix, such as 192.0.2.1/24 or 2001:db8::1/64")
def address(value, version=None):
    try:
        if '%' in value:
            return False

        parsed = ipaddress.ip_interface(value)

        return version is None or parsed.version == version
    except ValueError:
        return False


@register("ipv4-address", "IPv4 address, such as 192.0.2.1")
def ipv4_address(value):
    return _ip_address(value, 4)


@register('interface-ipv6-value', 'an IPv6 /64 prefix, interface identifier, or link-local address')
def interface_ipv6_value(value, kind):
    try:
        if kind == 'eui64':
            network = ipaddress.IPv6Network(value, strict=True)
            return network.prefixlen == 64 and not network.is_multicast and not network.is_link_local
        address = ipaddress.IPv6Address(value)
        if '%' in value:
            return False
        if kind == 'interface-identifier':
            return 0 < int(address) < 2**64
        return kind == 'link-local-address' and address.is_link_local
    except ValueError:
        return False


@register('ipv6-address', 'IPv6 address, such as 2001:db8::1')
def ipv6_address(value):
    return _ip_address(value, 6)


@register('ipv6-link-local-address', 'an IPv6 link-local address, such as fe80::1')
def ipv6_link_local_address(value):
    return _ip_address(value, 6) and ipaddress.IPv6Address(value).is_link_local


@register('ipv6-global-next-hop', 'a unicast non-link-local IPv6 next-hop address')
def ipv6_global_next_hop(value):
    if not _ip_address(value, 6):
        return False

    address = ipaddress.IPv6Address(value)
    return not (address.is_link_local or address.is_multicast or address.is_unspecified)


@register('dhcpv6-listen-address', 'a non-link-local unicast IPv6 listening address')
def dhcpv6_listen_address(value):
    if not _ip_address(value, 6):
        return False

    address = ipaddress.IPv6Address(value)
    return not (address.is_link_local or address.is_multicast or address.is_unspecified)


@register('inet-address', 'IPv4 or IPv6 address, such as 192.0.2.1 or 2001:db8::1')
def inet_address(value):
    return _ip_address(value)


@register('multicast-address', 'an IPv4 or IPv6 multicast address, such as 239.1.1.1 or ff3e::1')
def multicast_address(value):
    return _ip_address(value) and ipaddress.ip_address(value).is_multicast


@register('unicast-address', 'a nonzero unicast IPv4 or IPv6 address, such as 192.0.2.1 or 2001:db8::1')
def unicast_address(value):
    if not _ip_address(value):
        return False

    address = ipaddress.ip_address(value)
    return not address.is_multicast and not address.is_unspecified


@register('dhcp-ha-address', 'a unicast IPv4 or IPv6 HA address; IPv6 link-local addresses are not supported')
def dhcp_ha_address(value):
    if not unicast_address(value):
        return False

    address = ipaddress.ip_address(value)
    # Peer URLs have no interface scope selector for IPv6 link-local addresses.
    return value != '255.255.255.255' and not (address.version == 6 and address.is_link_local)


@register("ipv4-prefix", "IPv4 prefix, such as 192.0.2.1/24")
def ipv4_prefix(value):
    try:
        return "/" in value and bool(ipaddress.IPv4Interface(value))
    except ValueError:
        return False


@register("ipv6-prefix", "IPv6 prefix, such as 2001:db8::1/64")
def ipv6_prefix(value):
    try:
        return "/" in value and bool(ipaddress.IPv6Interface(value))
    except ValueError:
        return False


@register("nonnegative-integer", "whole number zero or greater")
def nonnegative_integer(value):
    return value.isascii() and value.isdecimal()


@register("positive-integer", "whole number greater than zero")
def positive_integer(value):
    return value.isascii() and value.isdecimal() and int(value) > 0


@register("port", "port number from 1 to 65535, or an allowed ascending port range")
def port(value, allow_range=False):
    bounds = value.split('-')
    if len(bounds) > (2 if allow_range else 1):
        return False

    numbers = []

    for part in bounds:
        if not part.isascii() or not part.isdecimal() or part.startswith('0'):
            return False

        number = int(part)
        if not 1 <= number <= 65535:
            return False

        numbers.append(number)

    return numbers[0] <= numbers[-1]


def prepare_length(maximum, minimum=0, unit='characters'):
    if (type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum
            or unit not in {'characters', 'utf8-bytes'}):
        raise ValueError('Length requires 0 <= minimum <= maximum and unit characters or utf8-bytes')

    return lambda value: minimum <= len(value.encode('utf-8') if unit == 'utf8-bytes' else value) <= maximum


@register('length', 'text within the configured length limit', prepare=prepare_length)
def length(value, maximum, minimum=0, unit='characters'):
    return prepare_length(maximum, minimum, unit)(value)


def prepare_byte_length(maximum, minimum=0):
    return prepare_length(maximum, minimum, unit='utf8-bytes')


@register('byte-length', 'text within the configured UTF-8 byte limit', prepare=prepare_byte_length)
def byte_length(value, maximum, minimum=0):
    return prepare_byte_length(maximum, minimum)(value)


@register("text", "nonempty single-line text without control characters")
def text(value):
    return bool(value) and all(ord(char) >= 32 and ord(char) != 127 for char in value)


def suggest_values(value, choices, *, mangles=(), ignore_case=False, limit=1, cutoff=0.8):
    """Rank canonical choices, applying ordered replacement pairs only to input.

    Case folding is a separate comparison option. Neither transformation changes
    the spelling returned to the caller or makes the entered value valid.
    """
    for old, new in mangles:
        value = value.replace(old, new)

    candidates = {}
    for choice in dict.fromkeys(choices):
        key = choice.casefold() if ignore_case else choice
        candidates.setdefault(key, []).append(choice)

    compared = value.casefold() if ignore_case else value
    matches = get_close_matches(compared, candidates, n=limit, cutoff=cutoff)
    suggestions = [choice for match in matches for choice in candidates[match]]
    return suggestions[:limit]


def failure_message(value, names, mode, suggestions=()):
    descriptions = [LABELS.get(name, "a supported value for this setting") for name in names]
    separator = " or " if mode == "OR" else " and "

    message = f"Invalid value {value!r}. Expected {separator.join(descriptions)}."
    if suggestions:
        alternatives = ', '.join(repr(choice) for choice in dict.fromkeys(suggestions))
        message += f' Did you mean {alternatives}?'
    return message


@register('log-flags', 'tcp-sequence, tcp-options, ip-options, skuid, ether or all; join with and')
def log_flags(value):
    flags = value.split(',')
    if all(flag in LOG_FLAGS for flag in flags):
        return len(flags) == len(set(flags))

    corrected = []
    for flag in flags:
        matches = suggest_values(flag, LOG_FLAGS, mangles=[['_', '-']], ignore_case=True)
        if not matches:
            return ValidationFailure()
        corrected.append(matches[0])

    if len(corrected) != len(set(corrected)):
        return ValidationFailure()

    return ValidationFailure(suggestions=[','.join(corrected)])


@register('tcp-flags', 'TCP flags fin, syn, rst, psh, ack, urg, ecn or cwr; join with and, optionally not; no repeated or contradictory flags')
def tcp_flags(value):
    try:
        tcp_flag_requirements(value)
    except ValueError:
        pass
    else:
        return True

    corrected = []
    for term in value.split(','):
        prefix = 'not ' if term.startswith('not ') else ''
        name = term[len(prefix):]
        matches = suggest_values(name, TCP_FLAGS, ignore_case=True)
        if not matches:
            return ValidationFailure()
        corrected.append(prefix + matches[0])

    suggestion = ','.join(corrected)
    # A spelling correction must not introduce repeated or contradictory flags.
    try:
        tcp_flag_requirements(suggestion)
    except ValueError:
        return ValidationFailure()

    return ValidationFailure(suggestions=[suggestion])


@register('connection-quantity', 'a nonnegative whole quantity; bytes allow k/m/g, durations require s/m/h/d, within native field capacity')
def valid_connection_quantity(value, kind):
    try:
        connection_quantity(value, kind)
    except ValueError:
        return False
    return True


@register('connection-label', 'distinct connection-label bit positions 0–127, joined with and')
def valid_connection_label(value):
    try:
        connection_label_mask(value)
    except ValueError:
        return False
    return True


CONTAINER_IMAGE = re.compile(r'(?:[a-zA-Z0-9.-]+(?::[0-9]{1,5})?/)?'
                             r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*'
                             r'(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*'
                             r'(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?'
                             r'(?:@sha256:[0-9a-f]{64})?')


def container_memory_bytes(value):
    if not re.fullmatch(r'[1-9][0-9]{0,18}[kmg]?', value):
        raise ValueError('Use positive bytes with an optional k, m or g suffix')

    suffix = value[-1]
    if suffix in 'kmg':
        return int(value[:-1]) * 1024 ** ('kmg'.index(suffix) + 1)

    return int(value)


def container_argument_words(value):
    return shlex.split(value, posix=True)


# Keep validation and completion descriptions together so every accepted capability has help.
CONTAINER_CAPABILITIES = {
    'audit-control': 'Configure kernel auditing and its filters',
    'audit-read': 'Read kernel audit events',
    'audit-write': 'Write records to the kernel audit log',
    'block-suspend': 'Prevent the system from suspending',
    'bpf': 'Perform privileged BPF operations',
    'checkpoint-restore': 'Perform privileged process checkpoint and restore operations',
    'chown': 'Change file owners and groups',
    'dac-override': 'Bypass file read, write and execute permission checks',
    'dac-read-search': 'Bypass file read and directory search permission checks',
    'fowner': 'Bypass checks requiring file ownership, such as chmod',
    'fsetid': 'Preserve setuid/setgid bits when modifying files',
    'ipc-lock': 'Lock memory and allocate huge pages',
    'ipc-owner': 'Bypass System V interprocess communication permission checks',
    'kill': 'Send signals to processes owned by other users',
    'lease': 'Establish file leases',
    'linux-immutable': 'Set or clear immutable and append-only file flags',
    'mac-admin': 'Configure mandatory access control policies (Smack)',
    'mac-override': 'Override mandatory access control checks (Smack)',
    'mknod': 'Create device files',
    'net-admin': 'Manage interfaces, routes, firewall rules and network settings',
    'net-bind-service': 'Bind to privileged network ports below 1024',
    'net-broadcast': 'Unused by the Linux kernel',
    'net-raw': 'Use raw IP and link-layer packet sockets',
    'perfmon': 'Perform privileged performance monitoring',
    'setfcap': 'Set file capabilities',
    'setgid': 'Change process group IDs and supplementary groups',
    'setpcap': 'Modify inheritable capabilities, capability bounds and securebits',
    'setuid': 'Change process user IDs',
    'sys-admin': 'Perform broad system administration, including mounts and namespaces',
    'sys-boot': 'Reboot the system or load a kernel with kexec',
    'sys-chroot': 'Change the process root directory with chroot',
    'sys-module': 'Load and unload kernel modules',
    'sys-nice': 'Change process priorities, scheduling and CPU affinity',
    'sys-pacct': 'Enable or disable process accounting',
    'sys-ptrace': 'Trace other processes and inspect or modify their memory',
    'sys-rawio': 'Access hardware I/O ports and physical memory',
    'sys-resource': 'Raise resource limits and override certain quotas',
    'sys-time': 'Set the system and hardware clocks',
    'sys-tty-config': 'Perform privileged virtual terminal operations',
    'syslog': 'Access privileged kernel logs and exposed kernel addresses',
    'wake-alarm': 'Set timers that wake the system from suspend',
}


@register('container-network-name', '1-12 ASCII letters, digits, underscores or hyphens, starting with a letter or digit; Podman network mode names are reserved')
def container_network_name(value):
    # These names select native modes instead of a named bridge attachment.
    reserved = {'bridge', 'host', 'none', 'private', 'slirp4netns', 'pasta', 'default'}
    return value not in reserved and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,11}', value) is not None


@register('container-name', '1-10 ASCII letters, digits, underscores or hyphens, starting with a letter or digit; pod is reserved')
def container_name(value):
    # The pod keyword selects pod-wide operational commands.
    return value != 'pod' and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,9}', value) is not None


@register('container-subnet', 'an IPv4 or IPv6 network prefix without host bits, with at least four addresses for a gateway and clients')
def container_subnet(value):
    if '/' not in value or '%' in value:
        return False

    try:
        subnet = ipaddress.ip_network(value)
    except ValueError:
        return False

    return subnet.num_addresses >= 4


@register('container-capability', 'none or a Linux capability such as net-admin or net-raw')
def container_capability(value):
    if value == 'none' or value in CONTAINER_CAPABILITIES:
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, ['none', *CONTAINER_CAPABILITIES], mangles=[['_', '-']], ignore_case=True,
    ))


@register('container-device', 'a device path beneath /dev without traversal')
def container_device(value):
    return value.startswith('/dev/') and container_source(value[5:])


@register('container-tmpfs-size', 'positive bytes through 1 TiB, with optional k, m or g suffix')
def container_tmpfs_size(value):
    try:
        return 1 <= container_memory_bytes(value) <= 1024**4
    except ValueError:
        return False


@register('container-image', 'a container image name with optional registry, tag or sha256 digest')
def container_image(value):
    return CONTAINER_IMAGE.fullmatch(value) is not None


@register('container-registry', 'a registry hostname or IPv4 address, optionally followed by :port')
def container_registry(value):
    host, separator, port = value.partition(':')
    if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', host):
        return False

    return not separator or (1 <= len(port) <= 5 and port.isascii() and port.isdigit()
                             and 1 <= int(port) <= 65535)


@register('container-source', 'a relative directory below /config/containers, without traversal')
def container_source(value):
    parts = value.split('/')
    return bool(value) and all(re.fullmatch(r'[a-zA-Z0-9_.-]+', part)
                               and part not in ('.', '..') for part in parts)


@register('container-destination', 'an absolute container directory without traversal')
def container_destination(value):
    return value.startswith('/') and value != '/' and container_source(value[1:])


@register('container-arguments', 'a single-line argument string with balanced shell-style quotes')
def container_arguments(value):
    try:
        container_argument_words(value)
    except ValueError:
        return False
    return text(value)


@register('container-entrypoint', 'quoted entrypoint arguments, or an empty string to clear the image entrypoint')
def container_entrypoint(value):
    return value == '' or container_arguments(value)


@register('container-memory', 'memory from 6 MiB through 1 TiB, with optional k, m or g suffix')
def container_memory(value):
    try:
        return 6 * 1024**2 <= container_memory_bytes(value) <= 1024**4
    except ValueError:
        return False


@register('container-cpus', 'CPU allowance from 0.01 through 1024')
def container_cpus(value):
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]{1,2})?', value):
        return False
    number = float(value)
    return math.isfinite(number) and 0.01 <= number <= 1024


@register('bgp-neighbor', 'a unicast IPv4/IPv6 address or an interface name for an unnumbered peer')
def bgp_neighbor(value):
    return bgp_update_source(value)


@register('bgp-remote-as', 'an AS number from 1 to 4294967295, internal, external or auto')
def bgp_remote_as(value):
    choices = ('internal', 'external', 'auto')
    if value in choices or (value.isdecimal() and 1 <= int(value) <= 4294967295):
        return True

    return ValidationFailure(suggestions=suggest_values(value, choices, ignore_case=True))


def bgp_address(value):
    """Validate an address independently of interface-neighbor syntax."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (not address.is_unspecified and not address.is_multicast
            and value != '255.255.255.255' and '%' not in value)


@register('bgp-router-id', 'a nonzero unicast IPv4 router identifier')
def bgp_router_id(value):
    return ipv4_address(value) and bgp_address(value)


@register('bgp-update-source', 'an interface name or unicast IPv4/IPv6 address')
def bgp_update_source(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,14}', value))
    return bgp_address(value)


@register('cpu-policy', 'a CPU policy value supported by this system')
def cpu_policy(value, setting):
    from nvyr.helpers import cpu_settings

    choices = cpu_settings.available(setting)
    if value in choices:
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, choices, mangles=[['_', '-']], ignore_case=True,
    ))


@register('time-zone', 'an installed IANA time zone, such as America/New_York or UTC')
def time_zone(value):
    from nvyr.helpers import timezones

    if timezones.valid_name(value):
        return True

    return ValidationFailure(suggestions=suggest_values(
        value, timezones.available(), mangles=[['-', '_']], ignore_case=True,
    ))
