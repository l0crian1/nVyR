"""Display-only masking shared by configuration and operational commands."""

from ipaddress import ip_address, ip_interface
import re


def strip_ip(value, strip_private=False):
    """Mask an IPv4/IPv6 address or prefix; retain non-address choices like dhcp."""
    if not strip_private:
        return value

    try:
        address = ip_interface(value)
    except ValueError:
        # NAT pools can be expressed as an inclusive address range.
        if isinstance(value, str) and value.count('-') == 1:
            start, end = value.split('-')
            left, right = strip_ip(start, strip_private), strip_ip(end, strip_private)
            if strip_private == 'partial' and left != start and right != end:
                return f'{left}-{right}'
            if left == right and left in {'<ipv4>', '<ipv6>'}:
                return left
            if strip_private == 'public':
                for masked in (left, right):
                    if masked in {'<ipv4>', '<ipv6>'}:
                        return masked

        return value

    if strip_private == 'public' and (not address.ip.is_global or address.ip.is_multicast):
        return value

    if strip_private == 'partial':
        if address.version == 4:
            masked = 'xxx.xxx.' + '.'.join(str(address.ip).split('.')[2:])
        else:
            # Read the final two hextets regardless of compression or scope identifier.
            packed = address.ip.packed
            high = int.from_bytes(packed[-4:-2], 'big')
            low = int.from_bytes(packed[-2:], 'big')
            # The last 32 bits of a mapped address contain the entire IPv4 address.
            suffix = 'x' if address.ip.ipv4_mapped else f'{high:x}'
            masked = f'x:x:x:x:x:x:{suffix}:{low:x}'

        if '/' in value:
            masked += f'/{address.network.prefixlen}'
        return masked

    return f'<ipv{address.version}>'


def strip_ipv4(value, strip_private=False):
    return strip_ip(value, strip_private) if ':' not in value else value


def strip_ipv6(value, strip_private=False):
    return strip_ip(value, strip_private) if ':' in value else value


def strip_mac(value, strip_private=False):
    if strip_private == 'public':
        return value
    if strip_private == 'partial':
        parts = value.split(':')
        if len(parts) == 6 and all(len(part) == 2 and all(char in '0123456789abcdefABCDEF' for char in part)
                                   for part in parts):
            return 'xx:xx:xx:xx:' + ':'.join(parts[-2:])
    return '<mac>' if strip_private else value


def strip_password(value, strip_private=False):
    return '<password>' if strip_private else value


def strip_value(value, strip_private=False):
    """Mask other sensitive values, including names and free-form descriptions."""
    return '<private>' if strip_private and strip_private != 'public' else value


# Match candidates, then validate them. Keep endpoint ports, CIDR lengths and
# interface scopes outside the replacement so native column offsets stay intact.
_ADDRESS = re.compile(
    # An FRR BGP row can put its three status flags directly against the prefix.
    r'(?:(?<![\w.])|(?<=^[* ][> =]i))(?:'
    r'(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}'
    r'|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}'
    r'|(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    r'|[0-9a-fA-F]{0,4}:[0-9a-fA-F:]+(?:\.[0-9]{1,3}){0,3}'
    r')(?!\w|\.\w)', re.MULTILINE
)
_MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
_DOTTED_MAC = re.compile(r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}')
_HEX = re.compile('[0-9a-fA-F]')
_ETH_HEADER = re.compile(r'(\bMAC=)((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}):'
                         r'((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})(?=:[0-9a-fA-F]{2}:)')


def _mask_literal(token, mode):
    if _MAC.fullmatch(token.replace('-', ':')) or _DOTTED_MAC.fullmatch(token):
        if mode == 'public':
            return token
        keep = token.rfind('.') if '.' in token else 11
        if mode != 'partial':
            keep = len(token)
        return _HEX.sub('x', token[:keep]) + token[keep:]

    try:
        address = ip_address(token)
    except ValueError:
        return token
    if mode == 'public' and (not address.is_global or address.is_multicast):
        return token
    if mode != 'partial':
        return _HEX.sub('x', token) if token != '::' else 'xx'
    if address.version == 4:
        first, second, rest = token.split('.', 2)
        return 'x' * len(first) + '.' + 'x' * len(second) + '.' + rest

    # The last two logical hextets may be dotted, explicit or compressed.
    parts = token.split(':')
    tail = 1 if address.ipv4_mapped or '.' in parts[-1] else 2
    if address.ipv4_mapped and '.' in parts[-1]:
        parts[-1] = _mask_literal(parts[-1], mode)
    explicit = len(token.partition('::')[2].split(':')) if '::' in token else 8
    visible = min(tail, explicit) if not token.endswith('::') else 0
    return ':'.join(_HEX.sub('x', part) if i < len(parts) - visible else part
                    for i, part in enumerate(parts))


def strip_text(text, mode):
    """Mask address literals in opaque text, retaining their original width."""
    if not mode:
        return text

    def replace(match):
        token = match[0]
        if token.endswith(':') and not token.endswith('::'):
            return _mask_literal(token[:-1], mode) + ':'
        return _mask_literal(token, mode)

    if mode != 'public' and 'MAC=' in text:
        # Kernel packet logs can print the whole Ethernet header after MAC=.
        text = _ETH_HEADER.sub(lambda m: m[1] + _mask_literal(m[2], mode) + ':' + _mask_literal(m[3], mode), text)
    return _ADDRESS.sub(replace, text)


def mask_fields(data, mode, fields, *, fallback=None, mask_keys=False):
    """Copy structured display data, applying a formatter to named fields."""
    def visit(value, formatter):
        if isinstance(value, dict):
            result = {}
            next_suffix = {}
            for key, item in value.items():
                label = strip_text(key, mode) if mask_keys else key
                if label != key and (label in result or label in value):
                    base = label
                    index = next_suffix.get(base, 1)
                    while label in result or label in value:
                        label = f'{base} <{index}>'
                        index += 1
                    next_suffix[base] = index
                result[label] = visit(item, fields.get(key, formatter))
            return result
        if isinstance(value, list):
            return [visit(item, formatter) for item in value]
        if formatter and isinstance(value, str) and value:
            return formatter(value, mode)
        return value

    return visit(data, fallback) if mode else data


KINDS = {'ipv4': strip_ipv4, 'ipv6': strip_ipv6, 'ip': strip_ip,
         'mac': strip_mac, 'password': strip_password, 'private': strip_value}


class ConfigurationMasker:
    """Copy schema-marked values, with aliases local to a single display.

    Distinct values must stay distinct: otherwise masked tag keys collide and
    comparisons silently lose changes. Alias suffixes contain no hashes or source data.
    Reuse one instance for both sides of a diff and its selected scope.
    """

    def __init__(self, schema, mode='all'):
        self.schema = schema
        self.mode = mode
        self.aliases = {}

    def value(self, node, value):
        kind = 'password' if node.get('secret') else node.get('strip_kind')
        if kind is None:
            return value

        masked = KINDS[kind](value, self.mode)
        if masked == value:
            return value

        key = (masked, value)
        if key not in self.aliases:
            identifier = len(self.aliases) + 1
            # Partial addresses can collide too; keep distinct keys and diff values.
            self.aliases[key] = (f'{masked[:-1]}-{identifier}>' if masked.startswith('<')
                                 else f'{masked} <private-{identifier}>')

        return self.aliases[key]

    def tree(self, tree, node=None):
        node = self.schema.root if node is None else node
        if node['kind'] == 'leaf_node':
            if node.get('valueless'):
                return tree

            return ([self.value(node, value) for value in tree] if node.get('multi')
                    else self.value(node, tree))

        if node['kind'] == 'tag_node':
            instance = {'kind': 'node', 'children': node.get('children', {})}
            return {self.value(node, key): self.tree(value, instance) for key, value in tree.items()}

        return {key: self.tree(value, node['children'][key]) for key, value in tree.items()}

    def path(self, path):
        node = self.schema.root
        result = []
        tag = False

        for word in path:
            if tag:
                result.append(self.value(node, word))
                tag = False
            else:
                node = node['children'][word]
                result.append(word)
                tag = node['kind'] == 'tag_node'

        return tuple(result)
