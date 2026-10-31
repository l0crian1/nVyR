"""Display-only masking shared by configuration and operational commands."""

from ipaddress import ip_interface


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
        # Fixed boundaries retain useful topology hints without exposing host bits.
        if address.version == 4:
            masked = '.'.join(str(address.ip).split('.')[:2]) + '.xxx.xxx'
        else:
            # packed excludes any scope identifier and handles compressed addresses.
            hextets = [int.from_bytes(address.ip.packed[offset:offset + 2], 'big') for offset in (0, 2)]
            masked = ':'.join(f'{part:x}' for part in hextets) + ':x:x:x:x:x:x'

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
            return ':'.join(parts[:3]) + ':xx:xx:xx'
    return '<mac>' if strip_private else value


def strip_password(value, strip_private=False):
    return '<password>' if strip_private else value


def strip_value(value, strip_private=False):
    """Mask other sensitive values, including names and free-form descriptions."""
    return '<private>' if strip_private and strip_private != 'public' else value


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
        kind = node.get('strip_kind')
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
