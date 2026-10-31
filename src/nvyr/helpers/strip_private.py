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
            left, right = strip_ip(start, True), strip_ip(end, True)
            if left == right and left in {'<ipv4>', '<ipv6>'}:
                return left

        return value

    return f'<ipv{address.version}>'


def strip_ipv4(value, strip_private=False):
    masked = strip_ip(value, strip_private)
    return masked if masked == '<ipv4>' else value


def strip_ipv6(value, strip_private=False):
    masked = strip_ip(value, strip_private)
    return masked if masked == '<ipv6>' else value


def strip_mac(value, strip_private=False):
    return '<mac>' if strip_private else value


def strip_password(value, strip_private=False):
    return '<password>' if strip_private else value


def strip_value(value, strip_private=False):
    """Mask other sensitive values, including names and free-form descriptions."""
    return '<private>' if strip_private else value


KINDS = {'ipv4': strip_ipv4, 'ipv6': strip_ipv6, 'ip': strip_ip,
         'mac': strip_mac, 'password': strip_password, 'private': strip_value}


class ConfigurationMasker:
    """Copy schema-marked values, with aliases local to a single display.

    Distinct values must stay distinct: otherwise masked tag keys collide and
    comparisons silently lose changes. Aliases contain no hashes or source data.
    Reuse one instance for both sides of a diff and its selected scope.
    """

    def __init__(self, schema):
        self.schema = schema
        self.aliases = {}

    def value(self, node, value):
        kind = node.get('strip_kind')
        if kind is None:
            return value

        masked = KINDS[kind](value, True)
        if masked == value:
            return value

        key = (masked, value)
        if key not in self.aliases:
            self.aliases[key] = f'{masked[:-1]}-{len(self.aliases) + 1}>'

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
