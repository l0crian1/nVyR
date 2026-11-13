"""Linux MPLS sysctls. Called only by the serialized netlink daemon."""

from pathlib import Path

from nvyr.errors import ValidationError
from nvyr.helpers.netlink import interface_name


ROOT = Path('/proc/sys/net/mpls')


def validate(values):
    # The root-only RPC still checks its envelope before constructing sysctl paths.
    if (not isinstance(values, dict) or not {'interfaces', 'label-table-size'} <= values.keys()
            or values.keys() - {'interfaces', 'label-table-size', 'ip-ttl-propagate', 'default-ttl'}):
        raise ValidationError('MPLS settings require interfaces and label-table-size')
    names = values['interfaces']
    if not isinstance(names, list) or any(not isinstance(name, str) or not interface_name(name) for name in names):
        raise ValidationError('MPLS interfaces must be valid interface names')
    capacity = values['label-table-size']
    if type(capacity) is not int or not 0 <= capacity <= 1048575:
        raise ValidationError('MPLS label-table-size must be between 0 and 1048575')
    for name, lower, upper, default in (('ip-ttl-propagate', 0, 1, 1), ('default-ttl', 1, 255, 255)):
        value = values.get(name, default)
        if type(value) is not int or not lower <= value <= upper:
            raise ValidationError(f'MPLS {name} must be between {lower} and {upper}')


def write(path, value):
    if path.read_text().strip() != str(value):
        path.write_text(str(value))


def apply(values, previous=()):
    """Missing links remain desired and receive input=1 when RTNL announces them."""
    names = set(values['interfaces'])
    capacity = values['label-table-size']
    table = ROOT / 'platform_labels'
    if not table.exists() and not capacity and not previous:
        return

    # Grow before enabling inputs; disable removed inputs before shrinking the table.
    current = int(table.read_text())
    if capacity > current:
        write(table, capacity)
    write(ROOT / 'ip_ttl_propagate', values.get('ip-ttl-propagate', 1))
    write(ROOT / 'default_ttl', values.get('default-ttl', 255))
    for name in sorted(names | set(previous)):
        path = ROOT / 'conf' / name / 'input'
        if path.exists():
            write(path, int(name in names))
    if capacity < current:
        write(table, capacity)
