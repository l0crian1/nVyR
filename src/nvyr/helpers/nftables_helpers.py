"""Explicit standard-port conntrack helpers and their shared object map."""

from nvyr.errors import ValidationError
from nvyr.tree import lookup


HELPERS = {'ftp': (('tcp', 21),), 'tftp': (('udp', 69),),
           'sip': (('tcp', 5060), ('udp', 5060))}
HOOKS = ('input', 'forward', 'output')
MAP_NAME = 'conntrack_helpers'
PATH = ('firewall', 'global-options', 'connection-tracking', 'helper')


def configured(firewall):
    """Return enabled applications without depending on kernel-setting defaults."""
    return lookup(firewall, PATH[1:], {})


def objects(firewall):
    """Index native helper objects by application, transport and standard port."""
    result = {}
    for helper in configured(firewall):
        for protocol, port in HELPERS[helper]:
            result[f'conntrack_helper_{helper}_{protocol}'] = (helper, protocol, port)
    return result


def verify(options):
    """Require an explicit nonempty selection of supported application helpers."""
    # An empty parent has no assignment behavior and usually indicates an incomplete command.
    if not options:
        raise ValidationError('firewall global-options connection-tracking helper: select at least one helper')

    for helper, enabled in options.items():
        # Native helper names and ports come only from the supported application catalog.
        if helper not in HELPERS or enabled is not True:
            raise ValidationError(f'firewall global-options connection-tracking helper: invalid helper {helper!r}')


def render_objects(firewall, rebuild):
    """Declare selected dual-family helpers before the map that references them."""
    definitions = objects(firewall)
    lines = []
    for name, (helper, protocol, _) in definitions.items():
        if ('ct helper', name) in rebuild:
            lines.append(f'ct helper {name} {{\n    type "{helper}" protocol {protocol}\n    l3proto inet\n}}')

    if definitions and ('map', MAP_NAME) in rebuild:
        entries = [f'{protocol} . {port} : "{name}"'
                   for name, (_, protocol, port) in definitions.items()]
        # Object-reference maps require typeof; ordinary typed data maps do not.
        lines.append(f'map {MAP_NAME} {{\n    typeof meta l4proto . th dport : ct helper\n'
                     '    elements = { ' + ', '.join(entries) + ' }\n}')
    return '\n\n'.join(lines)


def assignment(firewall, entrypoint):
    """Assign only new original-direction connections, then continue rule evaluation."""
    if entrypoint not in HOOKS or not configured(firewall):
        return ''
    return ('ct state new ct direction original meta l4proto { tcp, udp } '
            f'ct helper set meta l4proto . th dport map @{MAP_NAME} '
            'comment "global-helpers|Connection helper assignment"')
