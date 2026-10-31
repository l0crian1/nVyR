"""Generate boot defaults and CLI declarations from the kernel-settings keymap."""

import argparse
from pathlib import Path
import runpy
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
KEYMAP = runpy.run_path(str(ROOT / 'src/nvyr/helpers/kernel_settings_map.py'))
SETTINGS = KEYMAP['SETTINGS']
CHOICES = {
    'enable': 'Enable this behavior', 'disable': 'Disable this behavior',
    'auto': 'Use automatic kernel sizing or allocation',
    'routing-header-2': 'Accept only IPv6 routing header type 2',
    'any': 'Allow any local source address (mode 0)',
    'subnet': 'Prefer a source in the destination subnet (mode 1)',
    'best-local': 'Use the best local address for the target (mode 2)',
    'same-subnet': 'Accept new gratuitous ARP entries only from the same subnet',
    'none': 'Do not log invalid connections', 'all': 'Log all invalid protocols',
    'icmp': 'IPv4 ICMP', 'icmpv6': 'IPv6 ICMP', 'tcp': 'TCP',
    'udp': 'UDP', 'udplite': 'UDP-Lite',
    **KEYMAP['ARP_IGNORE_CHOICES'],
    'eui64': 'Generate addresses from the interface MAC using modified EUI-64',
    'stable-privacy': 'Generate stable addresses with a persistent private secret',
    'prefer-public': 'Generate temporary addresses but prefer public source addresses',
    'prefer-temporary': 'Generate and prefer temporary source addresses',
}
NODE_DESCRIPTIONS = {
    'ip': 'IPv4 settings for this interface',
    'ipv4': 'IPv4 kernel settings',
    'ipv6': 'IPv6 kernel settings',
    'arp': 'ARP kernel settings',
    'tcp': 'TCP kernel settings',
    'udp': 'UDP kernel settings',
    'sctp': 'SCTP kernel settings',
    'gre': 'GRE kernel settings',
    'icmp-rate-limit': 'ICMP response rate limiting',
    'timeout': 'Connection tracking timeouts by protocol and state',
    'flowtable-timeout': 'Idle timeouts for offloaded flows',
    'duplicate-address-detection': 'IPv6 duplicate address detection',
}


def schema(*, interface=False):
    """The schema declares validation/defaults, not kernel execution metadata."""
    result = {}
    declarations = ((name.split(), spec) for name, spec in SETTINGS.items() if spec['owner'] == 'firewall')
    if interface:
        declarations = ((path, SETTINGS[name]) for path, name in KEYMAP['INTERFACE_SETTINGS'].items())
    for parts, spec in declarations:
        children = result
        for part in parts[:-1]:
            description = NODE_DESCRIPTIONS.get(part)
            if description is None:
                description = part.replace('-', ' ').capitalize() + ' kernel settings'

            node = children.setdefault(part, {
                'kind': 'node', 'anchor': True,
                'description': description,
                'children': {},
            })
            children = node['children']

        leaf = {'kind': 'leaf_node', 'description': spec['description']}
        if interface and spec['owner'] == 'firewall':
            leaf['description'] = spec['description'].replace('; inherited by interfaces', '') + '; inherits firewall global setting'
        kind = spec['kind']
        if kind == 'presence':
            leaf['valueless'] = True
        else:
            # Global settings apply whenever firewall exists, even without their parent nodes.
            if not interface:
                leaf['default'] = {'mode': 'always', 'value': spec['default']}
            if kind == 'choice':
                leaf['choices'] = {value: CHOICES[value] for value in spec['values']}
                leaf['validators'] = {'list': {'values': ' '.join(spec['values'])}}
            elif kind in ('milliseconds', 'seconds'):
                leaf['validators'] = {'kernel-duration': {
                    'milliseconds': kind == 'milliseconds',
                    'minimum': spec['minimum'], 'maximum': spec['maximum'],
                }}
                units = 'ms, s, m, h or d' if kind == 'milliseconds' else 's, m, h or d'
                leaf['hints'] = {'duration': f'Duration in {units}; default {spec["default"]}'}
            else:
                validator = 'auto-integer' if kind == 'auto-integer' else 'integer-range'
                leaf['validators'] = {validator: {'minimum': spec['minimum'], 'maximum': spec['maximum']}}
                leaf['hints'] = {'number': f'{spec["minimum"]}–{spec["maximum"]}; default {spec["default"]}'}
                if kind == 'auto-integer':
                    leaf['choices'] = {'auto': 'Restore the kernel capacity recorded at boot'}
        children[parts[-1]] = leaf

    if interface:
        ipv6 = result['ipv6']['children']
        for name, description, hint, multi in (
            ('eui64', 'Configure an IPv6 address derived from a /64 prefix and this interface MAC',
             'IPv6 /64 network without host bits', True),
            ('interface-identifier', 'Fixed lower 64 bits for SLAAC addresses; requires autoconf',
             'Nonzero IPv6 interface identifier, for example ::1234', False),
            ('link-local-address', 'Use this IPv6 link-local address instead of an automatically generated one',
             'IPv6 link-local address without a prefix, for example fe80::1', False),
        ):
            leaf = {'kind': 'leaf_node', 'description': description,
                    'hints': {'address': hint},
                    'validators': {'interface-ipv6-value': {'kind': name}}}
            if multi:
                leaf['multi'] = True
            ipv6[name] = leaf

        ipv6['no-default-link-local'] = {
            'kind': 'leaf_node', 'valueless': True,
            'description': 'Suppress automatically generated IPv6 link-local addresses',
        }
    return result


class SpacedDumper(yaml.SafeDumper):
    """Keep logical schema nodes separated in generated YAML too."""

    def write_line_break(self, data=None):
        super().write_line_break(data)
        if len(self.indents) == 1:
            super().write_line_break()


def generated_files():
    def render(nodes):
        text = yaml.dump({'children': nodes}, Dumper=SpacedDumper, sort_keys=False, allow_unicode=True, width=110)
        # Child groups are easier to read with a blank line before their contents.
        text = text.replace('children:\n', 'children:\n\n')
        text = re.sub(r'(?m)^( +)([a-z][a-z0-9-]*):\n( +kind:)', r'\n\1\2:\n\3', text)
        return '# Generated by build_tools/kernel_settings.py; edit kernel_settings_map.py.\n\n' + text

    return {
        ROOT / 'packaging/50-nvyr-router.conf': KEYMAP['boot_configuration'](),
        ROOT / 'schemas/includes/firewall/kernel-options.yaml.i':
            render(schema()),
        ROOT / 'schemas/includes/interfaces/ip-options.yaml.i': render(schema(interface=True)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for path, text in generated_files().items():
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8') != text:
                parser.error(f'{path.relative_to(ROOT)} is stale; run python -m build_tools.kernel_settings')
        else:
            path.write_text(text, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
