"""Compare native policy across boots without comparing transient runtime state."""

from copy import deepcopy
import difflib
import json

from nvyr.helpers.process import cmd


def stable_expression(value):
    """Remove only statement statistics; preserve configured match operands and limits."""
    if isinstance(value, list):
        return [stable_expression(item) for item in value]
    if not isinstance(value, dict):
        return value

    result = {}
    for key, item in value.items():
        if key == 'counter' and isinstance(item, dict):
            item = {name: data for name, data in item.items() if name not in ('packets', 'bytes')}
        elif key == 'last' and isinstance(item, dict):
            item = {name: data for name, data in item.items() if name not in ('used', 'msecs')}
        elif key == 'quota' and isinstance(item, dict):
            item = {name: data for name, data in item.items() if name not in ('used', 'used_unit')}
        result[key] = stable_expression(item)
    return result


def firewall(document):
    """Compare objects by name and rules in chain order, ignoring handles and learned keys."""
    objects = {}
    chains = {}
    for entry in document['nftables']:
        for kind, original in entry.items():
            if kind == 'metainfo':
                continue
            value = deepcopy(original)
            value.pop('handle', None)
            if kind in ('set', 'map'):
                # Runtime learning is not persisted policy; its definition still is.
                if 'dynamic' in value.get('flags', []):
                    value.pop('elem', None)
                    value.pop('count', None)
                elif 'elem' in value:
                    elements = [stable_expression(element) for element in value['elem']]
                    value['elem'] = sorted(elements, key=lambda element: json.dumps(element, sort_keys=True))
            if kind == 'counter':
                value.pop('packets', None)
                value.pop('bytes', None)
            if kind == 'quota':
                value.pop('used', None)
                value.pop('used_unit', None)
            value = stable_expression(value)
            if kind == 'rule':
                chains.setdefault(value['chain'], []).append(value)
            else:
                objects[f'{kind}:{value["name"]}'] = value
    return {'objects': objects, 'chains': chains}


def routing(text):
    """Compare routing policy, excluding banners and per-daemon startup hostnames."""
    return [line.rstrip() for line in text.splitlines()
            if line.strip() and not line.startswith(
                ('!', 'Building configuration', 'Current configuration:', 'hostname '))]


def vrf_conntrack(document, vrfs):
    """Compare VRF ownership, allowing zone IDs to be reallocated after reboot."""
    document = deepcopy(document)
    mapping = next(item['map'] for item in document['nftables'] if 'map' in item)
    zones = {zone: name for name, zone in mapping.get('elem', []) if name in vrfs}
    if len(zones) != len(vrfs):
        raise AssertionError('Missing or shared VRF conntrack zone identities')
    mapping['elem'] = [[interface, zones[zone]] for interface, zone in mapping.get('elem', [])]
    return firewall(document)


def capture():
    """Read live daemon/kernel configuration, never our generated configuration files."""
    nftables = json.loads(cmd(['nft', '-s', '-n', '-j', 'list', 'table', 'inet', 'nvyr_filter']))
    conntrack = json.loads(cmd(['nft', '-s', '-n', '-j', 'list', 'table', 'inet', 'nvyr_vrf_conntrack']))
    vrfs = [link['ifname'] for link in json.loads(cmd(['ip', '-j', '-d', 'link', 'show', 'type', 'vrf']))]
    return {'firewall': firewall(nftables), 'vrf_conntrack': vrf_conntrack(conntrack, vrfs),
            'routing': routing(cmd(['vtysh', '-c', 'show running-config']))}


def compare(before, after):
    """Produce separate failures and a bounded diff while retaining full snapshots on disk."""
    results = []
    for subsystem in ('firewall', 'routing', 'vrf_conntrack'):
        previous = before[subsystem]
        current = after[subsystem]
        if subsystem == 'routing':
            previous = routing('\n'.join(previous))
            current = routing('\n'.join(current))
        result = {'check': f'{subsystem}_native_configuration', 'status': 'PASSED'}
        if previous != current:
            old = json.dumps(previous, indent=2, sort_keys=True).splitlines()
            new = json.dumps(current, indent=2, sort_keys=True).splitlines()
            difference = '\n'.join(difflib.unified_diff(old, new, fromfile='before', tofile='after'))
            result.update(status='FAIL', reason=difference[:8000])
        results.append(result)
    return results
