"""Own only the VNI binding inside each Zebra VRF stanza."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_reload
from nvyr.tree import lookup


def get_config(context):
    vrfs = lookup(context.effective, ('vrf', 'name'), {})
    return {name: values['vni'] for name, values in vrfs.items() if 'vni' in values}


def verify(configuration, context):
    owners = {}
    for name, bindings in configuration.items():
        # Zebra binds at most one L3VNI to a tenant VRF.
        if len(bindings) != 1:
            raise ValidationError(f'VRF {name}: configure exactly one L3VNI')
        vni = next(iter(bindings))
        # One L3VNI identifies one tenant routing table on this VTEP.
        if vni in owners:
            raise ValidationError(f'VRFs {name} and {owners[vni]} share L3VNI {vni}')
        owners[vni] = name


def generate(configuration, context):
    desired = {}
    for name, bindings in configuration.items():
        vni, options = next(iter(bindings.items()))
        suffix = ' prefix-routes-only' if 'prefix-routes-only' in options else ''
        desired[name] = [f' vni {vni}{suffix}']
    return desired


class VrfBindings:
    def select(self, text, scopes):
        selected = {name: [] for name in scopes}
        name = None
        for line in text.splitlines():
            if line.startswith('vrf '):
                name = line[4:]
            elif line.startswith(' vni ') and name in selected:
                selected[name].append(line)
            elif line and not line.startswith(' '):
                name = None
        return selected

    def replace(self, text, desired):
        lines = []
        remaining = dict(desired)
        name = None
        for line in text.splitlines():
            if line.startswith('vrf '):
                name = line[4:]
                lines.append(line)
                lines.extend(remaining.pop(name, ()))
                continue
            if line.startswith(' vni ') and name in desired:
                continue
            if line and not line.startswith(' '):
                name = None
            if line.strip() != 'end':
                lines.append(line)
        for name, binding in remaining.items():
            if binding:
                lines.extend([f'vrf {name}', *binding, 'exit-vrf'])
        return '\n'.join([*lines, 'end', ''])


adapter = VrfBindings()


def apply(generated, context):
    frr_reload.manager.apply('evpn-vni', generated, context.state_directory, adapter=adapter,
                             daemons=('zebra',), recovery=context.recovery)
