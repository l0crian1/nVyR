"""Gather real BGP lifecycle inputs for tests specifying per-VRF instances."""

from copy import deepcopy
from types import SimpleNamespace

from nvyr.config_scripts import protocols_bgp


def bgp_configuration(instances, context):
    effective = deepcopy(context.effective)
    for vrf, instance in instances.items():
        section = effective
        if vrf != 'default':
            section = effective.setdefault('vrf', {}).setdefault('name', {}).setdefault(vrf, {})
        section.setdefault('protocols', {})['bgp'] = instance

    return protocols_bgp.get_config(SimpleNamespace(
        effective=effective, scripts={'bgp': {'vrf': tuple(instances)}},
    ))


def verify_bgp(instances, context):
    protocols_bgp.verify(bgp_configuration(instances, context), context)
