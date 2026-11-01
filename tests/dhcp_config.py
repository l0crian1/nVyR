"""Build service lifecycle inputs for DHCP verification and native fixtures."""

import json
from types import SimpleNamespace

from nvyr.config_scripts import service_dhcp
from nvyr.helpers import kea


def verify_servers(servers, context, family):
    owner = service_dhcp.service_name(family)
    effective = {'vrf': {'name': {}}}
    for vrf, server in servers.items():
        target = effective if vrf == 'default' else effective['vrf']['name'].setdefault(vrf, {})
        target.setdefault('service', {})[owner] = server
    gathered = service_dhcp.get_config(SimpleNamespace(
        owner=owner, effective=effective, scripts={owner: {'vrf': tuple(servers)}},
        check_only=context.check_only, reapply_paths=(),
    ))
    service_dhcp.verify(gathered, context)


def generated_server(server, family, devices, *, vrf='default', state_directory='/state'):
    # Direct lifecycle fixtures supply the effective default normally added by the schema.
    if family == 4:
        server = {'socket-type': 'raw'} | server

    plan = service_dhcp.generate({
        'family': family, 'servers': {vrf: server}, 'devices': devices,
        'log-level': 'info', 'rebind': False,
    }, SimpleNamespace(state_directory=state_directory))
    return json.loads(plan.desired[kea.instance_name(family, vrf)])
