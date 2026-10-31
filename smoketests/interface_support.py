"""Resource reservation, configuration reset, and cleanup for interface suites."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import assert_config_names_unused, assert_false, assert_not_in, assert_true
from smoketests.support import defer_interrupt, prepared_test

VRFS = {'NVYRIFSMOKE': 41010, 'NVYRIFSMOKE2': 41011}


@contextmanager
def interface_suite(config, request, links, commands, *, ethernet=None, vrfs=(), shared_vrfs=False):
    """Reserve devices once per script and retain them across configuration resets."""
    def reset():
        """Replace test configuration in one commit, then release unused VRFs."""
        config.discard()
        running = config.get_config()
        for kind, members in links.items():
            for name in members:
                if lookup(running, ('interfaces', kind, name), None) is not None:
                    config.delete(f'delete interfaces {kind} {name}')

        # Baseline routing domains stay instantiated through every case reset.
        for name in vrfs:
            config.set(f'set vrf name {name} table {VRFS[name]}')

        # No commit between delete and set: netlinkd sees only the final baseline.
        # Restore both peer definitions together so a retained veth pair stays intact.
        for command in commands:
            config.set(command)
        config.commit()

        # Detach members before removing routing domains outside the shared baseline.
        running = config.get_config()
        changed = False
        for name in VRFS:
            if name not in vrfs and lookup(running, ('vrf', 'name', name), None) is not None:
                config.delete(f'delete vrf name {name}')
                changed = True
        if changed:
            config.commit()

    with interface_test(config, request, links, ethernet=ethernet, reserve_vrfs=not shared_vrfs):
        reset()
        yield reset


@contextmanager
def interface_case(request, reset):
    """Give the next function a clean configuration without recreating its devices."""
    try:
        yield
    finally:
        try:
            with defer_interrupt():
                reset()
        except BaseException:
            request.session.shouldstop = 'Interface reset failed; stopping tests and restoring the original configuration.'
            raise


@contextmanager
def interface_test(config, request, links, *, ethernet=None, reserve_vrfs=True):
    """Reserve fresh names and remove members before VRFs when the scope exits."""
    prepared = False
    restore_empty_ethernet = False
    names = [name for members in links.values() for name in members]
    reserved_vrfs = VRFS if reserve_vrfs else {}

    def standup(session):
        """Refuse existing configuration, references, devices, and routing tables."""
        nonlocal prepared, restore_empty_ethernet
        running = session.get_config()
        # An explicitly selected empty Ethernet profile owns no policy. Remove only
        # that definition from the collision check; references elsewhere still fail.
        checked = deepcopy(running)
        restore_empty_ethernet = ethernet is not None and lookup(
            running, ('interfaces', 'ethernet', ethernet), None) == {}
        if restore_empty_ethernet:
            del checked['interfaces']['ethernet'][ethernet]
        assert_config_names_unused(checked, *names, *reserved_vrfs)
        devices = json.loads(cmd(['ip', '-j', '-d', 'address', 'show']))
        existing = {device['ifname']: device for device in devices}

        for name in [*names, *reserved_vrfs]:
            if name != ethernet:
                assert_not_in(name, existing, msg=f'Smoketest device {name} is already in use')

        for device in devices:
            table = device.get('linkinfo', {}).get('info_data', {}).get('table')
            assert_not_in(table, reserved_vrfs.values(), msg='Smoketest routing table is already in use')

        for vrf in lookup(running, ('vrf', 'name'), {}).values():
            assert_not_in(str(vrf.get('table')), {str(table) for table in reserved_vrfs.values()})

        for family in ('-4', '-6'):
            routes = json.loads(cmd(['ip', family, '-j', 'route', 'show', 'table', 'all']))
            for route in routes:
                assert_not_in(str(route.get('table')), {str(table) for table in reserved_vrfs.values()})
                if ethernet:
                    link_local = family == '-6' and route.get('dst', '').startswith(('fe80:', 'ff00:'))
                    assert_false(route.get('dev') == ethernet and not (restore_empty_ethernet and link_local),
                                 msg='Selected spare port already carries a route')

        if ethernet:
            assert_true(re.fullmatch(r'eth[0-9]+', ethernet), msg='Select an ethN physical port')
            assert_true(ethernet in existing, msg='Selected Ethernet port does not exist')
            assert_true((Path('/sys/class/net') / ethernet / 'device').exists(),
                        msg='Ethernet smoketests require a physical port')
            device = existing[ethernet]
            if not restore_empty_ethernet:
                assert_false('UP' in device['flags'], msg='Selected spare port must initially be down')
            addresses = device.get('addr_info', [])
            if restore_empty_ethernet:
                addresses = [address for address in addresses
                             if not (address.get('family') == 'inet6' and address.get('scope') == 'link')]
            assert_false(addresses, msg='Selected spare port already has addresses')
            assert_false(device.get('master'), msg='Selected spare port already has a master')

        prepared = True

    def cleanup(session):
        """Discard rejected edits and delete only the resources reserved above."""
        if not prepared:
            return

        session.discard()
        running = session.get_config()
        changed = False
        for kind, members in links.items():
            for name in members:
                if lookup(running, ('interfaces', kind, name), None) is not None:
                    session.delete(f'delete interfaces {kind} {name}')
                    changed = True
                if name == ethernet and restore_empty_ethernet:
                    session.set(f'set interfaces ethernet {ethernet}')
                    changed = True

        # Commit both veth endpoint removals together; release VRF references first.
        if changed:
            session.commit()

        running = session.get_config()
        changed = False
        for name in reserved_vrfs:
            if lookup(running, ('vrf', 'name', name), None) is not None:
                session.delete(f'delete vrf name {name}')
                changed = True

        if changed:
            session.commit()

    def stop(message):
        """A cleanup failure must stop further mutations and trigger global restore."""
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield


def spare_ethernet(request):
    """Never guess which physical port can safely be reconfigured."""
    name = request.config.getoption('--ethernet-interface')
    if not name:
        pytest.skip('Select an unused down port with --ethernet-interface ethN')
    return name
