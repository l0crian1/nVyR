"""Keep the shipped command trees useful even when live suggestions are empty."""

import json
from pathlib import Path

import pytest


SCHEMAS = Path(__file__).resolve().parents[1] / 'src/nvyr/schemas'


def command_nodes(node, path=()):
    """Visit expanded command nodes, including shared and replaced fragments."""
    yield path, node

    for name, child in node.get('children', {}).items():
        yield from command_nodes(child, (*path, name))


@pytest.mark.parametrize('name', ['configuration', 'operational', 'control', 'pipelines'])
def test_shipped_commands_explain_their_purpose_and_values(name):
    """Every value needs static help; suggestors alone can return no results."""
    schema = json.loads((SCHEMAS / f'{name}.json').read_text())
    missing = []

    for path, node in command_nodes(schema):
        if path and not node.get('description', '').strip():
            missing.append(f'{" ".join(path)}: missing command description')

        takes_value = node['kind'] in {'leaf_node', 'tag_node'} and not node.get('valueless')
        if takes_value and not (node.get('hints') or node.get('choices')):
            missing.append(f'{" ".join(path)}: missing value hints or described choices')

        for category in ('hints', 'choices'):
            for value, description in node.get(category, {}).items():
                if not description.strip() or description == 'Enter a value for this setting':
                    missing.append(f'{" ".join(path)}: unclear {category} entry {value}')

    assert not missing, '\n'.join(missing)


def test_container_device_help_explains_host_and_container_paths(controller, session):
    """Device tags and their destination leaves must describe different namespaces."""
    source = controller.completion('set container name test device ', session, explicit=True)
    assert '/dev/net/tun' in dict(source['hints'])['/dev/path']
    assert 'Host' in dict(source['hints'])['/dev/path']
    assert '<value>' not in dict(source['candidates'])

    destination = controller.completion(
        'set container name test device /dev/net/tun destination ', session, explicit=True)
    assert 'inside the container' in dict(destination['hints'])['/dev/path']


def test_container_choices_explain_permissions_and_restart_behavior(controller, session):
    """Enumerated values should complete with meaning, not a generic placeholder."""
    permissions = controller.completion(
        'set container name test device /dev/net/tun permissions ', session, explicit=True)
    assert dict(permissions['candidates'])['rwm'] == 'Read, write and create device nodes'

    restart = controller.completion('set container name test restart-policy ', session, explicit=True)
    assert dict(restart['candidates'])['no'] == 'Do not automatically restart'
    assert dict(restart['candidates'])['on-failure'] == 'Restart after a failed exit'


def test_dhcp_value_hints_survive_vrf_inclusion(controller, session):
    """The VRF include must retain address-family-specific server guidance."""
    ipv4 = controller.completion(
        'set vrf name BLUE service dhcp-server listen-address ', session, explicit=True)
    assert 'IPv4' in dict(ipv4['hints'])['x.x.x.x']

    ipv6 = controller.completion(
        'set vrf name BLUE service dhcpv6-server listen-address ', session, explicit=True)
    assert 'IPv6' in dict(ipv6['hints'])['IPv6-address']


def test_operational_selectors_have_help_without_live_suggestions(controller, monkeypatch):
    """Empty inventory must still explain which container or image name is expected."""
    monkeypatch.setattr('nvyr.helpers.suggestors.cmd', lambda *args, **kwargs: '[]')
    container = controller.completion('show containers name ', explicit=True)
    assert dict(container['hints'])['name'] == 'Configured container name'

    image = controller.completion('delete system image ', explicit=True)
    assert dict(image['hints'])['name'] == 'Installed nVyR image name'


def test_connection_ranges_and_units_remain_clear_after_negation(controller, session):
    """Negated fields retain their range guidance and accounting fields retain units."""
    zone = controller.completion(
        'set firewall ipv4 input filter rule 10 connection zone not ', session, explicit=True)
    assert {'0-65535', 'start-end'} <= dict(zone['hints']).keys()

    byte_count = controller.completion(
        'set firewall ipv4 input filter rule 10 connection original bytes gt ', session, explicit=True)
    assert 'binary k, m or g' in dict(byte_count['hints'])['bytes']
