"""Production registration must never substitute a successful no-op lifecycle."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import (
    container, firewall, firewall_failsafe, interface_ethernet, interface_dummy, interface_virtual_ethernet,
    interface_bridge, interface_loopback, protocols_static, protocols_bgp, policy, logging,
    service_ssh, service_dhcp, system_dns, system_login, system_hostname, system_configuration, system_ntp, system_cpu,
    system_timezone, vrf, vrf_conntrack,
)
from nvyr.modules import registry
from nvyr.schema import Schema


def test_bundled_owners_use_scripts_directly_without_lifecycle_recording():
    modules = registry(Schema.bundled())

    assert modules == {
        'time-zone': system_timezone,
        'cpu': system_cpu,
        'container': container,
        'logging': logging,
        'firewall': firewall,
        'firewall_failsafe': firewall_failsafe,
        'ethernet': interface_ethernet,
        'dummy': interface_dummy,
        'loopback': interface_loopback,
        'virtual-ethernet': interface_virtual_ethernet,
        'bridge': interface_bridge,
        'vrf': vrf,
        'vrf_conntrack': vrf_conntrack,
        'static': protocols_static,
        'bgp': protocols_bgp,
        'policy': policy,
        'ssh': service_ssh,
        'dhcp-server': service_dhcp,
        'dhcpv6-server': service_dhcp,
        'dns': system_dns,
        'ntp': system_ntp,
        'login': system_login,
        'system': system_hostname,
        'configuration': system_configuration,
    }
    assert all(not hasattr(module, 'calls') for module in modules.values())


def test_unregistered_owner_is_rejected_instead_of_getting_a_no_op():
    schema = Schema({'kind': 'node', 'children': {
        'feature': {'kind': 'node', 'script': {'name': 'missing-feature', 'priority': 1}},
    }})

    with pytest.raises(ValueError, match='No configuration script registered for: missing-feature'):
        registry(schema)


def test_registry_only_includes_requested_owners():
    assert registry(SimpleNamespace(owners={'firewall': None})) == {'firewall': firewall}
    assert registry(SimpleNamespace(owners={})) == {}
