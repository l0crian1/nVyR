"""CGN CLI translation, allocation changes and removal on shared dummy interfaces.

No packet tests or routing convergence; live translation is covered by the routed
functional scenario. Incompatible with another test replacing NAT concurrently.
"""

from smoketests.assertions import assert_firewall_object, assert_firewall_rule, assert_operational_output
from smoketests.firewall_support import firewall_environment, firewall_suite, firewall_vrf_suite, vrf_environment


def test_allocation_map_and_pool_update(config):
    config.set('set nat cgnat pool SMOKECGN public-address 203.0.113.10 block-size 1024')
    config.set('set nat cgnat rule 10 pool SMOKECGN source-address 100.64.0.1-100.64.0.3 outbound-interface dum999 counter description "CGN smoke"')
    config.commit()
    assert_firewall_object('map', 'cgnat_allocation_10', '100.64.0.1', '203.0.113.10', '1024-2047')
    assert_firewall_rule('ipv4_cgnat', 10, 'ct zone 0', 'snat ip to ip saddr map @cgnat_allocation_10')
    assert_operational_output('show nat cgnat rules', 'Installed', 'SMOKECGN')
    assert_operational_output('show nat cgnat pool SMOKECGN', '203.0.113.10', '1024')
    assert_operational_output('show nat cgnat subscriber 100.64.0.2', '203.0.113.10', '2048-3071')
    config.set('set nat cgnat pool SMOKECGN port-range 2048-65535')
    config.commit()
    assert_firewall_object('map', 'cgnat_allocation_10', '2048-3071', '3072-4095', '4096-5119')
    assert_operational_output('show nat cgnat public-address 203.0.113.10 port 3072', '100.64.0.2')


def test_vrf_zone_and_interface_scope(config, vrf_environment):
    config.set('set interfaces dummy dum999 vrf NVYRFWSMOKE')
    config.set('set nat cgnat pool SMOKECGN public-address 203.0.113.10')
    config.set('set nat cgnat rule 10 vrf NVYRFWSMOKE source-address 100.64.0.1 outbound-interface dum999 pool SMOKECGN counter')
    config.commit()

    assert_firewall_rule('ipv4_cgnat', 10, 'ct zone [1-9][0-9]*', 'oifname.*NVYRFWSMOKE.*dum999')
    assert_operational_output('show nat cgnat subscriber 100.64.0.1 vrf NVYRFWSMOKE', '203.0.113.10', '1024-2047')
