"""Native unicast option round trips, replacements and removal, without convergence waits."""

import os

import pytest

from tests.test_bgp_live import apply, native


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_BGP_TEST') != '1', reason='requires disposable FRR daemons')


def test_peer_transport_and_local_as(native):
    peer = {'remote-as': 'external', 'shutdown': {}, 'passive': {},
            'local-as': {'number': '65100', 'no-prepend': {'replace-as': {'dual-as': {}}}},
            'port': '1179', 'tcp-mss': '1200', 'disable-connected-route-check': {},
            'disable-enforce-first-as': {}, 'timers': {'advertisement-interval': '5', 'delay-open': '3'},
            'address-family': {'ipv4-unicast': {}, 'ipv6-unicast': {}}}
    configuration = {'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': peer}}}
    apply(native, configuration)
    peer['remote-as'] = 'auto'
    peer['local-as'] = {'number': '65101', 'no-prepend': {}}
    apply(native, configuration)
    peer.pop('local-as')
    apply(native, configuration)


def test_capabilities_roles_and_restart(native):
    peer = {'remote-as': '65001', 'shutdown': {}, 'graceful-shutdown': {},
            'graceful-restart': 'helper', 'role': {'type': 'provider', 'strict': {}},
            'capability': {'extended-nexthop': {}, 'dynamic': {}, 'link-local': {},
                           'software-version': {}, 'disable-fqdn': {}, 'strict-match': {}},
            'address-family': {'ipv4-unicast': {}, 'ipv6-unicast': {}}}
    configuration = {'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': peer}}}
    apply(native, configuration)
    peer['graceful-restart'] = 'restart'
    peer['capability'] = {'override': {}}
    apply(native, configuration)
    peer['graceful-restart'] = 'disable'
    peer['capability'] = {'disable-negotiation': {}}
    apply(native, configuration)


def test_ipv4_unicast_policy_options(native):
    settings = {'next-hop-self': {'force': {}}, 'allowas-in': {'count': '2', 'route-map': 'BGP_TEST'},
                'as-override': {}, 'remove-private-as': {'all': {'replace': {}}},
                'soft-reconfiguration': {'inbound': {}},
                'maximum-prefix': {'limit': '200', 'threshold': '90', 'warning-only': {}, 'force': {}},
                'maximum-prefix-out': '250', 'weight': '200',
                'conditional-advertisement': {'advertise-map': 'BGP_TEST', 'exist-map': 'BGP_TEST'},
                'addpath': {'transmit': {'best-selected': '3'}, 'receive-limit': '5'},
                'attribute-unchanged': {'as-path': {}, 'next-hop': {}, 'med': {}},
                'unsuppress-map': 'BGP_TEST'}
    configuration = {'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': {
        'remote-as': '65001', 'shutdown': {}, 'address-family': {'ipv4-unicast': settings}}}}}
    apply(native, configuration)
    settings['allowas-in'] = {'origin': {}}
    settings['maximum-prefix'] = {'limit': '300', 'restart': '2'}
    settings['remove-private-as'] = {'replace': {}}
    settings['addpath'] = {'transmit': {'all': {}}, 'disable-receive': {}}
    settings['conditional-advertisement'] = {'advertise-map': 'BGP_TEST', 'non-exist-map': 'BGP_TEST'}
    apply(native, configuration)
    settings['allowas-in'] = {'count': '3'}
    settings['remove-private-as'] = {}
    settings['addpath'] = {'transmit': {'best-selected': '2'}}
    apply(native, configuration)


def test_ipv6_unicast_policy_options(native):
    settings = {'next-hop-self': {'force': {}}, 'allowas-in': {'origin': {}, 'route-map': 'BGP_TEST'},
                'as-override': {}, 'remove-private-as': {'all': {}},
                'soft-reconfiguration': {'inbound': {}},
                'maximum-prefix': {'limit': '200', 'threshold': '80', 'restart': '2', 'force': {}},
                'maximum-prefix-out': '250', 'weight': '200',
                'conditional-advertisement': {'advertise-map': 'BGP_TEST', 'non-exist-map': 'BGP_TEST'},
                'addpath': {'transmit': {'best-selected': '2'}, 'receive-limit': '5'},
                'attribute-unchanged': {'med': {}}, 'unsuppress-map': 'BGP_TEST'}
    apply(native, {'default': {'local-as': '65000', 'neighbor': {'2001:db8::2': {
        'remote-as': '65001', 'shutdown': {}, 'address-family': {'ipv6-unicast': settings}}}}})


def test_ipv4_aggregate_and_redistribution_options(native):
    options = {'network': {'192.0.2.0/24': {}},
               'redistribute': {'kernel': {'metric': '50', 'route-map': 'BGP_TEST'},
                                'connected': {'metric': '100'}, 'static': {'metric': '200'}},
               'aggregate-address': {'192.0.0.0/16': {'origin': 'incomplete', 'route-map': 'BGP_TEST',
                   'matching-med-only': {}, 'suppress-map': 'BGP_TEST'}},
               'distance': {'external': '30', 'internal': '210', 'local': '220'}}
    apply(native, {'default': {'local-as': '65000', 'address-family': {'ipv4-unicast': options}}})


def test_ipv6_aggregate_and_redistribution_options(native):
    options = {'network': {'2001:db8:1::/64': {}},
               'redistribute': {'kernel': {'metric': '50', 'route-map': 'BGP_TEST'},
                                'connected': {'metric': '100'}, 'static': {'metric': '200'}},
               'aggregate-address': {'2001:db8::/32': {'origin': 'igp', 'route-map': 'BGP_TEST',
                   'matching-med-only': {}, 'suppress-map': 'BGP_TEST'}},
               'distance': {'external': '30', 'internal': '210', 'local': '220'},
               'next-hop': {'prefer-global': {}}}
    apply(native, {'default': {'local-as': '65000', 'address-family': {'ipv6-unicast': options}}})


def test_interface_and_link_local_neighbors(native):
    configuration = {'default': {'local-as': '65000', 'neighbor': {
        'eth0': {'remote-as': 'external', 'ipv6-only': {}, 'shutdown': {},
                 'address-family': {'ipv4-unicast': {}, 'ipv6-unicast': {}}},
        'fe80::2': {'remote-as': '65001', 'interface': 'eth0', 'shutdown': {},
                    'address-family': {'ipv6-unicast': {}}}}}}
    apply(native, configuration)
    del configuration['default']['neighbor']['eth0']['ipv6-only']
    apply(native, configuration)


def test_group_family_deactivation(native):
    group = {'remote-as': 'internal', 'shutdown': {}, 'passive': {},
             'address-family': {'ipv4-unicast': {'next-hop-self': {}, 'route-reflector-client': {},
                                                'default-originate': {}}}}
    peer = {'peer-group': 'PEERS'}
    configuration = {'default': {'local-as': '65000', 'peer-group': {'PEERS': group},
                                 'neighbor': {'192.0.2.2': peer}}}
    apply(native, configuration)
    peer['address-family'] = {'ipv4-unicast': {'disable': {}}}
    apply(native, configuration)


def test_route_server_clients(native):
    apply(native, {'default': {'local-as': '65000', 'neighbor': {
        '192.0.2.2': {'remote-as': '65001', 'shutdown': {}, 'role': {'type': 'rs-server'},
            'address-family': {'ipv4-unicast': {'route-server-client': {}}}},
        '2001:db8::2': {'remote-as': '65002', 'shutdown': {},
            'address-family': {'ipv6-unicast': {'route-server-client': {}}}}}}})


def test_interface_peer_group(native):
    configuration = {'default': {'local-as': '65000', 'peer-group': {'PEERS': {
        'remote-as': '65001', 'shutdown': {}, 'address-family': {'ipv6-unicast': {}}}},
        'neighbor': {'eth0': {'peer-group': 'PEERS', 'remote-as': '65001', 'ipv6-only': {}}}}}
    apply(native, configuration)
    del configuration['default']['neighbor']['eth0']['remote-as']
    apply(native, configuration)


def test_explicit_native_defaults(native):
    settings = {'weight': '0', 'allowas-in': {'count': '3'},
                'maximum-prefix': {'limit': '100', 'threshold': '75'}}
    configuration = {'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': {
        'remote-as': '65001', 'port': '179', 'shutdown': {},
        'timers': {'advertisement-interval': '0'}, 'address-family': {'ipv4-unicast': settings}}},
        'address-family': {'ipv4-unicast': {'distance': {'external': '20', 'internal': '200', 'local': '200'}}}}}
    apply(native, configuration)
