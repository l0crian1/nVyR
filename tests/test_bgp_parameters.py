"""Parameter defaults, validation and actual FRR reload/readback behavior."""

from copy import deepcopy
import os

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import bgp_parameters
from nvyr.schema import Schema
from nvyr.tree import lookup
from tests.bgp_config import verify_bgp
from tests.test_bgp import context
from tests.test_bgp_live import apply, native


NATIVE = pytest.mark.skipif(os.environ.get('NVYR_BGP_TEST') != '1', reason='requires disposable FRR daemons')


def nested(path, value):
    result = value
    for key in reversed(path.split()):
        result = {key: result}
    return result


def test_requested_defaults():
    text = bgp.generate({'instances': {'default': {'local-as': '65000'}}}, None)['default'][0]
    assert 'no bgp ebgp-requires-policy' in text
    assert 'no bgp reject-as-sets' in text
    assert 'no bgp default ipv4-unicast' in text
    assert 'no bgp network import-check' in text


def test_schema_defaults_agree_with_parameter_rendering():
    parameters = {}
    paths = [path for path, _, _, _ in bgp_parameters.SWITCHES]
    paths.extend(bgp_parameters.NUMBERS)
    for path in paths:
        parent = parameters
        for part in path.split()[:-1]:
            parent = parent.setdefault(part, {})

    explicit = {'protocols': {'bgp': {'local-as': '65000', 'parameters': parameters}}}
    effective = Schema.bundled().defaults(explicit)['protocols']['bgp']['parameters']
    for path, _, _, default in bgp_parameters.SWITCHES:
        assert lookup(effective, tuple(path.split())) == ('enable' if default else 'disable')
    for path, default in bgp_parameters.NUMBERS.items():
        assert int(lookup(effective, tuple(path.split()))) == default

    assert bgp.generate({'instances': {'default': explicit['protocols']['bgp']}}, None) == bgp.generate(
        {'instances': {'default': {'local-as': '65000', 'parameters': effective}}}, None)


def test_parameters_do_not_create_bgp_for_static_routes(controller, session, engine):
    controller.execute('set protocols static route 192.0.2.0/24 blackhole', session)
    result = engine.commit(session)
    assert 'bgp' not in result['results']


@pytest.mark.parametrize('path,native_command,native_default,default', bgp_parameters.SWITCHES)
def test_switch_schema_and_defaults(controller, session, path, native_command, native_default, default):
    controller.execute('set protocols bgp local-as 65000', session)
    controller.execute('set protocols bgp parameters ' + path + ' enable', session)
    controller.execute('set protocols bgp parameters ' + path + ' disable', session)


@pytest.mark.parametrize('parameters,message', [
    ({'confederation': {'identifier': '65000'}}, 'must differ'),
    ({'confederation': {'identifier': '64512', 'peers': ['65000']}}, 'cannot contain'),
    ({'confederation': {'peers': ['65001']}}, 'require identifier'),
    ({'suppress-fib-pending-delay': '10'}, 'requires suppress'),
    ({'tcp-keepalive': {'idle': '10'}}, 'requires idle'),
    ({'max-med': {'on-startup': {'med': '100'}}}, 'requires time'),
    ({'bestpath': {'as-path': {'multipath-relax-as-set': 'enable'}}}, 'requires multipath'),
    ({'dampening': {'state': 'enable', 'reuse': '3000'}}, 'less than suppress'),
    ({'dampening': {'state': 'enable', 'max-suppress-time': '1'}}, 'at least half-life'),
    ({'listen': {'range': {'192.0.2.0/24': {}}}}, 'configured peer-group'),
])
def test_parameter_validation(parameters, message):
    with pytest.raises(ValidationError, match=message):
        verify_bgp({'default': {'local-as': '65000', 'parameters': parameters}}, context())


def test_daemon_wide_timer_rejects_vrf_scope():
    with pytest.raises(ValidationError, match='daemon-wide'):
        verify_bgp({'BLUE': {'local-as': '65000', 'parameters': {'route-map': {'delay-timer': '10'}}}}, context())


def test_dampening_rejects_unsupported_vrf():
    with pytest.raises(ValidationError, match='default VRF'):
        verify_bgp({'BLUE': {'local-as': '65000', 'parameters': {'dampening': {'state': 'enable'}}}}, context())


@pytest.mark.parametrize('command', [
    'set protocols bgp parameters enforce-first-as yes',
    'set protocols bgp parameters tcp-keepalive probes 31',
    'set protocols bgp parameters listen range 192.0.2.1/24 peer-group PEERS',
    'set protocols bgp parameters listen range 2001:db8::1/64 peer-group PEERS',
    'set protocols bgp parameters listen range 192.0.2.1 peer-group PEERS',
    'set protocols bgp parameters graceful-restart restart-time 4096',
    'set protocols bgp parameters graceful-restart mode invalid',
    'set protocols bgp parameters max-med on-startup time 4',
    'set protocols bgp parameters always-compare-med enable',
    'set protocols bgp parameters deterministic-med enable',
    'set protocols bgp parameters bestpath use-imported-attributes enable',
    'set protocols bgp parameters default software-version-capability latest',
    'set protocols bgp parameters default-originate timer 0',
    'set protocols bgp parameters shutdown-message maintenance',
    'set protocols bgp parameters labeled-unicast',
])
def test_parameter_schema_rejects_invalid_or_deferred_settings(controller, session, command):
    with pytest.raises(RouterError):
        controller.execute(command, session)


def test_policy_requirement_is_opt_in():
    instance = {'local-as': '65000', 'neighbor': {'192.0.2.2': {
        'remote-as': '65001', 'address-family': {'ipv4-unicast': {}}}}}
    verify_bgp({'default': instance}, context())
    instance['parameters'] = {'ebgp-requires-policy': 'enable'}
    with pytest.raises(ValidationError, match='explicit import policy'):
        verify_bgp({'default': instance}, context())


def test_policy_requirement_excludes_confederation_members():
    """RFC 8212 enforcement distinguishes confederation members from ordinary eBGP peers."""
    instance = {'local-as': '65000', 'parameters': {'ebgp-requires-policy': 'enable',
                'confederation': {'identifier': '64512', 'peers': ['65001']}},
                'neighbor': {'192.0.2.2': {'remote-as': '65001', 'address-family': {'ipv4-unicast': {}}}}}
    verify_bgp({'default': instance}, context())


@NATIVE
@pytest.mark.parametrize('path,native_command,native_default,default', bgp_parameters.SWITCHES)
def test_native_switch_roundtrip(native, path, native_command, native_default, default):
    instance = {'local-as': '65000'}
    for state in ('enable', 'disable'):
        instance['parameters'] = nested(path, state)
        apply(native, {'default': instance})
    apply(native, {'default': {'local-as': '65000'}})


COMPLEX_PARAMETERS = [
    {'cluster-id': '192.0.2.5'},
    {'conditional-advertisement': {'timer': '10'}},
    {'confederation': {'identifier': '64512', 'peers': ['65002', '65001']}},
    {'default': {'local-preference': '200', 'subgroup-pkt-queue-max': '50'}},
    {'default': {'software-version-capability': 'legacy'}},
    {'graceful-restart': {'mode': 'restart', 'restart-time': '90', 'stalepath-time': '240',
                          'select-defer-time': '60', 'rib-stale-time': '300'}},
    {'graceful-restart': {'mode': 'disable'}},
    {'long-lived-graceful-restart': {'stale-time': '300'}},
    {'minimum-holdtime': '30'},
    {'bestpath': {'as-path': {'multipath-relax': 'enable', 'multipath-relax-as-set': 'enable'}}},
    {'bestpath': {'med': {'confed': 'enable', 'missing-as-worst': 'enable'}}},
    {'bestpath': {'bandwidth': 'skip-missing'}},
    {'bestpath': {'bandwidth': 'default-weight-for-missing'}},
    {'bestpath': {'bandwidth': 'ignore'}},
    {'max-med': {'administrative': '1000', 'on-startup': {'time': '30', 'med': '500'}}},
    {'suppress-fib-pending': 'enable', 'suppress-fib-pending-delay': '50'},
    {'tcp-keepalive': {'idle': '10', 'interval': '5', 'probes': '3'}},
    {'dampening': {'state': 'enable'}},
    {'dampening': {'state': 'enable', 'half-life': '10', 'reuse': '500', 'suppress': '1500', 'max-suppress-time': '40'}},
    {'route-map': {'delay-timer': '10'}},
]


@NATIVE
@pytest.mark.parametrize('parameters', COMPLEX_PARAMETERS)
def test_native_parameter_roundtrip(native, parameters):
    instance = {'local-as': '65000', 'parameters': deepcopy(parameters)}
    verify_bgp({'default': instance}, context())
    apply(native, {'default': instance})
    apply(native, {'default': {'local-as': '65000'}})


@NATIVE
@pytest.mark.parametrize('family,address', [('ipv4-unicast', '192.0.2.2'), ('ipv6-unicast', '2001:db8::2')])
def test_native_default_activation_existing_peer(native, family, address):
    instance = {'local-as': '65000', 'neighbor': {address: {'remote-as': '65000'}}}
    apply(native, {'default': instance})
    instance['parameters'] = {'default': {family: 'enable'}}
    apply(native, {'default': instance})
    instance['parameters']['default'][family] = 'disable'
    apply(native, {'default': instance})


@NATIVE
def test_native_dynamic_listeners(native):
    instance = {'local-as': '65000', 'parameters': {'listen': {'limit': '25', 'range': {
        '192.0.2.0/24': {'peer-group': 'DYNAMIC'}, '2001:db8::/32': {'peer-group': 'DYNAMIC'}}}},
        'peer-group': {'DYNAMIC': {'remote-as': '65001', 'address-family': {'ipv4-unicast': {}, 'ipv6-unicast': {}}}}}
    verify_bgp({'default': instance}, context())
    apply(native, {'default': instance})
    apply(native, {'default': {'local-as': '65000'}})


@NATIVE
@pytest.mark.parametrize('path', ['default shutdown', 'default dynamic-capability', 'default link-local-capability',
                                'default software-version-capability', 'default ipv4-unicast', 'default ipv6-unicast'])
def test_native_defaults_with_existing_group_members(native, path):
    instance = {'local-as': '65000', 'peer-group': {'PEERS': {'remote-as': '65000'}},
                'neighbor': {'192.0.2.2': {'peer-group': 'PEERS'}, '192.0.2.3': {'remote-as': '65000'}}}
    apply(native, {'default': instance})
    value = 'legacy' if path.endswith('software-version-capability') else 'enable'
    instance['parameters'] = nested(path, value)
    apply(native, {'default': instance})
    del instance['parameters']
    apply(native, {'default': instance})


@NATIVE
def test_native_minimum_holdtime_below_writer_bug(native):
    """The immediately lower minimum remains a supported, persistent value."""
    apply(native, {'default': {'local-as': '65000', 'parameters': {'minimum-holdtime': '179'}}})
    apply(native, {'default': {'local-as': '65000'}})


@NATIVE
def test_native_minimum_holdtime_above_writer_bug(native):
    """The immediately higher minimum remains a supported, persistent value."""
    apply(native, {'default': {'local-as': '65000', 'parameters': {'minimum-holdtime': '181'}}})
    apply(native, {'default': {'local-as': '65000'}})


@NATIVE
def test_native_dampening_maximum_threshold(native):
    """Instance dampening accepts FRR's full suppression range through 50,000."""
    apply(native, {'default': {'local-as': '65000', 'parameters': {
        'dampening': {'state': 'enable', 'suppress': '50000'}}}})
    apply(native, {'default': {'local-as': '65000'}})
