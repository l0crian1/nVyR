"""Nonfatal lifecycle feedback and zone-default warnings through check and commit."""

import json
import logging

from nvyr.errors import Warning
from nvyr.protocol import Client
from tests.test_integration import daemon


def test_warning_reports_without_ending_verification(controller, engine, session, monkeypatch):
    controller.execute('set system host-name router', session)
    stages = []

    def verify(configuration, context):
        context.report(Warning('An advisory condition.'))
        context.report('Existing text feedback.\n')
        stages.append('verified')

    monkeypatch.setattr(engine.modules['system'], 'verify', verify)
    warning = Warning('An advisory condition.')
    assert not isinstance(warning, BaseException)
    assert str(warning) == 'Warning: An advisory condition.'

    checked = engine.check(session)
    committed = engine.commit(session)

    for result in (checked, committed):
        assert result['results']['system']['success']
        assert result['messages'] == [str(warning), 'Existing text feedback.\n']
        json.dumps(result)

    assert stages == ['verified', 'verified']
    assert engine.running['system']['host-name'] == 'router'
    assert [stage for _, stage, _ in engine.modules['system'].calls][-2:] == ['generate', 'apply']


def test_unattended_warning_keeps_warning_severity(controller, engine, session, monkeypatch, caplog):
    controller.execute('set system host-name router', session)
    engine.commit(session)

    def verify(configuration, context):
        context.report(Warning('Recovery advisory.'))

    monkeypatch.setattr(engine.modules['system'], 'verify', verify)
    engine._run_recovery(engine.running, engine.running, {'system'})

    assert any(record.levelno == logging.WARNING and
               record.getMessage() == 'system: Warning: Recovery advisory.'
               for record in caplog.records)


def test_zone_implicit_defaults_warn_only_for_active_hooks(controller, engine, session):
    controller.execute('set firewall zone USERS interface eth1', session)

    result = controller.execute('commit check', session)['text']

    assert result.count('Warning:') == 2
    assert 'firewall ipv4 forward filter defaults to accept' in result
    assert 'firewall ipv6 forward filter defaults to accept' in result
    assert 'input filter' not in result and 'output filter' not in result
    assert 'Configuration check passed.' in result
    assert engine.running == {}

    result = controller.execute('commit', session)['text']
    assert result.count('Warning:') == 2
    assert 'firewall: done' in result
    assert engine.running['firewall']['zone']['USERS']['interface'] == ['eth1']


def test_local_zone_warns_for_explicit_and_implicit_accept_defaults(controller, session):
    controller.execute('set firewall zone USERS interface eth1', session)
    controller.execute('set firewall zone LOCAL local-zone', session)
    controller.execute('set firewall ipv4 input filter default-action accept', session)
    controller.execute('set firewall ipv4 forward filter default-action drop', session)
    controller.execute('set firewall ipv6 output filter default-action reject', session)

    result = controller.execute('commit check', session)['text']

    assert result.count('Warning:') == 4
    assert 'firewall ipv4 input filter defaults to accept' in result
    assert 'firewall ipv4 output filter defaults to accept' in result
    assert 'firewall ipv6 input filter defaults to accept' in result
    assert 'firewall ipv6 forward filter defaults to accept' in result
    assert 'firewall ipv4 forward filter defaults to accept' not in result
    assert 'firewall ipv6 output filter defaults to accept' not in result
    assert 'Configuration check passed.' in result


def test_zone_warning_does_not_skip_later_verification_errors(controller, engine, session):
    controller.execute('set firewall zone USERS interface eth1', session)
    controller.execute('set firewall ipv4 forward filter rule 10 description incomplete', session)

    checked = engine.check(session)
    committed = engine.commit(session)

    for result in (checked, committed):
        assert len(result['messages']) == 2
        assert not result['results']['firewall']['success']
        assert 'action is required' in result['results']['firewall']['error']
    assert engine.running == {}


def test_zone_warnings_stop_when_fallbacks_drop_or_zones_removed(controller, session):
    controller.execute('set firewall zone USERS interface eth1', session)
    controller.execute('set firewall ipv4 forward filter default-action drop', session)
    controller.execute('set firewall ipv6 forward filter default-action drop', session)
    controller.execute('set firewall ipv4 name UNUSED default-action accept', session)

    assert 'Warning:' not in controller.execute('commit check', session)['text']

    controller.execute('delete firewall zone', session)
    controller.execute('set firewall ipv4 forward filter default-action accept', session)
    assert 'Warning:' not in controller.execute('commit check', session)['text']


def test_local_zone_alone_has_no_active_hook_warnings(controller, session):
    controller.execute('set firewall zone LOCAL local-zone', session)

    result = controller.execute('commit check', session)['text']

    assert 'Warning:' not in result
    assert 'Configuration check passed.' in result


def test_failsafe_warning_identifies_its_own_configuration(controller, session):
    controller.execute('set firewall fail-safe zone USERS interface eth1', session)

    result = controller.execute('commit check', session)['text']

    assert result.count('Warning:') == 2
    assert 'firewall fail-safe ipv4 forward filter defaults to accept' in result
    assert 'firewall fail-safe ipv6 forward filter defaults to accept' in result
    assert 'Configuration check passed.' in result


def test_zone_warnings_cross_rpc_for_check_and_commit(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set firewall zone USERS interface eth1')

        checked = client.request('execute', text='commit check')['text']
        committed = client.request('execute', text='commit')['text']

        assert checked.count('Warning:') == 2
        assert committed.count('Warning:') == 2
        assert 'Configuration check passed.' in checked
        assert 'firewall: done' in committed
    finally:
        client.close()
