"""Timezone names, default lifecycle, atomic file replacement and compensation."""

from copy import deepcopy
import os
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import system_timezone
from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import suggestors, timezones, validators
from nvyr.schema import Schema


def prepare(zone):
    configuration = system_timezone.get_config(
        SimpleNamespace(effective={'system': {'time-zone': zone}}))
    system_timezone.verify(configuration, None)
    return system_timezone.generate(configuration, None)


def test_installed_names_and_suggestions():
    names = {item.value for item in suggestors.time_zones(None)}
    assert {'UTC', 'America/New_York', 'Asia/Kathmandu'} <= names
    assert 'localtime' not in names
    assert 'posixrules' not in names
    assert not any(name.startswith(('right/', 'posix/')) for name in names)
    assert validators.time_zone('America/New_York')


@pytest.mark.parametrize('value', [
    '', '.', '..', '/etc/passwd', '../etc/passwd', 'America/../UTC',
    'America//New_York', 'America/New_York/', 'America/Not_A_Zone',
    'america/new_york', 'right/UTC', 'posix/UTC', 'localtime', 'zone.tab',
])
def test_invalid_names(value):
    assert not validators.time_zone(value)


def test_database_changes_are_visible_and_external_links_are_rejected(tmp_path, monkeypatch):
    root = tmp_path / 'zoneinfo'
    root.mkdir()
    source = (timezones.ZONEINFO / 'UTC').read_bytes()
    (root / 'UTC').write_bytes(source)
    outside = tmp_path / 'outside'
    outside.write_bytes(source)
    (root / 'Escape').symlink_to(outside)
    monkeypatch.setattr(timezones, 'ZONEINFO', root)

    assert validators.time_zone('UTC')
    assert [item.value for item in suggestors.time_zones(None)] == ['UTC']
    assert not validators.time_zone('Escape')
    (root / 'UTC').unlink()
    assert not validators.time_zone('UTC')
    assert suggestors.time_zones(None) == []


def test_default_and_early_owner():
    schema = Schema.bundled()
    assert schema.defaults({'system': {}})['system']['time-zone'] == 'UTC'
    assert system_timezone.get_config(SimpleNamespace(effective={}))['zone'] == 'UTC'
    assert schema.owners['time-zone'][1] < schema.owners['logging'][1]


def test_cli_completion(controller, session):
    completion = controller.completion('set system time-zone America/New_', session, explicit=True)
    assert 'America/New_York' in dict(completion['candidates'])


def test_prepare_is_read_only_and_apply_preserves_plan(monkeypatch):
    refreshes = []
    monkeypatch.setattr(system_timezone.time, 'tzset', lambda: refreshes.append(True))
    plan = prepare('America/New_York')
    original = deepcopy(plan)
    assert not system_timezone.LOCALTIME.exists()
    assert not system_timezone.TIMEZONE.exists()

    system_timezone.apply(plan, None)

    assert plan == original
    assert system_timezone.TIMEZONE.read_text() == 'America/New_York\n'
    assert os.readlink(system_timezone.LOCALTIME) == '/usr/share/zoneinfo/America/New_York'
    assert refreshes == [True]
    assert prepare('America/New_York') == []


def test_replace_link_does_not_modify_database():
    source = timezones.ZONEINFO / 'UTC'
    before = source.read_bytes()
    system_timezone.LOCALTIME.symlink_to(source)
    system_timezone.TIMEZONE.write_text('UTC\n')

    system_timezone.apply(prepare('Asia/Kathmandu'), None)

    assert source.read_bytes() == before
    assert system_timezone.LOCALTIME.resolve() == (timezones.ZONEINFO / 'Asia/Kathmandu').resolve()


@pytest.mark.parametrize('original', ['missing', 'symlink', 'broken-symlink', 'file'])
def test_failed_application_restores_both_files(original, monkeypatch):
    if original == 'symlink':
        system_timezone.LOCALTIME.symlink_to(timezones.ZONEINFO / 'UTC')
    elif original == 'broken-symlink':
        system_timezone.LOCALTIME.symlink_to('/missing/old-zone')
    elif original == 'file':
        system_timezone.LOCALTIME.write_bytes((timezones.ZONEINFO / 'UTC').read_bytes())
        system_timezone.LOCALTIME.chmod(0o640)
    if original != 'missing':
        system_timezone.TIMEZONE.write_text('UTC\n')
    before = {path: system_timezone.file_state(path)
              for path in (system_timezone.LOCALTIME, system_timezone.TIMEZONE)}
    plan = prepare('America/New_York')
    install = system_timezone.install_file

    def fail_after_replace(path, value):
        install(path, value)
        if path == system_timezone.TIMEZONE and value == plan[1]['after']:
            raise OSError('injected fsync failure')

    monkeypatch.setattr(system_timezone, 'install_file', fail_after_replace)
    with pytest.raises(RouterError, match='Cannot apply time zone'):
        system_timezone.apply(plan, None)
    assert {path: system_timezone.file_state(path) for path in before} == before


def test_compensation_failure_is_reported(monkeypatch):
    plan = prepare('Asia/Tokyo')

    def unavailable(path, value):
        raise OSError('read-only filesystem')

    monkeypatch.setattr(system_timezone, 'install_file', unavailable)
    with pytest.raises(RecoveryError, match='Cannot restore time zone'):
        system_timezone.apply(plan, None)


def test_set_delete_and_saved_recovery(engine, controller, session):
    from nvyr.engine import Engine
    from tests.lifecycle import recorded_registry

    controller.execute('set system time-zone America/New_York', session)
    result = engine.commit(session)
    assert result['results']['time-zone']['success']
    assert system_timezone.TIMEZONE.read_text() == 'America/New_York\n'
    engine.save(session)

    controller.execute('delete system time-zone', session)
    result = engine.commit(session)
    assert result['results']['time-zone']['success']
    assert system_timezone.TIMEZONE.read_text() == 'UTC\n'

    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store, boot_id='timezone-new-boot')
    assert restarted.running['system']['time-zone'] == 'America/New_York'
    assert system_timezone.TIMEZONE.read_text() == 'America/New_York\n'


def test_check_does_not_apply_timezone(engine, controller, session):
    before = {path: system_timezone.file_state(path)
              for path in (system_timezone.LOCALTIME, system_timezone.TIMEZONE)}
    controller.execute('set system time-zone Asia/Tokyo', session)

    engine.check(session)

    assert {path: system_timezone.file_state(path) for path in before} == before


def test_removing_system_restores_utc(engine, controller, session):
    controller.execute('set system time-zone Asia/Tokyo', session)
    engine.commit(session)

    controller.execute('delete system', session)
    result = engine.commit(session)

    assert result['results']['time-zone']['success']
    assert system_timezone.TIMEZONE.read_text() == 'UTC\n'


def test_invalid_cli_and_load_rejected(engine, controller, session):
    with pytest.raises(RouterError, match="Did you mean 'America/New_York'"):
        controller.execute('set system time-zone america/new-york', session)
    with pytest.raises(RouterError, match="Did you mean 'America/New_York'"):
        engine.schema.validate_configuration({'system': {'time-zone': 'america/new-york'}})
    with pytest.raises(RouterError, match='IANA time zone'):
        controller.execute('set system time-zone Invalid/Timezone', session)
    with pytest.raises(RouterError, match='IANA time zone'):
        engine.schema.validate_configuration({'system': {'time-zone': '../etc/passwd'}})
