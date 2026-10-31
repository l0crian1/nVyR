"""CPU policy discovery, driver restrictions, rollback and lifecycle integration."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import system_cpu
from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers import cpu_settings, suggestors, validators
from nvyr.modules import registry


def gathered(settings):
    return system_cpu.get_config(SimpleNamespace(effective={'system': {'cpu': settings}}))


def apply_settings(settings):
    configuration = gathered(settings)
    system_cpu.verify(configuration, None)
    plan = system_cpu.generate(configuration, None)
    system_cpu.apply(plan, None)


def policy(name='policy0', *, driver='intel_pstate', governors='performance powersave',
           governor='powersave', preference='balance_performance'):
    path = cpu_settings.ROOT / name
    path.mkdir(parents=True)
    fields = {'scaling_driver': driver, 'scaling_available_governors': governors,
              'scaling_governor': governor}
    if preference is not None:
        fields.update(energy_performance_preference=preference,
                      energy_performance_available_preferences='default performance balance_performance balance_power power')
    for field, value in fields.items():
        (path / field).write_text(value + '\n')
    return path


def test_dynamic_completion_and_validation_intersect_all_policies():
    policy()
    second = policy('policy1', driver='intel_cpufreq', governors='performance schedutil',
                    governor='schedutil', preference=None)
    items = suggestors.cpu_policy(None, 'governor')
    assert [(item.value, item.description) for item in items] == [
        ('performance', 'Prioritize CPU performance within hardware limits')]
    assert validators.cpu_policy('performance', 'governor')
    assert not validators.cpu_policy('powersave', 'governor')
    assert not validators.cpu_policy('balance-power', 'energy-performance')

    # A later capability change is visible without restarting configd.
    (second / 'scaling_available_governors').write_text('performance powersave')
    assert validators.cpu_policy('powersave', 'governor')


def test_unexposed_cpu_controls_allow_boot_but_reject_explicit_configuration():
    system_cpu.verify(gathered({}), None)
    apply_settings({})
    assert cpu_settings.available('governor') == []
    assert not validators.cpu_policy('performance', 'governor')
    with pytest.raises(ValidationError, match='not supported'):
        system_cpu.verify(gathered({'governor': 'performance'}), None)
    with pytest.raises(ValidationError, match='not supported'):
        system_cpu.verify(gathered({'energy-performance': 'performance'}), None)


def test_unsupported_performance_retains_boot_governor_on_override_removal():
    path = policy(driver='other', governors='schedutil conservative', governor='schedutil', preference=None)
    apply_settings({})
    assert (path / 'scaling_governor').read_text().strip() == 'schedutil'
    apply_settings({'governor': 'conservative'})
    apply_settings({})
    assert (path / 'scaling_governor').read_text().strip() == 'schedutil'


@pytest.mark.parametrize('driver', ['intel_pstate', 'amd-pstate-epp'])
def test_active_drivers_reject_incompatible_preferences_before_writes(driver):
    path = policy(driver=driver)
    with pytest.raises(ValidationError, match='requires energy-performance performance'):
        apply_settings({'governor': 'performance', 'energy-performance': 'balance-power'})
    assert (path / 'scaling_governor').read_text().strip() == 'powersave'
    assert not cpu_settings.BASELINE.exists()


def test_boot_performance_override_and_removal_restore_pre_management_preference():
    path = policy()
    apply_settings({})
    assert (path / 'scaling_governor').read_text().strip() == 'performance'
    assert (path / 'energy_performance_preference').read_text().strip() == 'performance'

    apply_settings({'governor': 'powersave', 'energy-performance': 'balance-power'})
    assert (path / 'energy_performance_preference').read_text().strip() == 'balance_power'
    apply_settings({'governor': 'powersave'})
    assert (path / 'energy_performance_preference').read_text().strip() == 'balance_performance'
    apply_settings({})
    assert (path / 'scaling_governor').read_text().strip() == 'performance'
    assert json.loads(cpu_settings.BASELINE.read_text())['policy0']['energy-performance'] == 'balance_performance'


@pytest.mark.parametrize('driver', ['intel_cpufreq', 'amd-pstate', 'acpi-cpufreq'])
def test_passive_drivers_apply_governors_without_epp(driver):
    path = policy(driver=driver, governors='performance schedutil', governor='schedutil', preference=None)
    apply_settings({})
    assert (path / 'scaling_governor').read_text().strip() == 'performance'
    apply_settings({'governor': 'schedutil'})
    assert (path / 'scaling_governor').read_text().strip() == 'schedutil'


def test_failed_write_restores_governor_and_implicit_epp_changes(monkeypatch):
    first = policy()
    second = policy('policy1')
    write = cpu_settings._write

    def reject(path, value):
        if path == second / 'scaling_governor' and value == 'performance':
            raise OSError('rejected')
        write(path, value)
        if path.name == 'scaling_governor' and value == 'performance':
            write(path.parent / 'energy_performance_preference', 'performance')

    monkeypatch.setattr(cpu_settings, '_write', reject)
    with pytest.raises(RouterError, match='previous settings restored'):
        apply_settings({})
    for path in (first, second):
        assert (path / 'scaling_governor').read_text().strip() == 'powersave'
        assert (path / 'energy_performance_preference').read_text().strip() == 'balance_performance'


def test_restore_failure_is_not_hidden(monkeypatch):
    policy()
    monkeypatch.setattr(cpu_settings, '_write', lambda *args: (_ for _ in ()).throw(OSError('gone')))
    with pytest.raises(RecoveryError, match='Could not restore CPU settings'):
        apply_settings({})


def test_schema_has_no_injected_cpu_default_and_uses_real_lifecycle(controller, session):
    path = policy()
    schema = controller.engine.schema
    assert 'cpu' not in schema.defaults({'system': {}}).get('system', {})
    assert registry(schema)['cpu'].__name__ == 'nvyr.config_scripts.system_cpu'
    controller.execute('set system cpu governor powersave energy-performance balance-power', session)
    controller.execute('commit', session)
    assert controller.engine.running['system']['cpu'] == {'governor': 'powersave', 'energy-performance': 'balance-power'}
    assert (path / 'energy_performance_preference').read_text().strip() == 'balance_power'
    controller.execute('delete system cpu', session)
    controller.execute('commit', session)
    assert (path / 'scaling_governor').read_text().strip() == 'performance'


def test_cpu_display_reports_actual_policy(monkeypatch):
    from nvyr.op_scripts import system

    policy()
    monkeypatch.setattr(system, 'cmd', lambda *args, **kwargs: json.dumps({'lscpu': [], 'cpus': []}))
    result = json.loads(system.cpu(raw=True))
    assert result['Frequency driver'] == 'intel_pstate'
    assert result['Governor'] == 'powersave'
    assert result['Energy preference'] == 'balance-performance'


def test_cpu_sysfs_mount_is_optional_and_narrow():
    unit = Path('packaging/nvyr-configd.service').read_text()
    assert 'ReadWritePaths=-/sys/devices/system/cpu/cpufreq' in unit
    assert 'ProtectKernelTunables=true' in unit


def test_configd_startup_applies_boot_policy_without_publishing_config(tmp_path):
    from nvyr.engine import Engine
    from nvyr.schema import Schema
    from nvyr.storage import Store
    from tests.lifecycle import recorded_registry

    path = policy()
    schema = Schema.bundled()
    store = Store(tmp_path / 'state')
    engine = Engine(schema, recorded_registry(schema), store)
    assert engine.running == {}
    assert (path / 'scaling_governor').read_text().strip() == 'performance'

    # A daemon restart retains the original EPP baseline, rather than capturing
    # the performance preference applied by the preceding daemon instance.
    Engine(schema, recorded_registry(schema), store)
    apply_settings({'governor': 'powersave'})
    assert (path / 'energy_performance_preference').read_text().strip() == 'balance_performance'


def test_prepared_cpu_plan_does_not_mutate_gathered_inputs_or_repeat_inventory(monkeypatch):
    from copy import deepcopy
    from nvyr.tree import ReadOnlyTree

    path = policy()
    configuration = system_cpu.get_config(SimpleNamespace(effective=ReadOnlyTree({})))
    before = deepcopy(configuration)
    monkeypatch.setattr(cpu_settings, 'inventory', lambda: pytest.fail('repeated inventory'))

    system_cpu.verify(configuration, None)
    plan = system_cpu.generate(configuration, None)
    prepared = deepcopy(plan)
    assert not cpu_settings.BASELINE.exists()
    assert (path / 'scaling_governor').read_text().strip() == 'powersave'

    system_cpu.apply(plan, None)

    assert configuration == before
    assert plan == prepared
    assert (path / 'scaling_governor').read_text().strip() == 'performance'


def test_hardware_support_is_rechecked_after_cli_entry():
    path = policy()
    assert validators.cpu_policy('powersave', 'governor')
    (path / 'scaling_available_governors').write_text('performance')

    with pytest.raises(ValidationError, match='not supported'):
        apply_settings({'governor': 'powersave'})
    assert not cpu_settings.BASELINE.exists()


def test_replaced_driver_is_not_written_and_prior_policy_is_restored():
    first = policy()
    second = policy('policy1')
    configuration = gathered({})
    system_cpu.verify(configuration, None)
    plan = system_cpu.generate(configuration, None)
    (second / 'scaling_driver').write_text('replacement')

    with pytest.raises(RouterError, match='CPU driver changed'):
        system_cpu.apply(plan, None)

    assert (first / 'scaling_governor').read_text().strip() == 'powersave'
    assert (first / 'energy_performance_preference').read_text().strip() == 'balance_performance'
    assert (second / 'scaling_governor').read_text().strip() == 'powersave'
