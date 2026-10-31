"""CPU configuration to sysfs translation, removal and incompatible settings.

No timing or throughput assertions. Hardware without CPUFreq/EPP skips the
corresponding checks; no CPU driver or firmware changes are required.
"""

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import cpu_settings
from smoketests.support import configuration_case


@pytest.fixture(autouse=True)
def cpu_environment(config, request):
    with configuration_case(config, request, config.get_config()):
        yield


def test_performance_governor(config):
    if 'performance' not in cpu_settings.available('governor'):
        pytest.skip('Performance governor not exposed by every CPU policy')
    config.delete('delete system cpu')
    config.set('set system cpu governor performance')
    config.commit()
    assert all(record['governor'] == 'performance' for record in cpu_settings.inventory())


def test_dynamic_governor_and_removal(config):
    available = cpu_settings.available('governor')
    governor = next((value for value in ('schedutil', 'powersave', 'ondemand', 'conservative') if value in available), None)
    if governor is None or 'performance' not in available:
        pytest.skip('A dynamic governor and performance are required')
    config.delete('delete system cpu')
    config.set(f'set system cpu governor {governor}')
    config.commit()
    assert all(record['governor'] == governor for record in cpu_settings.inventory())

    config.delete('delete system cpu governor')
    config.commit()
    assert all(record['governor'] == 'performance' for record in cpu_settings.inventory())


def test_energy_preference(config):
    if ('powersave' not in cpu_settings.available('governor')
            or 'balance-power' not in cpu_settings.available('energy-performance')):
        pytest.skip('Powersave governor and balance-power EPP are required')
    config.delete('delete system cpu')
    config.set('set system cpu governor powersave energy-performance balance-power')
    config.commit()
    assert all(record['energy-performance'] == 'balance_power' for record in cpu_settings.inventory())


def test_invalid_governor(config):
    with pytest.raises(RouterError):
        config.set('set system cpu governor nonexistent')


def test_invalid_energy_preference(config):
    with pytest.raises(RouterError):
        config.set('set system cpu energy-performance nonexistent')


def test_incompatible_governor_and_preference(config):
    if ('balance-power' not in cpu_settings.available('energy-performance')
            or not any(record['driver'] in ('intel_pstate', 'amd-pstate-epp') for record in cpu_settings.inventory())):
        pytest.skip('An active P-state driver with balance-power EPP is required')
    config.delete('delete system cpu')
    config.set('set system cpu governor performance energy-performance balance-power')
    with pytest.raises(RouterError, match='requires energy-performance performance'):
        config.commit()
