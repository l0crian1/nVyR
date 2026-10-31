"""Discover CPUFreq capabilities and apply system-wide CPU policy safely.

CPU policies, rather than logical CPU numbers, are the writable units. The
optional energy preference belongs to hardware-managed frequency drivers;
governor writes can change it, so rollback restores governors before preferences.
"""

from pathlib import Path

from nvyr.errors import RecoveryError, RouterError
from nvyr.storage import atomic_json


ROOT = Path('/sys/devices/system/cpu/cpufreq')
BASELINE = Path('/run/nvyr-kernel-settings/cpu.json')
GOVERNORS = {
    'performance': 'Prioritize CPU performance within hardware limits',
    'powersave': 'Favor power savings; behavior depends on the CPU driver',
    'schedutil': 'Adjust CPU frequency using scheduler utilization',
    'ondemand': 'Adjust CPU frequency based on sampled load',
    'conservative': 'Adjust CPU frequency gradually as load changes',
}
PREFERENCES = {
    'performance': 'Prefer performance over energy savings',
    'balance-performance': 'Balance energy use while favoring performance',
    'balance-power': 'Balance performance while favoring energy savings',
    'power': 'Prefer energy savings over performance',
    'default': 'Use the platform default energy preference',
}


def inventory():
    """Read capabilities fresh; CPU drivers and online policies can change."""
    records = []
    for path in sorted(ROOT.glob('policy[0-9]*'), key=lambda path: int(path.name[6:])):
        preference = path / 'energy_performance_preference'
        records.append({
            'policy': path.name,
            'driver': (path / 'scaling_driver').read_text().strip(),
            'governor': (path / 'scaling_governor').read_text().strip(),
            'governors': (path / 'scaling_available_governors').read_text().split(),
            'energy-performance': preference.read_text().strip() if preference.exists() else None,
            'preferences': (path / 'energy_performance_available_preferences').read_text().split()
                           if preference.exists() else [],
        })
    return records


def available(setting, records=None):
    """Offer the supported intersection, using CLI hyphens for preference names."""
    records = inventory() if records is None else records
    names = set(GOVERNORS if setting == 'governor' else PREFERENCES)
    field = 'governors' if setting == 'governor' else 'preferences'
    if not records:
        return []
    for record in records:
        names.intersection_update(value.replace('_', '-') for value in record[field])
    return sorted(names)


def valid_value(value, setting):
    return value in available(setting)


def _write(path, value):
    """Sysfs requires in-place writes; replacing a file is not a kernel operation."""
    path.write_text(value + '\n')


def apply(plan):
    """Write prepared policy values, restoring affected policies on failure."""
    if plan['baseline'] is not None:
        # Persist the original boot values before the first managed sysfs write.
        atomic_json(BASELINE, plan['baseline'])

    changed = []
    try:
        for record in plan['policies']:
            path = ROOT / record['policy']
            # A replaced CPU driver must not receive a plan for its predecessor.
            if (path / 'scaling_driver').read_text().strip() != record['driver']:
                raise RouterError(f"CPU driver changed for {record['policy']} before application")

            selected = record['target-governor']
            preference = record['target-energy-performance']

            changed.append(record)
            if selected != record['governor']:
                _write(path / 'scaling_governor', selected)
            # The governor write may itself have changed EPP; read it again.
            if preference is not None and (path / 'energy_performance_preference').read_text().strip() != preference:
                _write(path / 'energy_performance_preference', preference)
    except Exception as error:
        failures = []
        for record in reversed(changed):
            path = ROOT / record['policy']
            try:
                _write(path / 'scaling_governor', record['governor'])
                if record['energy-performance'] is not None:
                    _write(path / 'energy_performance_preference', record['energy-performance'])
            except OSError as restore_error:
                failures.append(f"{record['policy']}: {restore_error}")
        if failures:
            raise RecoveryError('Could not restore CPU settings: ' + '; '.join(failures)) from error
        raise RouterError(f'Could not apply CPU settings; previous settings restored: {error}') from error
