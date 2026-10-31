"""Gather, verify and prepare system-wide CPU policy before sysfs application."""

import json

from nvyr.errors import ValidationError
from nvyr.helpers import cpu_settings
from nvyr.tree import lookup


def get_config(context):
    baseline = cpu_settings.BASELINE
    return {
        'settings': lookup(context.effective, ('system', 'cpu'), {}),
        'records': cpu_settings.inventory(),
        'baseline': json.loads(baseline.read_text()) if baseline.exists() else {},
    }


def verify(configuration, context):
    records = configuration['records']
    configuration = configuration['settings']
    governor = lookup(configuration, ('governor',), 'performance')
    preference = lookup(configuration, ('energy-performance',), None)

    # Only explicit governors require support everywhere. The unconfigured boot
    # policy selects performance where available and leaves other policies alone.
    if 'governor' in configuration and governor not in cpu_settings.available('governor', records):
        raise ValidationError(f'system cpu governor {governor}: not supported by every CPU policy')

    # Energy preferences require the actual driver attribute on every policy.
    if preference is not None and preference not in cpu_settings.available('energy-performance', records):
        raise ValidationError(f'system cpu energy-performance {preference}: not supported by every CPU policy')

    for record in records:
        selected = governor if governor in record['governors'] else record['governor']
        # Active Intel/AMD performance governors force performance EPP and reject
        # conflicting writes; reject the combination before changing any policy.
        if (record['driver'] in ('intel_pstate', 'amd-pstate-epp') and selected == 'performance'
                and preference not in (None, 'performance')):
            raise ValidationError('system cpu: the performance governor requires energy-performance performance or omission')


def generate(configuration, context):
    settings = configuration['settings']
    baseline = configuration['baseline']
    updated = dict(baseline)
    policies = []

    for record in configuration['records']:
        name = record['policy']
        # Preserve boot values across commits and daemon restarts so removing an
        # override restores the baseline rather than the last configured value.
        if updated.get(name, {}).get('driver') != record['driver']:
            updated[name] = {
                'driver': record['driver'],
                'governor': 'performance' if 'performance' in record['governors'] else record['governor'],
                'energy-performance': record['energy-performance'],
            }

        selected = lookup(settings, ('governor',), updated[name]['governor'])
        preference = lookup(settings, ('energy-performance',), None)
        if preference is not None:
            preference = preference.replace('-', '_')
        elif record['driver'] in ('intel_pstate', 'amd-pstate-epp') and selected == 'performance':
            preference = 'performance' if record['energy-performance'] is not None else None
        else:
            preference = updated[name]['energy-performance']

        policies.append(record | {'target-governor': selected, 'target-energy-performance': preference})

    return {'policies': policies, 'baseline': updated if updated != baseline else None}


def apply(plan, context):
    cpu_settings.apply(plan)
