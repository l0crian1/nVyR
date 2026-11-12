"""Firewall boot ordering and continued interface recovery after a load failure."""

import pytest

from nvyr.errors import RouterError


def startup_configuration():
    return {
        'vrf': {'name': {'BLUE': {'table': '100'}}},
        'interfaces': {'dummy': {'dum9': {'vrf': 'BLUE'}}},
        'firewall': {
            'flowtable': {'FUTURE': {'interface': ['dum9']}},
            'ipv4': {'input': {'filter': {'rule': {
                '10': {'inbound-interface': ['dum9'], 'action': 'accept'},
            }}}},
        },
    }


def test_startup_applies_firewall_after_zones_and_vrfs_before_interfaces(engine, monkeypatch):
    applied = []
    monkeypatch.setattr(engine, '_lifecycle', lambda owner, *args, **kwargs: applied.append(owner))

    engine._run_recovery(startup_configuration(), {},
                         {'vrf_conntrack', 'vrf', 'firewall', 'dummy'}, startup=True)

    assert applied == ['vrf_conntrack', 'vrf', 'firewall', 'dummy']


def test_firewall_failure_does_not_stop_interface_startup(engine, monkeypatch):
    applied = []

    def apply(owner, *args, **kwargs):
        applied.append(owner)
        if owner == 'firewall':
            raise RouterError('Native firewall installation failed')

    monkeypatch.setattr(engine, '_lifecycle', apply)

    with pytest.raises(RouterError, match='Recovery failed for firewall'):
        engine._run_recovery(startup_configuration(), {},
                             {'vrf_conntrack', 'vrf', 'firewall', 'dummy'}, startup=True)

    assert applied == ['vrf_conntrack', 'vrf', 'firewall', 'dummy']


def test_firewall_nat_and_nat66_share_early_priority(engine):
    schema = engine.schema
    for root in ('firewall', 'nat', 'nat66'):
        assert schema.resolve((root,)).owner == 'firewall'
    assert schema.owners['vrf'][1] < schema.owners['firewall'][1] < schema.owners['dummy'][1]
    assert 'firewall_failsafe' not in schema.owners
