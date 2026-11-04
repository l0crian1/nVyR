"""Verify Linux bond attributes across mode changes without rebuilding the test ports."""

from pathlib import Path

import pytest

from smoketests.assertions import assert_config_commit_rejected, assert_link
from smoketests.interface_support import interface_suite


@pytest.fixture(scope='module')
def ports(config, request):
    with interface_suite(config, request, {'bond': ['bond990'], 'dummy': ['dum990', 'dum991']}, [
        'set interfaces dummy dum990', 'set interfaces dummy dum991',
        'set interfaces bond bond990 mode active-backup',
        'set interfaces bond bond990 member interface dum990',
        'set interfaces bond bond990 member interface dum991',
    ]) as reset:
        yield reset


def test_monitor_and_primary(config, ports):
    config.set('set interfaces bond bond990 primary dum991')
    config.set('set interfaces bond bond990 link-monitor mii interval 50ms up-delay 100ms')
    config.commit()
    data = assert_link('bond990', kind='bond', up=True)['linkinfo']['info_data']
    assert data['miimon'] == 50 and data['updelay'] == 100
    assert Path('/sys/class/net/bond990/bonding/primary').read_text().strip() == 'dum991'
    ports()


def test_lacp_only_options(config, ports):
    config.set('set interfaces bond bond990 lacp rate fast')
    assert_config_commit_rejected(config, 'require mode 802.3ad')
    config.set('set interfaces bond bond990 mode 802.3ad')
    config.commit()
    assert_link('dum990', master='bond990')
    data = assert_link('bond990', kind='bond', up=True)['linkinfo']['info_data']
    assert data['ad_lacp_rate'] == 'fast'
    ports()
