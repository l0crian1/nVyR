"""Timezone CLI translation, UTC removal, and invalid-name rejection.

The suite restores the original configuration after each case. It inspects the
host's timezone files and operational date output; it does not change the clock
or test NTP synchronization.
"""

from pathlib import Path

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_operational_output
from smoketests.support import configuration_case


@pytest.fixture(autouse=True)
def timezone_environment(config, request):
    with configuration_case(config, request, config.get_config()):
        yield


def test_named_timezone(config):
    config.set('set system time-zone America/New_York')
    config.commit()

    assert Path('/etc/timezone').read_text() == 'America/New_York\n'
    assert Path('/etc/localtime').resolve() == Path('/usr/share/zoneinfo/America/New_York').resolve()
    assert_operational_output('show date', cmd(['date', '+%Z']).strip())


def test_fractional_offset_timezone(config):
    config.set('set system time-zone Asia/Kathmandu')
    config.commit()

    assert Path('/etc/timezone').read_text() == 'Asia/Kathmandu\n'
    assert cmd(['date', '+%z']).strip() == '+0545'


def test_delete_restores_utc(config):
    config.set('set system time-zone Asia/Tokyo')
    config.commit()
    config.delete('delete system time-zone')
    config.commit()

    assert Path('/etc/timezone').read_text() == 'UTC\n'
    assert Path('/etc/localtime').resolve() == Path('/usr/share/zoneinfo/UTC').resolve()
    assert_operational_output('show date', 'UTC')


def test_invalid_timezone(config):
    with pytest.raises(RouterError, match='IANA time zone'):
        config.set('set system time-zone America/Not_A_Zone')


def test_timezone_path_traversal(config):
    with pytest.raises(RouterError, match='IANA time zone'):
        config.set('set system time-zone ../etc/passwd')
