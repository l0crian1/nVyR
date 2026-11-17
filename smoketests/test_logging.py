"""File collectors and exact firewall log selectors on an installed router."""

from copy import deepcopy
from pathlib import Path

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import assert_config_commit_rejected
from smoketests.assertions import assert_in, assert_false
from smoketests.firewall_support import firewall_environment, firewall_suite
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def logging_suite(config, request, firewall_suite):
    """Install the common logging baseline once, then restore it at module exit."""
    original = deepcopy(config.get_config())

    def standup(session):
        session.set('set system logging level info')
        session.commit()

    def cleanup(session):
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def logging_environment(config, request, logging_suite, firewall_environment):
    """Discard rejected settings without restarting the unchanged collector."""
    with configuration_case(config, request, logging_suite):
        yield


def test_nflog_rejects_kernel_only_options(config):
    """NFLOG must not silently ignore a kernel-only severity or format flag."""
    config.set('set firewall group log-group SMOKELOG4')
    config.set('set firewall ipv4 input filter rule 10 action accept log group SMOKELOG4 level warn')
    assert_config_commit_rejected(config, 'cannot be combined with level or flags')


def test_missing_log_group_rejected(config):
    """An unknown collector must be rejected before any rule is installed."""
    config.set('set firewall ipv4 input filter rule 10 action accept log group UNKNOWN_LOG_GROUP')
    assert_config_commit_rejected(config, 'not configured|does not exist|missing')


@pytest.mark.parametrize(('event', 'mask'), [('new', 1), ('destroy', 4)])
def test_conntrack_event_selection(config, event, mask):
    """Each CLI event selects only its native netlink event bit."""
    config.set(f'set firewall global-options connection-tracking logging event {event}')
    config.commit()
    native = Path('/run/nvyr-logging/conntrack.conf').read_text()
    assert_in(f'event_mask={mask}\n', native)
    assert_in('hash_enable=0\n', native)


def test_conntrack_filters_and_removal(config):
    """Multiple protocols share a subscription and are removed with the collector."""
    config.set('set firewall global-options connection-tracking logging event new')
    config.set('set firewall global-options connection-tracking logging event destroy')
    config.set('set firewall global-options connection-tracking logging filter protocol tcp')
    config.set('set firewall global-options connection-tracking logging filter protocol udp')
    config.commit()
    native = Path('/run/nvyr-logging/conntrack.conf').read_text()
    assert_in('event_mask=5\n', native)
    assert_in('accept_proto_filter="tcp,udp"', native)

    config.delete('delete firewall global-options connection-tracking logging')
    config.commit()
    assert_false(Path('/run/nvyr-logging/conntrack.conf').exists())


def test_conntrack_logging_requires_kernel_events(config):
    """A collector cannot work when its kernel event source is explicitly disabled."""
    config.set('set firewall global-options connection-tracking events disable')
    config.set('set firewall global-options connection-tracking logging event new')
    assert_config_commit_rejected(config, 'requires events auto or enable')


def test_conntrack_logging_requires_event_selection(config):
    """Filters alone must not silently select a default event set."""
    config.set('set firewall global-options connection-tracking logging filter protocol udp')
    assert_config_commit_rejected(config, 'at least one event is required')
