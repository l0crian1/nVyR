"""Shared session, options and reporting for both installed live test suites."""

import os
import sys

import pytest

from smoketests.support import SmokeSession, defer_interrupt, preserved_configuration
from smoketests.reporting import SmokeReporter


def configure(config):
    """Register one session fixture and reporter even when both suites are selected."""
    if not config.pluginmanager.hasplugin('nvyr-live-fixtures'):
        config.pluginmanager.register(sys.modules[__name__], 'nvyr-live-fixtures')
        config.pluginmanager.register(SmokeReporter(config, label='Live-test'), 'nvyr-live-reporting')


def add_options(parser):
    """Both suite entry points share a single set of command-line options."""
    if getattr(parser, '_nvyr_live_options_added', False):
        return
    parser._nvyr_live_options_added = True
    group = parser.getgroup('nvyr live tests')
    group.addoption('--smoke-session-timeout', type=int, default=28800,
                    help='Total configd session lifetime in seconds (default: 28800)')
    group.addoption('--ethernet-interface', help='Explicit spare Ethernet port: unused and down, or configured with an empty profile')
    group.addoption('--ethernet-dhcp', action='store_true',
                    help='Also require a DHCP lease and renewal on the selected spare port')
    group.addoption('--container-image',
                    help='Preloaded BusyBox-compatible image for container workload tests (no automatic downloads)')


@pytest.fixture(scope='session')
def config(request):
    """Hold one configuration session and backup across the entire live test run.

    Per-test fixtures prepare their own features; original configuration is
    restored once after all scripts finish. Defer interrupts while opening and
    closing the session so cleanup cannot strand a partially managed connection.
    """
    if sys.platform != 'linux' or os.geteuid() != 0:
        pytest.fail('Live tests must run as root on an nVyR test router.', pytrace=False)

    if request.config.getoption('numprocesses', default=0):
        pytest.fail('Live tests must run sequentially; do not use pytest-xdist.', pytrace=False)

    timeout = request.config.getoption('--smoke-session-timeout')
    if timeout <= 0:
        pytest.fail('--smoke-session-timeout must be positive.', pytrace=False)

    session = None
    try:
        with defer_interrupt():
            session = SmokeSession(timeout=timeout)

        terminal = request.config.pluginmanager.getplugin('terminalreporter')
        report = terminal.write_line if terminal is not None else print
        with preserved_configuration(session, report=report):
            yield session
    finally:
        if session is not None:
            with defer_interrupt():
                session.exit()
