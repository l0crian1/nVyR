"""Compact live-test progress, retaining pytest's diagnostics and result counts."""

from pathlib import Path
from textwrap import shorten

import pytest
from tabulate import tabulate


class SmokeReporter:
    def __init__(self, config, *, label="Smoketest"):
        self.config = config
        self.label = label
        self.script = None
        self.progress = False
        self.failures = []

    def pytest_runtest_logstart(self, nodeid, location):
        script = location[0]
        if script != self.script:
            self.script = script
            terminal = self.config.pluginmanager.getplugin('terminalreporter')
            if terminal is not None:
                terminal.write_line(f'\n########## {Path(script).name} ##########')

    @pytest.hookimpl(wrapper=True)
    def pytest_report_teststatus(self, report, config):
        result = yield
        if self.progress:
            # Keep the category for pytest's counts, suppress only its progress text.
            return result[0], '', ''

        return result

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_logreport(self, report):
        self.progress = True
        try:
            result = yield
        finally:
            self.progress = False

        if report.failed:
            script, name = report.nodeid.split('::', 1)
            crash = getattr(report.longrepr, 'reprcrash', None)
            reason = crash.message if crash is not None else report.longreprtext
            phase = {'setup': 'Setup', 'call': 'Test', 'teardown': 'Cleanup'}[report.when]
            self.failures.append((Path(script).name, name, phase, shorten(reason, width=160)))

        terminal = self.config.pluginmanager.getplugin('terminalreporter')
        if terminal is not None:
            category, letter, word = self.config.hook.pytest_report_teststatus(report=report, config=self.config)
            markup = {}
            if isinstance(word, tuple):
                word, markup = word

            if word == 'FAILED':
                word = 'FAIL'

            if word:
                # Parameter values can contain IPv6 addresses with "::".
                name = report.nodeid.split('::', 1)[1]
                phase = f' ({report.when})' if report.when != 'call' else ''
                # Preserve our padding when rendering each result independently.
                row = tabulate(
                    [[name.ljust(90), f'{word}{phase}']],
                    tablefmt='presto', colalign=(None, None),
                )
                terminal.write_line(row, **markup)

        return result

    @pytest.hookimpl(trylast=True)
    def pytest_terminal_summary(self, terminalreporter):
        if self.failures:
            terminalreporter.write_sep('=', f'{self.label} failures')
            terminalreporter.write_line(tabulate(
                self.failures, headers=['Script', 'Test', 'Phase', 'Reason'],
                maxcolwidths=[None, None, None, 80],
            ))
