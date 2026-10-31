"""Register the shared live-router test session and command-line options."""

from smoketests import live


def pytest_addoption(parser):
    live.add_options(parser)


def pytest_configure(config):
    live.configure(config)
