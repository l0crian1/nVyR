import os

import pytest
from nvyr.engine import Engine
from nvyr.schema import Schema
from nvyr.storage import Store
from tests.lifecycle import recorded_registry


@pytest.fixture(autouse=True)
def isolated_umask():
    """Entry-point tests may set a private umask; do not leak it to later tests."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture(autouse=True)
def isolated_network_profiles(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from nvyr.config_scripts import protocols_bgp, system_timezone
    from nvyr.helpers import logging_runtime
    from nvyr.helpers import kernel_settings
    from nvyr.helpers import cpu_settings

    # Unit engine startup must never change the development host's CPU governor.
    monkeypatch.setattr(cpu_settings, 'ROOT', tmp_path / 'cpufreq')
    monkeypatch.setattr(cpu_settings, 'BASELINE', tmp_path / 'cpu-baseline.json')

    # Default timezone recovery must never replace the test host's localtime files.
    monkeypatch.setattr(system_timezone, 'LOCALTIME', tmp_path / 'localtime')
    monkeypatch.setattr(system_timezone, 'TIMEZONE', tmp_path / 'timezone')

    monkeypatch.setattr(kernel_settings, 'manager', SimpleNamespace(transaction=lambda *args, **kwargs: nullcontext()))
    monkeypatch.setattr(logging_runtime, "install", lambda *args, **kwargs: None)
    monkeypatch.setattr(logging_runtime, "cleanup", lambda *args, **kwargs: None)
    monkeypatch.setattr(logging_runtime, "prepare_groups", lambda *args, **kwargs: None)
    from nvyr.helpers import interfaces, suggestors, nftables, ssh, accounts, system, frr_reload, kea, ntp
    from nvyr.config_scripts import container as containers

    monkeypatch.setattr(system, 'apply_hostname', lambda *args, **kwargs: None)
    monkeypatch.setattr(accounts, 'manager', SimpleNamespace(verify=lambda *args, **kwargs: None,
                                                           apply=lambda *args, **kwargs: None))

    # Only opt-in container tests may program the real packet filter.
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None,
                                                          named_chains=lambda: [], flowtables=lambda: [], icmp_groups=lambda: [], singleton_groups=lambda: [], match_groups=lambda: [], maps=lambda: [], rule_limits=lambda: [], named_state=lambda: [], table_exists=lambda name: False))
    monkeypatch.setattr(ssh, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None))
    monkeypatch.setattr(ntp, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None))
    monkeypatch.setattr(kea, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None))
    monkeypatch.setattr(containers.worker, 'run_apply', lambda *args, **kwargs: None)
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None))
    monkeypatch.setattr(suggestors, 'cmd', lambda command: '[]')
    monkeypatch.setattr(protocols_bgp, 'local_addresses', lambda **kwargs: set())

    # Ordinary engine tests never program interfaces or contact the real daemon.
    monkeypatch.setattr(interfaces, 'manager', SimpleNamespace(
        apply=lambda *args, **kwargs: None, validate=lambda *args, **kwargs: None,
        replace=lambda *args, **kwargs: None,
        request=lambda *args, **kwargs: {}))


@pytest.fixture
def engine(tmp_path):
    schema = Schema.bundled()
    modules = recorded_registry(schema)

    def generate_container(configuration, context):
        # Engine tests exercise schema/verification; native generation has its own tests.
        modules['container']._stage('generate', context)
        return None

    modules['container'].generate = generate_container
    return Engine(schema, modules, Store(tmp_path))


@pytest.fixture
def session(engine):
    return engine.open("alice", "/dev/pts/1")


@pytest.fixture
def controller(engine):
    from nvyr.controller import Controller

    return Controller(engine)
