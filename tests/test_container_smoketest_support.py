"""Test workload quoting and cleanup without touching Podman or the host network."""

from types import SimpleNamespace
import shlex

import pytest

from smoketests import container_support
from tests.test_static_smoketest import local_session


@pytest.fixture
def reserved_suite(local_session, monkeypatch):
    monkeypatch.setattr(container_support, 'cmd', lambda argv: '[]')
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    fixture = container_support.container_suite.__wrapped__(local_session, request)
    cleanup = next(fixture)
    try:
        yield cleanup
    finally:
        with pytest.raises(StopIteration):
            next(fixture)


def test_rejected_case_cleanup_does_not_commit(local_session, reserved_suite, monkeypatch):
    local_session.set('set container name NVYRSMOKE')
    commits = []
    monkeypatch.setattr(local_session, 'commit', lambda: commits.append(True))

    reserved_suite(local_session)

    assert commits == []
    assert 'NVYRSMOKE' not in local_session.get_config().get('container', {}).get('name', {})


def test_cleanup_keeps_shared_network_and_removes_workload(local_session, reserved_suite):
    local_session.set('set container network NVYRBASE subnet 198.18.232.0/24')
    local_session.set('set container name NVYRSMOKE image alpine network NVYRBASE')
    local_session.commit()

    reserved_suite(local_session)

    running = local_session.get_config()
    assert 'NVYRBASE' in running['container']['network']
    assert 'NVYRSMOKE' not in running['container']['name']


@pytest.mark.parametrize('entrypoint', [False, True])
def test_idle_workload_preserves_shell_argument_through_cli(local_session, entrypoint):
    local_session.set('set container name NVYRSMOKE image alpine')
    container_support.idle_container(local_session, entrypoint=entrypoint)
    local_session.commit()

    container = local_session.get_config()['container']['name']['NVYRSMOKE']
    assert container['entrypoint' if entrypoint else 'command'] == 'sh'
    arguments = shlex.split(container['argument'])
    assert arguments == ['-c', 'trap \'exit 0\' TERM INT; while :; do sleep 3600 & wait "$!"; done']
