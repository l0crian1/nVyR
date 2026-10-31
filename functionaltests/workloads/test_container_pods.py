"""Four independent pods installed together for runtime and mutation coverage.

Tests IPv4 shared localhost, IPv6 attachment, member replacement without sibling
restart, pod hostname, disable/enable and explicit restart. All pods coexist;
mutation cases own separate pods. Whole-tree/network deletion is incompatible.
"""

import json
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd, rc_cmd
from nvyr.op_scripts import containers as operations
from smoketests.assertions import assert_equal, assert_in, assert_not_equal
from functionaltests.container_scenarios import container_socket


def test_ipv4_pod_shared_localhost():
    """Two members share one IPv4 attachment and reach each other over localhost."""
    first = json.loads(cmd(['podman', 'inspect', 'P4FIRST']))[0]
    second = json.loads(cmd(['podman', 'inspect', 'P4SECOND']))[0]
    assert_equal(first['Pod'], second['Pod'])
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'pd-POD4-0']))[0]
    assert_equal(link['master'], 'pd-PODLAN4')
    # Exercise the actual member network namespaces without assuming an HTTP server in the image.
    with container_socket('P4SECOND') as listener, container_socket('P4FIRST') as sender:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        sender.connect(listener.getsockname())
        receiver, _ = listener.accept()
        with receiver:
            receiver.settimeout(3)
            sender.sendall(b'shared')
            assert_equal(receiver.recv(64), b'shared')
    assert_in('198.18.240.10/24', operations.pods(name='POD4'))


def test_pod_member_change_preserves_sibling(config):
    """Changing one workload's memory does not recreate the other member."""
    sibling = json.loads(cmd(['podman', 'inspect', 'PMSECOND']))[0]['Id']

    config.set('set container name PMFIRST memory 64m')
    config.commit()
    assert_equal(json.loads(cmd(['podman', 'inspect', 'PMSECOND']))[0]['Id'], sibling)


def test_pod_disable_restart_and_hostname(config):
    """Pod disable stops its members, and restart recreates the enabled shared service."""
    assert_equal(cmd(['podman', 'exec', 'PLFIRST', 'hostname']).strip(), 'shared-host')
    before = json.loads(cmd(['podman', 'inspect', 'PLFIRST']))[0]['Id']
    operations.restart_pod('PODLIFE')
    assert_not_equal(json.loads(cmd(['podman', 'inspect', 'PLFIRST']))[0]['Id'], before)

    config.set('set container pod PODLIFE disable')
    config.commit()
    assert_equal(rc_cmd(['podman', 'container', 'exists', 'PLFIRST'])[0], 1)
    config.delete('delete container pod PODLIFE disable')
    config.commit()
    assert_equal(json.loads(cmd(['podman', 'inspect', 'PLFIRST']))[0]['State']['Running'], True)


def test_ipv6_pod_attachment():
    """IPv6 uses the same pod-owned attachment and address configuration."""
    assert_in('fd00:230::10/64', operations.pods(name='POD6'))
