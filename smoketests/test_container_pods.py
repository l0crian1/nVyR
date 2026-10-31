"""Pods share network attachments while retaining independent workload settings."""

import json

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_commit_rejected, assert_equal, assert_raises
from smoketests.container_support import container_environment, container_suite, idle_container, image


def test_ipv6_pod_attachment(config, image):
    """IPv6 uses the same pod-owned attachment and address configuration."""
    config.set('set container network NVYRSMOKE subnet fd00:230::/64')
    config.set('set container pod NVYRPOD network NVYRSMOKE address fd00:230::10')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE pod NVYRPOD')
    config.commit()
    pod = json.loads(cmd(['podman', 'pod', 'inspect', 'NVYRPOD']))[0]
    infra = json.loads(cmd(['podman', 'inspect', pod['InfraContainerID']]))[0]
    assert_equal(infra['NetworkSettings']['Networks']['NVYRSMOKE']['GlobalIPv6Address'], 'fd00:230::10')


def test_pod_multiple_attachments(config, image):
    """Distinct IDs create the requested shared host-side veth names."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE2 subnet 198.18.231.0/24')
    config.set('set container pod NVYRPOD network NVYRSMOKE id 0')
    config.set('set container pod NVYRPOD network NVYRSMOKE2 id 9')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE pod NVYRPOD')
    config.commit()
    assert_equal(json.loads(cmd(['ip', '-j', 'link', 'show', 'pd-NVYRPOD-0']))[0]['master'], 'pd-NVYRSMOKE')
    assert_equal(json.loads(cmd(['ip', '-j', 'link', 'show', 'pd-NVYRPOD-9']))[0]['master'], 'pd-NVYRSMOKE2')


def test_pod_name_collision_rejected(config):
    """Pod and container names share one namespace."""
    config.set('set container pod NVYRSMOKE')
    config.set('set container name NVYRSMOKE image alpine')
    assert_config_commit_rejected(config, 'names must be distinct')


def test_pod_member_network_override_rejected(config):
    """Network ownership cannot be split between a pod and its member."""
    config.set('set container pod NVYRPOD')
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine')
    config.set('set container name NVYRSMOKE pod NVYRPOD network NVYRSMOKE')
    assert_config_commit_rejected(config, 'pod membership conflicts')


def test_pod_duplicate_attachment_ids_rejected(config):
    """Default attachment IDs participate in uniqueness validation."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE2 subnet 198.18.231.0/24')
    config.set('set container pod NVYRPOD network NVYRSMOKE')
    config.set('set container pod NVYRPOD network NVYRSMOKE2')
    assert_config_commit_rejected(config, 'duplicate id 0')


def test_pod_deletion_reference_protection(config, image):
    """A configured member protects the pod from accidental deletion."""
    config.set('set container pod NVYRPOD')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE pod NVYRPOD')
    config.commit()
    with assert_raises(Exception, match='referenced by'):
        config.delete('delete container pod NVYRPOD')
