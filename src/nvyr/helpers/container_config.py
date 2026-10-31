"""Shared container object names and filesystem paths."""

from pathlib import Path


RUNTIME = Path('/run/nvyr-containers')
VOLUME_ROOT = '/config/containers'
MOUNT_ROOT = '/run/nvyr-containers/mounts'


def bridge_name(network):
    return 'pd-' + network


def veth_name(container, attachment):
    return f'pd-{container}-{int(attachment.get("id", "0"))}'


def interface_owners(configuration):
    """Map generated host interfaces to their owning native object."""
    owners = {bridge_name(name): ('network', name) for name in configuration.get('network', {})}
    for section, kind in (('name', 'container'), ('pod', 'pod')):
        for name, owner in configuration.get(section, {}).items():
            if 'disable' not in owner:
                for attachment in owner.get('network', {}).values():
                    owners[veth_name(name, attachment)] = (kind, name)
    return owners


def unit_name(name):
    return 'nvyr-container-' + name.encode().hex()


def pod_unit_name(name):
    return 'nvyr-pod-' + name.encode().hex()


def network_unit_name(name):
    return 'nvyr-network-' + name.encode().hex()


def enabled(container, configuration):
    """A disabled pod suppresses its members without changing their own settings."""
    pod = configuration.get('pod', {}).get(container.get('pod'), {})
    return 'disable' not in container and 'disable' not in pod


def mount_path(name, volume):
    return f'{MOUNT_ROOT}/{name.encode().hex()}/{volume.encode().hex()}'


def environment_path(name):
    return f'/run/nvyr-containers/environment/{name.encode().hex()}.env'
