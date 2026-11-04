"""Batch-owned container scenarios; tests never tear down another case's workload."""

from contextlib import contextmanager
from pathlib import Path
import json
import os
import shlex
import socket
import tempfile

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_names_unused, assert_not_in
from smoketests.support import configuration_case


IDLE_SCRIPT = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait \"$!\"; done"


def available_port(kind):
    """Let the kernel choose a currently unused loopback publication port."""
    with socket.socket(socket.AF_INET, kind) as reservation:
        reservation.bind(('127.0.0.1', 0))
        return str(reservation.getsockname()[1])


@contextmanager
def namespace_socket(namespace, family, kind):
    """Create the socket in its namespace, then restore the test process immediately."""
    with open('/proc/self/ns/net', 'rb') as original, open(namespace, 'rb') as target:
        try:
            os.setns(target.fileno(), 0)
            endpoint = socket.socket(family, kind)
        finally:
            os.setns(original.fileno(), 0)
    with endpoint:
        endpoint.settimeout(3)
        yield endpoint


def container_socket(name, family=socket.AF_INET, kind=socket.SOCK_STREAM):
    record = json.loads(cmd(['podman', 'inspect', name]))[0]
    return namespace_socket(f'/proc/{record["State"]["Pid"]}/ns/net', family, kind)


@contextmanager
def publication_client():
    """Attach an external client before Podman binds either router address."""
    prefix = '2001:db8:ce::'
    assert not cmd(['ip', '-6', 'route', 'show', 'table', 'all', 'exact', prefix + '/64']).strip()
    namespace = 'nvyr-publish-client'
    cmd(['ip', 'netns', 'add', namespace])
    try:
        cmd(['ip', 'link', 'add', 'ctpub-test', 'type', 'veth', 'peer', 'name', 'client0', 'netns', namespace])
        cmd(['ip', 'link', 'set', 'ctpub-test', 'up'])
        for address in ('1', '2'):
            cmd(['ip', '-6', 'addr', 'add', prefix + address + '/64', 'dev', 'ctpub-test', 'nodad'])
        cmd(['ip', '-n', namespace, 'link', 'set', 'client0', 'up'])
        cmd(['ip', '-n', namespace, 'addr', 'add', prefix + '3/64', 'dev', 'client0', 'nodad'])
        yield '/run/netns/' + namespace
    finally:
        cmd(['ip', 'netns', 'del', namespace])


@contextmanager
def batch_containers(config, request, image, filenames):
    """Create a complete scenario once and restore it before releasing volume files."""
    original = config.get_config()
    root = Path('/config/containers')
    root.mkdir(parents=True, exist_ok=True)
    # Keep files on cleanup failure so mounted workloads retain their backing data.
    directory = Path(tempfile.mkdtemp(prefix='nvyr-functional-', dir=root))
    volume = directory / 'volume'
    volume.mkdir()
    environment = directory / 'values.env'
    environment.write_text('SMOKE_FILE=from-file\nSMOKE_OVERRIDE=file\n')
    external = Path(tempfile.mkdtemp(prefix='nvyr-functional-', dir='/run'))
    hostfile = external / 'host-file'
    hostfile.write_text('absolute host file\n')
    text = '\n'.join((Path(__file__).with_name('configs') / filename).read_text()
                     for filename in filenames)
    replacements = {
        '@IMAGE@': shlex.quote(image), '@ENV@': str(environment.relative_to(root)),
        '@VOLUME@': str(volume.relative_to(root)),
        '@HOSTFILE@': str(hostfile),
        '@TCP_PORT@': available_port(socket.SOCK_STREAM),
        '@UDP_PORT@': available_port(socket.SOCK_DGRAM),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    commands = [line for line in text.splitlines() if line and not line.startswith('#')]
    names = {'name': set(), 'network': set(), 'pod': set(), 'vrf': set()}
    for command in commands:
        words = shlex.split(command)
        if words[1] == 'container':
            names[words[2]].add(words[3])
        elif words[1:3] == ['vrf', 'name']:
            names['vrf'].add(words[3])

    if 'containers.conf' in filenames:
        # This name must remain absent until the unrelated-commit test creates it.
        names['network'].add('CTUNUSED')

    assert_config_names_unused(original, *set.union(*names.values()))
    for kind, arguments, field in (
        ('name', ['ps', '-a'], 'Names'), ('pod', ['pod', 'ps'], 'Name'),
        ('network', ['network', 'ls'], 'name'),
    ):
        records = json.loads(cmd(['podman', *arguments, '--format=json']))
        for record in records:
            existing = record[field] if isinstance(record[field], list) else [record[field]]
            for name in names[kind]:
                assert_not_in(name, existing)
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    owned_links = names['vrf'] | {'pd-' + name for name in names['network']}
    owned_links |= {'pd-' + name + '-0' for name in names['name'] | names['pod']}
    for link in links:
        assert_not_in(link['ifname'], owned_links)
        if names['vrf']:
            assert str(link.get('linkinfo', {}).get('info_data', {}).get('table')) != '28405'

    with configuration_case(config, request, original):
        for command in commands:
            config.set(command)
        # Each workload handles TERM as PID 1; real restart tests still exercise systemd.
        for name in sorted(names['name']):
            config.set(f'set container name {name} command sh')
            config.set(f'set container name {name} argument ' + shlex.quote(shlex.join(['-c', IDLE_SCRIPT])))
        config.commit()
        yield {'volume': volume, 'directory': directory, 'hostfile': hostfile,
               'tcp_port': replacements['@TCP_PORT@'], 'udp_port': replacements['@UDP_PORT@']}

    environment.unlink()
    hostfile.unlink()
    external.rmdir()
    for file in volume.iterdir():
        file.unlink()
    volume.rmdir()
    directory.rmdir()
