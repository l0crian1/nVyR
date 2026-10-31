"""Container grammar, confinement, permissions, native plans and recovery."""

from tests.container_harness import ContainerHarness
from tests.container_harness import verify_container

from copy import deepcopy
import json
import os
from email.parser import Parser
from pathlib import Path
import tomllib

import pytest

from nvyr.errors import RouterError, RecoveryError, ValidationError
from nvyr.helpers import container_config as config
from nvyr.config_scripts import container as containers
from nvyr.helpers.containers import run_apply as host_worker_request
from nvyr.helpers import containers as worker, filesystem
from tests.container_rendering import container_unit
from tests.container_rendering import network_unit
from tests.test_login import as_role


IMAGE = 'docker.io/library/busybox:1.37'
IMAGE_ID = 'a' * 64


def test_storage_mount_helper_is_explicitly_packaged():
    repository = Path(__file__).resolve().parents[1]
    storage = tomllib.loads((repository / 'packaging/containers-storage.conf').read_text())['storage']
    helper = Path(storage['options']['overlay']['mount_program'])
    image_packages = (repository / 'images/router.list.chroot').read_text().splitlines()
    control = (repository / 'packaging/debian/control').read_text()
    dependencies = [item.strip() for item in Parser().parsestr(control)['Depends'].split(',')]

    assert str(helper) == '/usr/bin/fuse-overlayfs'
    assert helper.name in image_packages
    assert helper.name in dependencies


def configuration():
    return {'network': {'LAN': {'subnet': {'172.29.210.0/24': {'gateway': '172.29.210.1'}}}},
            'name': {'APP': {'image': IMAGE, 'network': {'LAN': {}}, 'command': 'sleep', 'argument': 'infinity'}}}


def test_network_isolation_default_disable_and_restore(controller, engine, session):
    """Isolation remains Netavark's default until explicitly disabled on the network."""
    controller.execute('set container network LAN subnet 172.29.210.0/24', session)

    def arguments():
        return network_unit('LAN', engine.view(session)['container']['network']['LAN'])

    assert 'Options=isolate=false' not in arguments()
    controller.execute('set container network LAN isolation disable', session)
    assert 'Options=isolate=false' in arguments()

    controller.execute('delete container network LAN isolation disable', session)
    assert 'Options=isolate=false' not in arguments()


def test_anchored_configuration_and_dependencies(controller, engine, session):
    controller.execute('set container network LAN description services subnet 172.29.210.0/24 gateway 172.29.210.1', session)
    controller.execute('set container name APP image docker.io/library/busybox:1.37 command sleep argument "100 100" memory 64m', session)
    controller.execute('set container name APP network LAN address 172.29.210.10', session)
    controller.execute('set container name APP volume DATA source APP/data', session)
    controller.execute('set container name APP volume DATA destination /data', session)
    section = engine.view(session)['container']
    verify_container(section)
    assert section['name']['APP']['argument'] == '100 100'
    assert 'Exec="sleep" "100" "100"' in container_unit('APP', section['name']['APP'], IMAGE_ID)
    assert 'cpus' in dict(controller.completion('set container name APP image ' + IMAGE + ' ', session)['candidates'])

    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete container network LAN', session)

    result = engine.commit(session)
    assert result['results']['container']['success']


def test_interactive_and_tty_defaults_and_independent_overrides(controller, engine, session):
    """CLI overrides preserve image CMD and deleting them restores the implicit defaults."""
    controller.execute('set container name APP image alpine', session)

    def rendered():
        configuration = engine.view(session)['container']['name']['APP']
        return container_unit('APP', configuration, IMAGE_ID)

    assert 'PodmanArgs=--interactive=true --tty=true' in rendered()
    assert 'Exec=' not in rendered()

    controller.execute('set container name APP interactive disable', session)
    assert 'PodmanArgs=--interactive=false --tty=true' in rendered()

    controller.execute('set container name APP tty disable', session)
    assert 'PodmanArgs=--interactive=false --tty=false' in rendered()

    controller.execute('delete container name APP interactive disable', session)
    assert 'PodmanArgs=--interactive=true --tty=false' in rendered()

    controller.execute('delete container name APP tty disable', session)
    assert 'PodmanArgs=--interactive=true --tty=true' in rendered()
    assert 'Exec=' not in rendered()


def test_attachment_ids_default_uniqueness_and_bounds(controller, engine, session):
    """Direct defaults collide until another ID is selected, and deleted IDs return to zero."""
    controller.execute('set container network LAN subnet 172.29.210.0/24', session)
    controller.execute('set container network WAN subnet 172.29.211.0/24', session)
    controller.execute('set container name APP image alpine network LAN', session)
    effective = engine.schema.defaults(engine.view(session))
    assert effective['container']['name']['APP']['network']['LAN']['id'] == '0'

    controller.execute('set container name APP network WAN', session)
    with pytest.raises(ValidationError, match='duplicate id 0'):
        verify_container(engine.view(session)['container'])

    controller.execute('set container name APP network WAN id 9', session)
    verify_container(engine.view(session)['container'])
    unit = container_unit('APP', engine.view(session)['container']['name']['APP'], IMAGE_ID)
    assert 'ContainerName=APP\n' in unit
    assert 'Network=nvyr-network-4c414e.network:host_interface_name=pd-APP-0\n' in unit
    assert 'Network=nvyr-network-57414e.network:host_interface_name=pd-APP-9\n' in unit

    with pytest.raises(RouterError):
        controller.execute('set container name APP network WAN id 10', session)
    with pytest.raises(RouterError):
        controller.execute('set container name APP network WAN id -1', session)

    controller.execute('delete container name APP network WAN id', session)
    effective = engine.schema.defaults(engine.view(session))
    assert effective['container']['name']['APP']['network']['WAN']['id'] == '0'
    with pytest.raises(ValidationError, match='duplicate id 0'):
        verify_container(engine.view(session)['container'])


def test_interface_name_length_boundaries(controller, engine, session):
    """The longest accepted names fit the kernel limit without truncation."""
    controller.execute('set container network ABCDEFGHIJKL subnet 172.29.210.0/24', session)
    controller.execute('set container name ABCDEFGHIJ image alpine network ABCDEFGHIJKL id 9', session)
    verify_container(engine.view(session)['container'])
    assert config.bridge_name('ABCDEFGHIJKL') == 'pd-ABCDEFGHIJKL'
    assert config.veth_name('ABCDEFGHIJ', {'id': '9'}) == 'pd-ABCDEFGHIJ-9'

    with pytest.raises(RouterError):
        controller.execute('set container network ABCDEFGHIJKLM', session)
    with pytest.raises(RouterError):
        controller.execute('set container name ABCDEFGHIJK', session)


def test_cli_rejects_invalid_names_ids_and_reserved_network_modes(controller, session):
    """Reject standalone invalid values before they enter the candidate configuration."""
    for invalid in ('ABCDEFGHIJKLM', 'bad.name', 'é', 'host', 'none', 'bridge', 'private', 'pasta', 'slirp4netns', 'default'):
        with pytest.raises(RouterError):
            controller.execute(f'set container network {invalid}', session)

    for invalid in ('ABCDEFGHIJK', 'bad.name', 'é'):
        with pytest.raises(RouterError):
            controller.execute(f'set container name {invalid}', session)

    for identifier in ('10', '-1', '00', 'x'):
        with pytest.raises(RouterError):
            controller.execute(f'set container name APP network LAN id {identifier}', session)


def test_bridge_and_attachment_name_collision_rejected():
    """A network named APP-0 cannot share its bridge name with APP's default attachment."""
    section = configuration()
    section['network']['APP-0'] = {'subnet': {'172.29.211.0/24': {}}}
    with pytest.raises(ValidationError, match='pd-APP-0 conflicts'):
        verify_container(section)


def test_ten_networks_have_distinct_names_and_preserve_ids():
    """All ten suffixes are usable, and removing an attachment never renumbers the rest."""
    section = {'network': {}, 'name': {'APP': {'image': IMAGE, 'network': {}}}}
    for identifier in range(10):
        network = f'NET{identifier}'
        section['network'][network] = {'subnet': {f'172.29.{identifier}.0/24': {}}}
        section['name']['APP']['network'][network] = {'id': str(identifier)}
    verify_container(section)

    del section['name']['APP']['network']['NET0']
    unit = container_unit('APP', section['name']['APP'], IMAGE_ID)
    assert 'Network=nvyr-network-4e455431.network:host_interface_name=pd-APP-1\n' in unit
    assert 'Network=nvyr-network-4e455439.network:host_interface_name=pd-APP-9\n' in unit


def test_image_operations_permissions_and_mapping(controller):
    for text, function in [('add container image ' + IMAGE, 'add'),
                           ('update container image name ' + IMAGE, 'update'),
                           ('update container image container APP', 'update_container')]:
        with as_role('read-only'), pytest.raises(RouterError, match='net-admin'):
            controller.execute(text)
        with as_role('net-admin'):
            result = controller.execute(text)
            assert result['event'] == 'command'
            controller.authorize_terminal(text, None)
            assert result['argv'][1] == function


def test_show_containers_is_available_to_operators(controller, monkeypatch):
    commands = []
    output = 'CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES\n'

    def execute(argv, **kwargs):
        commands.append(argv)
        return output

    monkeypatch.setattr('nvyr.controller.cmd', execute)
    with as_role('read-only'):
        result = controller.execute('show containers')

    assert result['text'] == output
    assert commands == [['containers.nvyr.op', 'show']]


def test_displays_can_share_the_operation_lock(tmp_path, monkeypatch):
    from nvyr.helpers import container_operations

    monkeypatch.setattr(container_operations, 'RUNTIME', tmp_path)
    monkeypatch.setattr(container_operations, 'protected_directory', lambda path: None)
    monkeypatch.setattr(container_operations, 'show', lambda runtime, view, **options: view)
    monkeypatch.setattr(container_operations, 'configured_state', lambda: {'configuration': {}, 'images': {}})

    with (tmp_path / 'lock').open('a') as lock:
        worker.fcntl.flock(lock, worker.fcntl.LOCK_SH | worker.fcntl.LOCK_NB)
        assert container_operations.display('containers') == 'containers'


@pytest.mark.parametrize('command', [
    'image --help', 'image docker-archive:/etc/shadow',
    'volume DATA source ../secrets', 'volume DATA source /etc',
    'volume DATA destination relative', 'memory 1m', 'cpus 0', 'process-limit 0',
])
def test_schema_rejects_unsafe_values(controller, session, command):
    with pytest.raises(RouterError):
        controller.execute('set container name APP ' + command, session)


@pytest.mark.parametrize('reference', [
    'busybox', 'busybox:latest', 'l0crian/segman', 'docker.io/l0crian/segman',
    'docker.io/l0crian/segman:latest', 'localhost:5000/team/my_image',
    'quay.io/team/image@sha256:' + 'a' * 64,
])
def test_image_names_allow_optional_registry_and_tag(controller, session, reference):
    controller.execute('set container name APP image ' + reference, session)
    verify_container({'name': {'APP': {'image': reference}}})

    with as_role('net-admin'):
        for command in ('add container image ', 'update container image name '):
            result = controller.execute(command + reference)
            assert result['argv'][-1] == reference


def test_default_registry_configuration(controller, engine, session):
    controller.execute('set container registry registry.example.com:5000 priority 10', session)
    registry = tomllib.loads(containers.registry_text(engine.view(session)['container']))
    assert registry['unqualified-search-registries'] == ['registry.example.com:5000']

    for registry in ('https://docker.io', 'docker.io/team', 'docker.io:70000', 'docker.io:'):
        with pytest.raises(RouterError):
            controller.execute('set container registry ' + registry + ' priority 10', session)


def test_host_network_exclusivity_and_no_implicit_default_network():
    section = configuration()
    section['name']['APP']['allow-host-networking'] = True
    with pytest.raises(ValidationError, match='conflicts'):
        verify_container(section)
    del section['name']['APP']['network']
    verify_container(section)
    assert 'Network=host' in container_unit('APP', section['name']['APP'], IMAGE_ID)
    del section['name']['APP']['allow-host-networking']
    assert 'Network=none' in container_unit('APP', section['name']['APP'], IMAGE_ID)


def test_network_address_validation():
    section = configuration()
    section['network']['OTHER'] = {'subnet': {'172.29.210.0/25': {}}}
    with pytest.raises(ValidationError, match='overlaps'):
        verify_container(section)
    del section['network']['OTHER']
    section['name']['APP']['network']['LAN']['address'] = ['172.29.211.10']
    with pytest.raises(ValidationError, match='outside'):
        verify_container(section)
    section['name']['APP']['network']['LAN']['address'] = ['172.29.210.1']
    with pytest.raises(ValidationError, match='reserved'):
        verify_container(section)
    section['name']['APP']['network']['LAN']['address'] = ['172.29.210.10']
    section['name']['OTHER'] = deepcopy(section['name']['APP'])
    with pytest.raises(ValidationError, match='already assigned'):
        verify_container(section)


def test_required_children_and_published_port_conflicts():
    section = configuration()
    section['name']['APP']['volume'] = {'DATA': {'source': 'APP/data'}}
    with pytest.raises(ValidationError, match='destination'):
        verify_container(section)
    del section['name']['APP']['volume']
    section['name']['APP']['port'] = {'HTTP': {'protocol': 'tcp', 'source-port': '8080', 'destination-port': '80'}}
    section['name']['OTHER'] = deepcopy(section['name']['APP'])
    with pytest.raises(ValidationError, match='conflicts'):
        verify_container(section)


def test_source_symlinks_rejected_and_directory_descriptor_pinned(tmp_path):
    root = tmp_path / 'volumes'
    outside = tmp_path / 'outside'
    outside.mkdir()
    root.mkdir()
    (root / 'escape').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        filesystem.open_directory(root, 'escape/data', create=True)
    assert not (outside / 'data').exists()

    descriptor = filesystem.open_directory(root, 'APP/data', create=True)
    try:
        inode = os.fstat(descriptor).st_ino
        (root / 'APP' / 'data').rename(root / 'APP' / 'original')
        (root / 'APP' / 'data').symlink_to(outside, target_is_directory=True)
        assert os.fstat(descriptor).st_ino == inode
        assert inode != outside.stat().st_ino
    finally:
        os.close(descriptor)


def test_unit_quoting_limits_and_network_settings():
    section = configuration()['name']['APP']
    section.update({'argument': '"two words" "${HOSTNAME}" "%n" same same',
                    'environment': {'TEST': {'value': '${HOSTNAME}%n'}},
                    'volume': {'DATA': {'source': 'APP/data', 'destination': '/data', 'read-only': True}}})
    text = container_unit('APP', section, IMAGE_ID)
    assert '"two words" "$${HOSTNAME}" "%%n" "same" "same"' in text
    assert 'Environment="TEST=$${HOSTNAME}%%n"' in text
    assert 'DefaultDependencies=false' in text
    assert 'NoNewPrivileges=true' in text and 'DropCapability=all' in text
    assert '--image-volume=ignore' in text and '--memory=536870912' in text
    assert ':ro\n' in text and 'PidsLimit=256' in text

    network = {'subnet': {'172.29.210.0/24': {}, 'fd00:210::/64': {}}, 'internal': True, 'disable-dns': True}
    argv = network_unit('LAN', network)
    assert 'IPv6=true' in argv and 'Internal=true' in argv and 'DisableDNS=true' in argv
    assert 'NetworkName=LAN' in argv
    assert 'InterfaceName=pd-LAN' in argv


class FakeRuntime(ContainerHarness):
    """Exercise reconciliation ordering with failing native service operations."""
    def __init__(self, tmp_path):
        super().__init__(state=tmp_path / 'managed.json', quadlets=tmp_path / 'quadlets',
                         registries=tmp_path / 'registries.conf.d' / '90-nvyr.conf',
                         execute=self.command, status=self.status_command)
        self.events = []
        self.networks = set()
        self.fail_start = 0
        self.available_image = IMAGE_ID
        self.links = []

    def command(self, argv, **kwargs):
        self.events.append(tuple(argv))
        if argv == ['ip', '-j', '-d', 'link', 'show']:
            return json.dumps(self.links)
        if argv[:2] == ['systemctl', 'list-units']:
            return json.dumps([{'unit': unit} for unit in argv[4:]])
        if argv[:3] == ['podman', 'network', 'rm']:
            self.networks.remove(argv[-1])
        if argv[:2] == ['systemctl', 'start']:
            if self.fail_start:
                self.fail_start -= 1
                raise RouterError('simulated startup failure')
            for path in self.quadlets.glob('*.network'):
                if path.stem + '-network.service' in argv:
                    self.networks.update(line.split('=', 1)[1] for line in path.read_text().splitlines()
                                         if line.startswith('NetworkName='))
        return ''

    def status_command(self, argv, **kwargs):
        self.events.append(tuple(argv))
        return 0, ''

    def image_id(self, reference):
        return self.available_image

    def owned(self, kind, name):
        return kind == 'network' and name in self.networks

    def validate_units(self, prepared):
        pass

    def unmount(self, name):
        pass


def test_host_interface_collision_rejected_before_workload_changes(tmp_path):
    """A name collision fails before the transaction journal or any service mutations."""
    runtime = FakeRuntime(tmp_path)
    runtime.links = [{'ifname': 'pd-APP-0', 'linkinfo': {'info_kind': 'veth'}}]
    with pytest.raises(RouterError, match='pd-APP-0 already exists'):
        runtime.apply(runtime.generate(configuration()))
    assert not runtime.pending.exists()
    assert not any(event[0] == 'systemctl' for event in runtime.events)
    assert not runtime.networks


def test_foreign_native_object_is_not_adopted(tmp_path):
    """Unprefixed names still require the ownership label for both object types."""
    def execute(argv, **kwargs):
        return json.dumps([{'Config': {'Labels': {}}, 'labels': {}}])

    runtime = ContainerHarness(state=tmp_path / 'state.json', execute=execute, status=lambda *args: (0, ''))
    with pytest.raises(RouterError, match='network LAN exists outside'):
        runtime.validate_ownership(containers.inventory({}), containers.inventory(configuration()),
                                   {'network': ['LAN'], 'name': ['APP'], 'pod': []})
    with pytest.raises(RouterError, match='container APP exists outside'):
        runtime.validate_ownership(containers.inventory({}), containers.inventory({'name': {'APP': {}}}),
                                   {'network': [], 'name': ['APP'], 'pod': []})


def test_runtime_noop_and_image_update_does_not_recreate(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    runtime.available_image = 'b' * 64
    runtime.pull(IMAGE)
    runtime.apply(runtime.generate(desired))
    assert not any(event[:2] == ('systemctl', 'stop') for event in runtime.events)
    assert runtime.read()['images']['APP'] == IMAGE_ID
    assert ('podman', 'pull', '--', IMAGE) in runtime.events


def test_registry_changes_do_not_restart_containers_and_reset_to_docker_hub(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()

    desired['registry'] = {'registry.example.com:5000': {'priority': '10'}}
    runtime.apply(runtime.generate(desired))
    assert tomllib.loads(runtime.registries.read_text())['unqualified-search-registries'] == ['registry.example.com:5000']
    assert not any(event[:2] == ('systemctl', 'stop') for event in runtime.events)

    del desired['registry']
    runtime.apply(runtime.generate(desired))
    assert tomllib.loads(runtime.registries.read_text())['unqualified-search-registries'] == ['docker.io']


def test_failed_commit_restores_previous_registry(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    desired['registry'] = {'registry.example.com': {'priority': '10'}}
    desired['name']['APP']['argument'] = '200'
    runtime.fail_start = 1

    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(desired))

    assert tomllib.loads(runtime.registries.read_text())['unqualified-search-registries'] == ['docker.io']


def test_network_replacement_restarts_consumers_and_restores_on_failure(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    changed = deepcopy(desired)
    changed['network']['LAN']['internal'] = True
    runtime.events.clear()
    runtime.fail_start = 1
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(changed))
    stop = next(index for index, event in enumerate(runtime.events) if event[:2] == ('systemctl', 'stop'))
    remove = next(index for index, event in enumerate(runtime.events) if event[:3] == ('podman', 'network', 'rm'))
    assert stop < remove
    assert runtime.read()['configuration'] == desired


def test_failed_compensation_is_recovery_error(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    changed = deepcopy(desired)
    changed['name']['APP']['argument'] = '200'
    runtime.fail_start = 2
    with pytest.raises(RecoveryError, match='rollback failed'):
        runtime.apply(runtime.generate(changed))


def test_boot_container_failure_does_not_abort_recovery(tmp_path):
    runtime = FakeRuntime(tmp_path)
    messages = []
    runtime.report = messages.append
    runtime.fail_start = 1
    runtime.apply(runtime.generate(configuration(), recovery=True))
    assert any('Container unavailable' in message for message in messages)
    assert runtime.read()['configuration'] == configuration()


def test_interrupted_operation_recovers_names_missing_from_manifest(tmp_path):
    runtime = FakeRuntime(tmp_path)
    runtime.pending.write_text(json.dumps(containers.inventory(configuration())))
    runtime.networks.add('LAN')
    with pytest.raises(RecoveryError, match='interrupted'):
        runtime.apply(runtime.generate({}))
    runtime.apply(runtime.generate({}, recovery=True))
    assert not runtime.networks
    assert not runtime.pending.exists()


def test_unprotected_storage_root_rejected(tmp_path):
    unsafe = tmp_path / 'podman'
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(RouterError, match='not protected'):
        filesystem.protected_directory(unsafe)


def test_boot_worker_failure_is_reported_without_blocking_configd(tmp_path, monkeypatch):
    monkeypatch.setattr(worker.config, 'RUNTIME', tmp_path)
    monkeypatch.setattr(worker, 'rc_cmd', lambda *args, **kwargs: (1, 'Podman is unavailable'))
    messages = []
    host_worker_request({}, recovery=True, report=messages.append)
    assert any('configd remains available' in message for message in messages)


def test_manifest_write_failure_compensates_native_changes(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    before_inventory = runtime.state.read_bytes()
    unit = runtime.quadlets / 'nvyr-container-415050.container'
    before_unit = unit.read_bytes()
    changed = deepcopy(desired)
    changed['name']['APP']['memory'] = '64m'
    original_write = containers.write
    failed = False

    def fail_once(path, text):
        nonlocal failed
        if Path(path) == runtime.state and not failed:
            failed = True
            raise RouterError('simulated disk full')
        original_write(path, text)

    monkeypatch.setattr(containers, 'write', fail_once)
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(changed))
    assert runtime.read()['configuration'] == desired
    assert runtime.state.read_bytes() == before_inventory
    assert unit.read_bytes() == before_unit
    assert not runtime.pending.exists()
