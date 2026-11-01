"""Image catalog transactions, installer safety, migration and CLI integration."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import struct
import tempfile
import threading
from unittest.mock import Mock

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import access, image_migration, images, installation
from nvyr.op_scripts import images as operations
from nvyr.storage import Store, atomic_json, read_saved, saved_document, has_saved_configuration

UUID = '11111111-2222-3333-4444-555555555555'


@pytest.fixture
def media(tmp_path):
    path = tmp_path/'media'
    (path/'live').mkdir(parents=True)

    for role, filename in images.PAYLOAD.items():
        (path/'live'/filename).write_bytes((role*100).encode())

    document = images.manifest(path, {'version': '1.0', 'build_timestamp': '2026-10-15T12:00:00Z'})
    atomic_json(path/'nvyr/image.json', document)

    return path, document


@pytest.fixture
def catalog(tmp_path, media):
    result = images.Images(tmp_path/'storage')

    with result.locked():
        result.add(*media, 'first', lambda stage: None, make_default=True, filesystem_uuid=UUID)

    result.running = result.catalog()['default']

    return result


def test_manifest_rejects_corruption(media):
    path, document = media

    assert images.verify_media(path) == document

    (path/'live/vmlinuz').write_bytes(b'bad')

    with pytest.raises(RouterError, match='integrity'):
        images.verify_media(path)


@pytest.mark.parametrize('field,value', [('files', ['rootfs', 'kernel', 'initrd']),
    ('files', None), ('build', []), ('build', None), ('build', {'version': 1}),
    ('files', {'rootfs': [], 'kernel': None, 'initrd': {}})])
def test_malformed_manifest_is_a_useful_error(media, field, value):
    path, document = media
    document[field] = value
    atomic_json(path/'nvyr/image.json', document)

    with pytest.raises(RouterError, match='Not a compatible, intact nVyR image'):
        images.verify_media(path)


def test_factory_metadata_is_not_configuration(tmp_path, controller, session):
    from nvyr.helpers import accounts

    store = Store(tmp_path/'state', saved_path=tmp_path/'config'/images.SAVED)
    accounts.initialize(store)
    original = store.read('boot.json')

    assert '_nvyr' not in original
    assert not has_saved_configuration(store.saved_path)
    assert read_saved(store.saved_path)[1] == {'factory': True}

    # Explicitly saving, including a default-looking tree, makes this user-saved.
    store.write('boot.json', original)

    assert has_saved_configuration(store.saved_path)

    controller.load(session, store.saved_path.read_text(), replace=True)

    assert controller.engine.view(session) == original

    controller.engine.commit(session)

    assert '_nvyr' not in controller.engine.running

    # Reloading must neither reset credentials nor reintroduce the factory flag.
    accounts.initialize(store)

    assert has_saved_configuration(store.saved_path)


def test_saved_metadata_is_required_and_preserves_future_fields(tmp_path):
    path = tmp_path/images.SAVED
    atomic_json(path, {'system': {'host-name': 'router'}})

    with pytest.raises(ValueError, match='metadata'):
        read_saved(path)

    configuration = {'system': {'host-name': 'router'}}
    atomic_json(path, saved_document(configuration, metadata={'factory': True, 'future': {'key': 'value'}}))

    assert read_saved(path) == (configuration, {'factory': True, 'future': {'key': 'value'}})
    assert not has_saved_configuration(path)

    atomic_json(path, {'_nvyr': {'factory': 'false'}})

    with pytest.raises(ValueError, match='metadata'):
        read_saved(path)


def test_saved_permissions_repaired_on_restart(tmp_path):
    path = tmp_path/'config'/images.SAVED
    atomic_json(path, {'system': {}}, mode=0o666)
    Store(tmp_path/'state', saved_path=path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o644

    path.unlink()
    other = tmp_path/'other'
    other.write_text('{}')
    path.symlink_to(other)

    with pytest.raises(RouterError, match='symbolic link'):
        Store(tmp_path/'state', saved_path=path)


def test_rename_to_parsing_abbreviation_and_completion(controller, session):
    for line in ('rename system image first to second', 'rena sys im first t second'):
        assert controller.execute(line)['argv'] == ['images.nvyr.op', 'rename', 'first', 'second']

    assert controller.execute('run rename system image first to second', session)['argv'] == [
        'images.nvyr.op', 'rename', 'first', 'second']

    for line in ('rename system image first second', 'rename system image first to'):
        with pytest.raises(RouterError):
            controller.execute(line)

    result = controller.completion('rename system image first ', explicit=True)

    assert 'to' in str(result['candidates'])


@pytest.mark.parametrize('status', [1, 130])
def test_worker_propagates_status_without_subprocess_diagnostics(monkeypatch, caplog, status):
    monkeypatch.setattr(operations, 'call', lambda *a, **k: status)

    with pytest.raises(SystemExit) as error:
        operations.add('bad.iso')

    assert error.value.code == status
    assert not caplog.records


@pytest.mark.parametrize('operation,arguments', [('install', []), ('add', ['bad.iso']),
    ('select', ['first']), ('rename', ['first', 'second']), ('delete', ['first'])])
def test_guided_cancellation_has_no_traceback(monkeypatch, capsys, operation, arguments):
    monkeypatch.setattr('sys.argv', ['installer', operation, *arguments])
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installation.signal, 'signal', lambda *args: None)

    def cancel(*args):
        raise KeyboardInterrupt

    if operation in ('install', 'add'):
        monkeypatch.setattr(installation, operation, cancel)
    elif operation == 'delete':
        monkeypatch.setattr(installation, 'confirm', cancel)
    else:
        monkeypatch.setattr(images.Images, operation, cancel)

    with pytest.raises(SystemExit) as error:
        installation.main()

    assert error.value.code == 130

    output = capsys.readouterr().err

    assert 'interrupted' in output and 'Traceback' not in output


def test_invalid_iso_worker_reports_error_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['installer', 'add', 'bad.iso'])
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installation.signal, 'signal', lambda *args: None)

    def fail(*args):
        raise RouterError('Not a compatible, intact nVyR image: missing manifest')

    monkeypatch.setattr(installation, 'add', fail)

    with pytest.raises(SystemExit) as error:
        installation.main()

    assert error.value.code == 1
    assert capsys.readouterr().err == 'Image operation failed: Not a compatible, intact nVyR image: missing manifest\n'


def test_download_cancellation_removes_partial_file(tmp_path, monkeypatch):
    from types import SimpleNamespace

    @contextmanager
    def response(*args, **kwargs):
        def interrupt(size):
            raise KeyboardInterrupt

        yield SimpleNamespace(read=interrupt)

    monkeypatch.setattr(installation, 'ARCHIVE', tmp_path)
    monkeypatch.setattr(installation.urllib.request, 'build_opener', lambda *args: SimpleNamespace(open=response))

    with pytest.raises(KeyboardInterrupt):
        installation.acquire('http://example.test/image.iso')

    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('saved', [False, True])
@pytest.mark.parametrize('workflow', ['fresh', 'live-add', 'installed-add'])
def test_only_user_saved_configs_offer_retention(saved, workflow, catalog, media, tmp_path, monkeypatch):
    prompts, summaries = [], []

    @contextmanager
    def mount(*args, **kwargs):
        yield media[0] if workflow == 'installed-add' else catalog.root

    monkeypatch.setattr(installation, 'mounted', mount)
    monkeypatch.setattr(installation, 'live_media', lambda: media[0])
    monkeypatch.setattr(installation, 'inventory', lambda: [disk()])
    monkeypatch.setattr(installation, 'existing_installation', lambda _: (
        ('/dev/test', catalog.catalog()) if workflow == 'live-add' else None))
    monkeypatch.setattr(installation, 'Images', lambda *args: catalog)
    monkeypatch.setattr(installation, 'acquire', lambda _: (tmp_path/'image.iso', False))
    monkeypatch.setattr(installation, 'ask_name', lambda *args: 'new')
    monkeypatch.setattr(installation, 'ask_administrator', lambda: ('nvyr', 'hashed'))
    monkeypatch.setattr(installation, 'has_saved_configuration', lambda _: saved)

    def choose(message, *args):
        prompts.append(message)
        if message == 'Installation mode:':
            return 1 if workflow == 'live-add' else 0
        return 0

    monkeypatch.setattr(installation, 'choose', choose)
    monkeypatch.setattr(installation, 'confirm', lambda message, *args: prompts.append(message) or False)

    def summary(*args, **kwargs):
        summaries.append(kwargs)
        return False

    monkeypatch.setattr(installation, 'summary', summary)

    if workflow == 'installed-add':
        installation._add('image.iso')
    else:
        installation._install()

    assert summaries[0]['retain'] is saved
    assert any('configuration' in prompt.lower() for prompt in prompts) is saved
    assert ('Enable developer administration?' in prompts) is (workflow == 'fresh')


def test_short_http_download_is_rejected_and_removed(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '1000000')
            self.end_headers()
            self.wfile.write(b'truncated')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    monkeypatch.setattr(installation, 'ARCHIVE', tmp_path)

    try:
        with pytest.raises(RouterError, match='incomplete'):
            installation.acquire(f'http://127.0.0.1:{server.server_port}/image.iso')

        assert not list(tmp_path.iterdir())
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize(('arguments', 'prompt'), [
    pytest.param(['install'], 'Continue? [y/N] ', id='install'),
    pytest.param(['add', 'unused.iso'], 'Continue? [y/N] ', id='add'),
    pytest.param(['delete', 'unused'],
                 "Delete image 'unused' and all of its persistent files? [y/N] ", id='delete'),
])
def test_prompt_cancellation_exits_without_mutation(arguments, prompt, monkeypatch, capsys):
    """Cancel at input's public boundary without racing the interpreter's terminal read."""
    read_input = Mock(side_effect=KeyboardInterrupt)
    install_image = Mock()
    add_image = Mock()
    image_catalog = Mock()
    monkeypatch.setattr(installation, 'input', read_input, raising=False)
    monkeypatch.setattr(installation.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installation.sys, 'argv', ['installer', *arguments])
    monkeypatch.setattr(installation, '_install', install_image)
    monkeypatch.setattr(installation, '_add', add_image)
    monkeypatch.setattr(installation, 'Images', image_catalog)

    # main installs process-wide handlers; restore them before another test runs.
    previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        with pytest.raises(SystemExit) as interrupted:
            installation.main()
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)

    assert interrupted.value.code == 130
    assert capsys.readouterr().err == (
        '\nImage operation interrupted; previously installed images remain available.\n'
    )
    read_input.assert_called_once_with(prompt)
    install_image.assert_not_called()
    add_image.assert_not_called()
    image_catalog.assert_not_called()


def test_ctrl_c_during_real_download_removes_partial_file(tmp_path):
    from tests.test_process import spawn_terminal, read_until, cleanup

    downloading, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '100000000')
            self.end_headers()
            self.wfile.write(b'partial')
            downloading.set()
            release.wait(10)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    source = ('import sys; from pathlib import Path; from contextlib import nullcontext; '
              'from nvyr.helpers import installation as i; i.os.geteuid=lambda: 0; '
              f'i.ARCHIVE=Path({str(tmp_path)!r}); '
              'i.installation_lock=nullcontext; i._add=i.acquire; '
              f'sys.argv=["installer","add","http://127.0.0.1:{server.server_port}/image.iso"]; i.main()')
    pid, descriptor = spawn_terminal(source)
    worker.start()

    try:
        read_until(descriptor, b'[y/N]')
        os.write(descriptor, b'y\n')

        assert downloading.wait(5)

        os.write(descriptor, b'\x03')
        output = read_until(descriptor, b'interrupted')

        assert b'Traceback' not in output and b'Operational command' not in output
        assert not list(tmp_path.iterdir())
    finally:
        cleanup(pid, descriptor)
        release.set()
        server.shutdown()
        server.server_close()
        worker.join()


def test_manifest_supports_live_build_versioned_payloads(media):
    path, document = media

    for name in ('vmlinuz', 'initrd.img'):
        (path/'live'/name).rename(path/'live'/(name+'-6.12-amd64'))

    result = images.manifest(path, document['build'])
    atomic_json(path/'nvyr/image.json', result)

    assert images.verify_media(path) == result

    atomic_json(path/'nvyr/image.json', [])

    with pytest.raises(RouterError, match='manifest must be an object'):
        images.verify_media(path)

    document['product'] = 'not-nvyr'
    atomic_json(path/'nvyr/image.json', document)

    with pytest.raises(RouterError, match='unsupported'):
        images.verify_media(path)


@pytest.mark.parametrize('unsafe', ['/etc/passwd', 'live/../../etc/passwd'])
def test_manifest_rejects_paths_outside_media(media, unsafe):
    path, document = media
    document['files']['kernel']['path'] = unsafe
    atomic_json(path/'nvyr/image.json', document)

    with pytest.raises(RouterError, match='unsafe'):
        images.verify_media(path)


def test_catalog_publish_rename_selection_delete(catalog, media):
    before = catalog.catalog()

    with catalog.locked():
        second = catalog.add(*media, 'second', lambda stage: (stage/'config/user-file').write_text('keep'), make_default=True)

    listing = catalog.listing().splitlines()

    assert listing[0].split() == ['Image', 'Running', 'Default']

    first = next(line for line in listing if line.startswith('first '))
    second_row = next(line for line in listing if line.startswith('second '))

    assert first.index('Yes') == listing[0].index('Running')
    assert second_row.index('Yes') == listing[0].index('Default')

    with pytest.raises(RouterError, match='running or default'):
        catalog.delete('first')

    with pytest.raises(RouterError, match='running or default'):
        catalog.delete('second')

    catalog.rename('second', 'renamed')

    assert catalog.find(catalog.catalog(), 'renamed') == second
    assert (catalog.path(second)/'config/user-file').read_text() == 'keep'

    catalog.select('first')
    catalog.delete('renamed')

    assert catalog.catalog() == before
    assert not catalog.path(second).exists()


@pytest.mark.parametrize('failure', [OSError('disk full'), KeyboardInterrupt()])
def test_failed_copy_or_migration_does_not_publish(catalog, media, failure):
    pointer = os.readlink(catalog.boot/'current')

    def fail(stage):
        (stage/'config/partial').write_text('incomplete')
        raise failure

    with catalog.locked(), pytest.raises(type(failure)):
        catalog.add(*media, 'failed', fail, make_default=True)

    assert os.readlink(catalog.boot/'current') == pointer
    assert not list(catalog.root.glob('.install-*'))
    assert list(catalog.catalog()['images']) == [catalog.running]


def test_atomic_menu_catalog_switch_failure(catalog, media, monkeypatch):
    before = catalog.catalog()
    replace = os.replace

    def fail(source, target):
        if Path(target).name == 'current':
            raise OSError('injected publication failure')

        return replace(source, target)

    monkeypatch.setattr(os, 'replace', fail)

    with catalog.locked(), pytest.raises(OSError):
        catalog.add(*media, 'complete-but-unpublished', lambda stage: None, make_default=True)

    assert catalog.catalog() == before
    assert 'complete-but-unpublished' not in (catalog.boot/'current/grub.cfg').read_text()

    # A safely orphaned complete image may be recovered manually after power loss.
    assert len(list((catalog.root/'images').iterdir())) == 2


def test_grub_uses_stable_ids_and_both_consoles(catalog):
    assert stat.S_IMODE((catalog.path(catalog.running)/'overlay/upper').stat().st_mode) == 0o755

    menu = catalog.menu(catalog.catalog())

    for value in ('set timeout=5', 'console=tty0', 'console=ttyS0,115200n8', 'boot=nvyr',
                  '--fs-uuid', 'terminal_input --append serial', 'terminal_output --append serial'):
        assert value in menu

    assert catalog.running in menu
    assert 'one-boot developer recovery' in menu
    assert 'nvyr.developer-recovery=1' in menu

    for name in ('../evil', "bad'name", 'name with spaces'):
        with pytest.raises(RouterError):
            catalog.rename('first', name)

    with catalog.locked(), pytest.raises(RouterError, match='already exists'):
        catalog.add(Path(), {}, 'first', lambda stage: None, make_default=True)


def test_external_saved_configuration_is_readable_not_writable(tmp_path):
    store = Store(tmp_path/'state', saved_path=tmp_path/'config/nvyr-saved-config')
    store.write('boot.json', {'system': {'host-name': 'router'}})
    store.write('state.json', {'configuration': {}})

    assert stat.S_IMODE(store.saved_path.stat().st_mode) == 0o644
    assert stat.S_IMODE(store.path('state.json').stat().st_mode) == 0o600
    assert store.read('boot.json')['system']['host-name'] == 'router'
    assert not (store.directory/'boot.json').exists()

    store.write('boot.json', {})

    assert stat.S_IMODE(store.saved_path.stat().st_mode) == 0o644


def test_saved_config_does_not_adopt_old_location(tmp_path):
    original = Store(tmp_path/'state')
    original.write('boot.json', {'saved': True})
    current = Store(original.directory, saved_path=tmp_path/'config/nvyr-saved-config')

    assert current.read('boot.json') is None
    assert original.read('boot.json') == {'saved': True}

    current.write('boot.json', {'current': True})

    assert current.read('boot.json') == {'current': True}
    assert original.read('boot.json') == {'saved': True}


def test_migration_snapshot_lock_blocks_persistent_writes(tmp_path):
    store = Store(tmp_path/'state')
    started, finished = threading.Event(), threading.Event()

    def writer():
        started.set()
        store.write('state.json', {'configuration': {}})
        finished.set()

    with image_migration.configuration_snapshot(store.directory):
        worker = threading.Thread(target=writer)
        worker.start()

        assert started.wait(2)
        assert not finished.wait(.1)
        assert not store.path('state.json').exists()

    worker.join(2)

    assert finished.is_set()


def test_daemon_locks_state_before_store_initialization(tmp_path, monkeypatch):
    from nvyr import daemon

    original = Store(tmp_path/'state')
    original.write('boot.json', {'preserve': True})
    target = tmp_path/'config/nvyr-saved-config'
    monkeypatch.setattr('sys.argv', ['configd', '--state', str(original.directory), '--saved', str(target)])

    def busy(*args):
        raise BlockingIOError('another daemon owns this state')

    monkeypatch.setattr(daemon.fcntl, 'flock', busy)
    monkeypatch.setattr(daemon, 'Store', lambda *a, **k: pytest.fail('Store opened before locking'))

    with pytest.raises(BlockingIOError):
        daemon.main()

    assert original.path('boot.json').exists() and not target.exists()


def disk(name='/dev/sda', **kwargs):
    return dict(name=name, type='disk', size=8*1024**3, vendor='vendor', model='model',
                tran='virtio', serial='disk1', rm=False, ro=False, mountpoints=[None], children=[], **kwargs)


def test_eligible_disks_exclude_live_mounted_removable_and_stacked():
    clean = disk()
    live = dict(clean, name='/dev/sdb', children=[dict(name='/dev/sdb1', type='part', mountpoints=['/run/live/medium'])])
    flash = dict(clean, name='/dev/sdc', tran='usb', rm=True)
    swap = dict(clean, children=[dict(type='part', mountpoints=['[SWAP]'])])
    raid = dict(clean, children=[dict(type='raid1', mountpoints=[])])

    assert installation.eligible_disks([clean, live, flash, swap, raid, dict(clean, ro=True)]) == [clean]


def test_revalidate_disk_before_erasing(monkeypatch):
    original = disk()
    monkeypatch.setattr(installation, 'inventory', lambda: [dict(original, serial='replacement')])

    with pytest.raises(RouterError, match='changed'):
        installation.recheck_disk(original)


def test_generic_images_directory_and_unpublished_install_are_not_active_catalogs(tmp_path, monkeypatch):
    (tmp_path/'images').mkdir()
    (tmp_path/'boot/nvyr').mkdir(parents=True)

    @contextmanager
    def mount(*args, **kwargs):
        yield tmp_path

    monkeypatch.setattr(installation, 'mounted', mount)
    target = dict(disk(), children=[{'name': '/dev/sda3', 'fstype': 'ext4', 'type': 'part'}])
    monkeypatch.setattr(installation, 'rc_cmd', lambda *a, **k: (0, 'Filesystem features: has_journal ext_attr\n'))

    assert installation.existing_installation(target) is None

    (tmp_path/'boot/nvyr/current').symlink_to('missing-generation')

    with pytest.raises(RouterError):
        installation.existing_installation(target)

    monkeypatch.setattr(installation, 'rc_cmd', lambda *a, **k: (0, 'Filesystem features: has_journal needs_recovery\n'))

    with pytest.raises(RouterError, match='journal recovery'):
        installation.existing_installation(target)


@pytest.mark.parametrize('approved', [False, True])
def test_fresh_install_does_not_inspect_old_filesystems(approved, media, tmp_path, monkeypatch):
    """Old ext4 contents never block an erase, but final approval still gates it."""
    target = dict(disk(), children=[dict(name='/dev/sda3', type='part', fstype='ext4', mountpoints=[])])
    root, esp = tmp_path/'new-root', tmp_path/'new-esp'
    root.mkdir()
    esp.mkdir()
    inventory_calls, partitions, bootloaders, plans = [], [], [], []

    def inventory():
        inventory_calls.append(True)
        return [target]

    def partition(device):
        assert approved and len(inventory_calls) == 2
        partitions.append(device)
        return '/dev/sda2', '/dev/sda3'

    @contextmanager
    def mount(device, **kwargs):
        assert partitions and kwargs['options'] == 'rw'
        yield esp if device == '/dev/sda2' else root

    def summary(*args, **kwargs):
        assert not partitions
        plans.append(kwargs)
        return approved

    def command(argv, **kwargs):
        assert argv == ['blkid', '-s', 'UUID', '-o', 'value', '/dev/sda3']
        return 0, UUID

    monkeypatch.setattr(installation, 'live_media', lambda: media[0])
    monkeypatch.setattr(installation, 'inventory', inventory)
    monkeypatch.setattr(installation, 'choose', lambda *args: 0)
    monkeypatch.setattr(installation, 'existing_installation',
                        lambda *args: pytest.fail('Fresh installation inspected old filesystem'))
    monkeypatch.setattr(installation, 'ask_name', lambda *args: 'fresh')
    monkeypatch.setattr(installation, 'ask_administrator', lambda: ('nvyr', 'hashed'))
    monkeypatch.setattr(installation, 'confirm', lambda *args: False)
    monkeypatch.setattr(installation, 'has_saved_configuration', lambda *args: False)
    monkeypatch.setattr(installation, 'summary', summary)
    monkeypatch.setattr(installation, 'partition', partition)
    monkeypatch.setattr(installation, 'mounted', mount)
    monkeypatch.setattr(installation, 'rc_cmd', command)
    monkeypatch.setattr(image_migration, 'prepare', lambda *args, **kwargs: None)
    monkeypatch.setattr(installation, 'bootloader', lambda *args: bootloaders.append(args))

    installation._install()

    assert plans[0]['fresh'] is True
    assert plans[0]['target'] == installation.disk_label(target)
    if approved:
        assert partitions == ['/dev/sda']
        assert bootloaders == [(root, esp, '/dev/sda')]
        installed = images.Images(root).catalog()
        assert installed['images'][installed['default']]['name'] == 'fresh'
    else:
        assert not partitions and not bootloaders
        assert len(inventory_calls) == 1
        assert not list(root.iterdir())


@pytest.mark.parametrize('filesystem', ['dirty', 'no-installation'])
def test_preserving_installation_requires_readable_existing_install(filesystem, media, monkeypatch):
    target = dict(disk(), children=[dict(name='/dev/sda3', type='part', fstype='ext4', mountpoints=[])])
    monkeypatch.setattr(installation, 'live_media', lambda: media[0])
    monkeypatch.setattr(installation, 'inventory', lambda: [target])
    monkeypatch.setattr(installation, 'choose',
                        lambda message, *args: 1 if message == 'Installation mode:' else 0)
    monkeypatch.setattr(installation, 'mounted', lambda *args, **kwargs: pytest.fail('Dirty filesystem mounted'))
    monkeypatch.setattr(installation, 'partition', lambda *args: pytest.fail('Preserve mode erased disk'))
    monkeypatch.setattr(installation, 'summary', lambda *args, **kwargs: pytest.fail('Invalid install accepted'))

    if filesystem == 'dirty':
        monkeypatch.setattr(installation, 'rc_cmd', lambda *args, **kwargs:
                            (0, 'Filesystem features: has_journal needs_recovery\n'))
        message = 'journal recovery'
    else:
        monkeypatch.setattr(installation, 'existing_installation', lambda *args: None)
        message = 'No existing nVyR installation'

    with pytest.raises(RouterError, match=message):
        installation._install()


@pytest.mark.parametrize('operation,args', [(installation.install, ()), (installation.add, ('https://example.test/image.iso',))])
def test_initial_refusal_has_no_filesystem_or_network_effects(operation, args, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: '')

    for name in ('acquire', 'live_media', 'inventory'):
        monkeypatch.setattr(installation, name, lambda *a: pytest.fail('work happened before initial approval'))

    operation(*args)


def test_final_refusal_preserves_images_and_local_iso(catalog, media, tmp_path, monkeypatch):
    before = catalog.catalog()
    iso = tmp_path/'supplied.iso'
    iso.write_bytes(b'original')

    @contextmanager
    def mount(*args, **kwargs):
        yield media[0]

    monkeypatch.setattr(installation, 'Images', lambda: catalog)
    monkeypatch.setattr(installation, 'acquire', lambda _: (iso, False))
    monkeypatch.setattr(installation, 'mounted', mount)
    monkeypatch.setattr(installation, 'ask_name', lambda *a: 'next')
    monkeypatch.setattr(installation, 'choose', lambda *a: 0)
    monkeypatch.setattr(installation, 'confirm', lambda *a: False)
    monkeypatch.setattr(image_migration, 'prepare', lambda *a, **k: pytest.fail('installation ran after refusal'))
    installation._add(str(iso))

    assert catalog.catalog() == before
    assert iso.read_bytes() == b'original'


def test_remote_download_and_local_source_resolution(tmp_path, monkeypatch):
    payload = b'test ISO payload'*1000

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    monkeypatch.setattr(installation, 'ARCHIVE', tmp_path/'archive')

    try:
        path, automatic = installation.acquire(f'http://127.0.0.1:{server.server_port}/image.iso')

        assert automatic and path.read_bytes() == payload
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert installation.acquire(path.name) == (path, False)
        assert installation.acquire(str(path)) == (path, False)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize('line,argv', [
    ('install image', ['install']),
    ('add system image example.iso', ['add', 'example.iso']),
    ('set system boot image first', ['select', 'first']),
    ('rename system image first to second', ['rename', 'first', 'second']),
    ('delete system image first', ['delete', 'first']),
])
def test_image_commands_and_privileged_boundary(controller, line, argv):
    assert controller.execute(line)['argv'] == ['images.nvyr.op', *argv]

    for role in ('read-only', 'net-admin', 'sys-admin'):
        token = access.role.set(role)

        try:
            if role == 'read-only':
                with pytest.raises(RouterError, match='net-admin'):
                    controller.execute(line)

                with pytest.raises(RouterError, match='net-admin'):
                    controller.authorize_terminal(line, None)
            else:
                assert controller.execute(line)['argv'] == ['images.nvyr.op', *argv]
                controller.authorize_terminal(line, None)
        finally:
            access.role.reset(token)


def test_image_script_runs_worker_outside_configd_sandbox(monkeypatch):
    calls = []
    monkeypatch.setattr(operations, 'call', lambda argv, **kwargs: calls.append((argv, kwargs)))
    operations.add('/config/nvyr-images/a file.iso')
    argv, options = calls[0]

    assert argv[0] == 'systemd-run' and '--pty' in argv and '--wait' in argv
    assert argv[-3:] == ['nvyr.helpers.installation', 'add', '/config/nvyr-images/a file.iso']
    assert options == {'new_process_group': False}

    operations.rename('old', 'new')

    assert calls[-1][0][-3:] == ['rename', 'old', 'new']


def test_migration_does_not_interpret_new_image_schema(tmp_path, monkeypatch):
    """An older installer can copy configuration for an image with new callbacks."""
    from nvyr.schema import Schema

    incoming_schema = {'kind': 'node', 'children': {
        'future-feature': {'kind': 'leaf_node', 'validators': {'checks': {
            'future-validator': {'name': 'future-validator'},
        }}},
    }}
    with pytest.raises(ValueError, match='Unknown callback future-validator'):
        Schema(incoming_schema)

    stage = tmp_path/'stage'
    destination = stage/'config'
    configuration = {'future-feature': 'value'}
    atomic_json(destination/images.SAVED, saved_document(configuration))
    records = {
        'state.json': {'configuration': configuration, 'future-metadata': 1},
        'transaction.json': {'before': configuration, 'after': {'future-feature': 'changed'}},
        'confirmed.json': {'before': configuration},
    }
    for name, value in records.items():
        atomic_json(destination/'.nvyr'/name, value)

    requests = []

    def extract(argv, **kwargs):
        requests.append(argv[-1])
        if argv[-1] == 'etc/group':
            return 'nvyr-access:x:123:\n'
        return json.dumps(incoming_schema)

    monkeypatch.setattr(image_migration, 'cmd', extract)
    monkeypatch.setattr(image_migration.os, 'chown', lambda *args: None)

    image_migration.prepare(stage, retain=True)

    assert requests == ['etc/group']
    assert read_saved(destination/images.SAVED)[0] == configuration
    for name, value in records.items():
        assert json.loads((destination/'.nvyr'/name).read_text()) == value


@pytest.mark.parametrize('name,contents', [
    ('state.json', '{unfinished'),
    ('transaction.json', '[]'),
    ('confirmed.json', '{"before": []}'),
])
def test_migration_rejects_unreadable_recovery_records(tmp_path, monkeypatch, name, contents):
    """Relaxing feature validation must not publish malformed recovery records."""
    stage = tmp_path/'stage'
    private = stage/'config/.nvyr'
    private.mkdir(parents=True)
    (private/name).write_text(contents)
    monkeypatch.setattr(image_migration.os, 'chown', lambda *args: None)
    monkeypatch.setattr(image_migration, 'cmd', lambda *args, **kwargs: pytest.fail('Read image after malformed record'))

    with pytest.raises(RouterError, match=name):
        image_migration.prepare(stage)

    assert not (stage/'config'/images.SAVED).exists()


@pytest.mark.parametrize('status,output', [
    (23, 'rsync: write failed: No space left on device (28)\n'),
    (24, 'file has vanished: /config/containers/app/temporary\n'),
    (12, ''),
])
def test_migration_copy_reports_rsync_failure(tmp_path, monkeypatch, status, output):
    source = tmp_path / 'source'
    destination = tmp_path / 'destination'

    def copy(argv, **options):
        assert argv == ['rsync', '-aHAX', '--numeric-ids', '--exclude=/nvyr-images/download.iso',
                        '--', str(source) + '/', str(destination) + '/']
        assert options == {'timeout': None, 'env': os.environ | {'LC_ALL': 'C'}}
        return status, output

    monkeypatch.setattr(image_migration, 'rc_cmd', copy)
    with pytest.raises(RouterError) as failure:
        image_migration.copy_directory(source, destination, exclude=('nvyr-images/download.iso',))

    message = str(failure.value)
    assert f'rsync exit {status}' in message
    assert str(source) in message and str(destination) in message
    if output:
        assert output.strip() in message


@pytest.mark.parametrize('status', [1, 12, 23, 30])
def test_migration_override_does_not_accept_other_copy_errors(tmp_path, monkeypatch, status):
    monkeypatch.setattr(image_migration, 'rc_cmd', lambda *a, **k: (status, 'copy failed'))
    vanished = []
    with pytest.raises(RouterError, match=f'rsync exit {status}'):
        image_migration.copy_directory(tmp_path / 'source', tmp_path / 'target', vanished=vanished)
    assert vanished == []


@pytest.mark.parametrize('answer', ['', 'n', 'y'])
def test_image_vanished_copy_confirmation(catalog, media, tmp_path, monkeypatch, capsys, answer):
    """Only explicit consent publishes the staged image, after releasing the snapshot lock."""
    source = tmp_path / 'source'
    source.mkdir()
    configuration = {'container': {'name': {'ntopng': {'volume': {
        'DATA': {'source': 'ntopng/main', 'destination': '/var/lib/ntopng'},
    }}}}}
    atomic_json(source / images.SAVED, saved_document(configuration))
    before = catalog.catalog()
    locked = False

    @contextmanager
    def snapshot(state):
        nonlocal locked
        locked = True
        try:
            yield
        finally:
            locked = False

    def copy(argv, **options):
        assert locked
        target = Path(argv[-1])
        atomic_json(target / images.SAVED, saved_document(configuration))
        atomic_json(target / '.nvyr/state.json', {'configuration': configuration})
        return 24, f'file has vanished: "{source}/containers/ntopng/main/alerts.db-journal"\n'

    def respond(prompt):
        assert not locked
        assert prompt == 'Continue with this copy anyway? [y/N] '
        return answer

    monkeypatch.setattr(image_migration, 'configuration_snapshot', snapshot)
    monkeypatch.setattr(image_migration, 'rc_cmd', copy)
    monkeypatch.setattr(image_migration, 'cmd', lambda *a, **k: 'nvyr-access:x:123:\n')
    monkeypatch.setattr(image_migration.os, 'chown', lambda *a: None)
    monkeypatch.setattr('builtins.input', respond)

    def prepare(stage):
        image_migration.prepare(stage, source=source, lock_state=source,
                                confirm_vanished=installation.confirm_vanished)

    with catalog.locked():
        if answer == 'y':
            installed = catalog.add(*media, 'second', prepare, make_default=True)
            assert catalog.catalog()['default'] == installed
            assert read_saved(catalog.path(installed) / 'config' / images.SAVED)[0] == configuration
        else:
            with pytest.raises(RouterError, match='Installation cancelled'):
                catalog.add(*media, 'second', prepare, make_default=True)
            assert catalog.catalog() == before

    assert not list(catalog.root.glob('.install-*'))
    assert read_saved(source / images.SAVED)[0] == configuration
    output = capsys.readouterr().out
    assert 'Affected container: ntopng; volume: DATA' in output
    assert 'alerts.db-journal' in output
    assert 'incomplete or inconsistent' in output
    assert 'set container name ntopng disable' in output
    assert 'Do not save the disabled state' in output


def test_vanished_paths_match_exact_volume_boundaries_and_shared_owners(tmp_path):
    source = Path('/config')
    target = tmp_path / 'config'
    configuration = {'container': {'name': {
        'one': {'volume': {'DATA': {'source': '/config/containers/data'}}},
        'two': {'volume': {'DATA': {'source': 'data'}}},
        'other': {'volume': {'DATA': {'source': 'data-other'}}},
    }}}
    atomic_json(target / images.SAVED, saved_document(configuration))
    issues = [(source, target, 'file has vanished: "/config/containers/data/file"\n')]

    assert image_migration.affected_containers(issues, target) == [
        ('one', 'DATA', '/config/containers/data'), ('two', 'DATA', '/config/containers/data'),
    ]
    issues = [(source, target, 'file has vanished: "/config/unrelated/file"\n')]
    assert image_migration.affected_containers(issues, target) == []


def test_unattributed_vanished_files_remain_visible(tmp_path, monkeypatch, capsys):
    issues = [(Path('/config'), tmp_path, 'file has vanished: "/config/unrelated/file"\n')]
    monkeypatch.setattr('builtins.input', lambda prompt: '')
    assert not installation.confirm_vanished(issues, tmp_path)
    output = capsys.readouterr().out
    assert '/config/unrelated/file' in output
    assert 'Affected container:' not in output


@pytest.fixture
def migration_directory():
    # The unprivileged probe must reach the copied files without depending on
    # pytest's private ancestor directories or xdist's additional worker level.
    with tempfile.TemporaryDirectory(prefix='nvyr-migration-', dir='/tmp') as directory:
        path = Path(directory)
        path.chmod(0o755)
        yield path


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which('rsync') is None, reason='root and rsync required')
def test_migration_preserves_files_and_isolates_config(migration_directory, monkeypatch):
    source = migration_directory/'source'
    source.mkdir()
    (source/'user-files').mkdir()
    (source/'user-files/custom').write_text('persistent')
    (source/'user-files/custom').chmod(0o640)
    os.chown(source/'user-files/custom', 12345, 123)
    os.setxattr(source/'user-files/custom', 'user.test', b'metadata')
    acl = struct.pack('<I', 2)+b''.join(struct.pack('<HHI', tag, permission, identity)
        for tag, permission, identity in [(1, 6, 0xffffffff), (2, 4, 54321),
                                          (4, 4, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)])
    os.setxattr(source/'user-files/custom', 'system.posix_acl_access', acl)
    config = {'system': {'host-name': 'copied'}}
    atomic_json(source/images.SAVED, saved_document(config))
    atomic_json(source/'.nvyr/state.json', {'configuration': config})
    atomic_json(source/'.nvyr/login/developer.json', {'enabled': True})
    (source/'.nvyr/ssh').mkdir()
    (source/'.nvyr/ssh/key').write_text('identity')
    stage = migration_directory/'stage'
    stage.mkdir()
    (stage/'config').mkdir()
    real_cmd = image_migration.cmd

    def command(argv, **kwargs):
        if argv[0] == 'unsquashfs':
            assert argv[-1] == 'etc/group', 'Installer must not load the incoming schema'
            return 'nvyr-access:x:123:\n'

        return real_cmd(argv, **kwargs)

    monkeypatch.setattr(image_migration, 'cmd', command)
    image_migration.prepare(stage, source=source, retain=True, ssh_keys=False)
    target = stage/'config'

    assert read_saved(target/images.SAVED) == (config, {'factory': False})
    assert json.loads((target/'.nvyr/login/developer.json').read_text()) == {'enabled': True}
    assert (source/'.nvyr/ssh/key').exists() and not (target/'.nvyr/ssh').exists()
    assert (target/'user-files/custom').read_text() == 'persistent'
    assert os.getxattr(target/'user-files/custom', 'user.test') == b'metadata'
    assert os.getxattr(target/'user-files/custom', 'system.posix_acl_access') == acl
    assert (target/'user-files/custom').stat().st_uid == 12345
    assert (target/'user-files/custom').stat().st_gid == 123
    assert stat.S_IMODE((target/'user-files/custom').stat().st_mode) == 0o640
    assert stat.S_IMODE(target.stat().st_mode) == 0o1775
    assert stat.S_IMODE((target/images.SAVED).stat().st_mode) == 0o644
    assert stat.S_IMODE((target/'.nvyr').stat().st_mode) == 0o700

    # A directory writer can create user files but cannot replace the saved file.
    stage.chmod(0o755)

    def unprivileged():
        os.setgroups([123])
        os.setgid(123)
        os.setuid(65534)

    result = subprocess.run(['/bin/sh', '-c', 'cp "$1/nvyr-saved-config" "$1/user-copy" && touch "$1/user-owned" && ! echo overwrite >"$1/nvyr-saved-config" && ! rm "$1/nvyr-saved-config" && ! mv "$1/user-copy" "$1/nvyr-saved-config"', 'test', str(target)],
                            preexec_fn=unprivileged, capture_output=True)

    if result.returncode:
        pytest.fail(result.stderr.decode())

    image_migration.prepare(stage, source=None, retain=False, ssh_keys=False)

    assert not (target/'.nvyr/state.json').exists()
    assert (target/'user-files/custom').exists()
    assert 'nvyr' in json.loads((target/images.SAVED).read_text())['system']['login']['user']
    assert json.loads((target/'.nvyr/login/developer.json').read_text()) == {'enabled': True}
    assert read_saved(target/images.SAVED)[0]['system']['login']['user']['nvyr']['role'] == 'dev-admin'
