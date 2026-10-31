"""Stage separation, prepared rollback, stale-plan rejection and worker transport."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import container
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import containers as worker
from nvyr.helpers.containers import run_apply
from nvyr.modules import CommitContext
from nvyr.tree import ReadOnlyTree
from tests.test_containers import FakeRuntime, configuration


def test_get_config_gathers_only_container_settings_and_vrf_names():
    effective = {'container': configuration(), 'vrf': {'name': {'BLUE': {'table': '100'}}},
                 'system': {'host-name': 'router'}}
    context = CommitContext(ReadOnlyTree(effective), ReadOnlyTree({}), 'container', ('container',),
                            previous_effective=ReadOnlyTree({}))
    gathered = container.get_config(context)

    assert gathered == {'container': configuration(), 'previous': {}, 'vrfs': ['BLUE'],
                        'changed': {'network': ['LAN'], 'pod': [], 'name': ['APP']}}
    container.verify(gathered, context)
    desired = configuration()
    desired['network']['LAN'].update({'vrf': 'MISSING', 'disable-dns': True})
    with pytest.raises(ValidationError, match='VRF MISSING is not configured'):
        container.verify({'container': desired, 'vrfs': ['BLUE']}, context)


def test_generation_prepares_changes_without_installing_them(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    original = deepcopy(desired)

    generated = runtime.generate(desired)

    assert desired == original
    assert generated['changed']['name'] == ['APP']
    assert generated['changed']['network'] == ['LAN']
    assert '[Container]\n' in generated['forward']['containers']['APP']['text']
    assert not runtime.state.exists()
    assert not runtime.pending.exists()
    assert not runtime.quadlets.exists()
    assert not runtime.registries.exists()
    assert not runtime.networks
    assert not any(event[0] == 'systemctl' for event in runtime.events)


def test_apply_uses_generated_bytes_without_rendering_or_resolving_again(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    generated = runtime.generate(configuration())
    original = deepcopy(generated)

    def unexpected(*args, **kwargs):
        pytest.fail('Apply attempted generation or verification again')

    monkeypatch.setattr(container, 'render', unexpected)
    monkeypatch.setattr(container, 'verify', unexpected)
    runtime.image_id = unexpected
    runtime.validate_units = unexpected
    runtime.apply(generated)

    assert generated == original
    path = runtime.quadlets / 'nvyr-container-415050.container'
    assert path.read_text() == generated['forward']['containers']['APP']['text']
    assert runtime.registries.read_text() == generated['forward']['registry']
    assert runtime.state.read_text() == generated['forward']['inventory']


def test_unchanged_multivalues_preserve_pinned_image_and_skip_rendering(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    desired['name']['APP']['capability'] = ['net-raw', 'net-admin']
    runtime.apply(runtime.generate(desired))
    image = runtime.read()['images']['APP']
    runtime.image_id = lambda *args: pytest.fail('Unchanged configuration resolved its image again')
    monkeypatch.setattr(container, 'render', lambda *args: pytest.fail('Unchanged units were rendered again'))

    generated = runtime.generate(desired)

    assert generated is None
    assert runtime.read()['images']['APP'] == image


def test_failed_apply_uses_prepared_rollback_without_regeneration(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    original = configuration()
    runtime.apply(runtime.generate(original))
    desired = deepcopy(original)
    desired['name']['APP']['memory'] = '64m'
    generated = runtime.generate(desired)
    snapshot = deepcopy(generated)
    runtime.fail_start = 1
    monkeypatch.setattr(container, 'render', lambda *args: pytest.fail('Rollback rendered configuration'))
    runtime.image_id = lambda *args: pytest.fail('Rollback resolved an image tag')

    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(generated)

    assert generated == snapshot
    assert runtime.read()['configuration'] == original
    assert (runtime.quadlets / 'nvyr-container-415050.container').read_text() == generated['rollback']['containers']['APP']['text']
    assert not runtime.pending.exists()


def test_changed_manifest_rejects_prepared_transaction_before_native_changes(tmp_path):
    runtime = FakeRuntime(tmp_path)
    generated = runtime.generate(configuration())
    changed = {'objects': {'name': ['OTHER']}, 'interfaces': {}, 'images': {}, 'inputs': {}}
    runtime.state.write_text(json.dumps(changed))

    with pytest.raises(RouterError, match='state changed after generation'):
        runtime.apply(generated)

    assert json.loads(runtime.state.read_text()) == changed
    assert not runtime.pending.exists()
    assert not runtime.networks
    assert not any(event[0] == 'systemctl' for event in runtime.events)


def test_new_pending_transaction_rejects_prepared_transaction(tmp_path):
    runtime = FakeRuntime(tmp_path)
    generated = runtime.generate(configuration())
    runtime.pending.write_text('{}')

    with pytest.raises(RouterError, match='state changed after generation'):
        runtime.apply(generated)

    assert runtime.pending.read_text() == '{}'
    assert not runtime.state.exists()
    assert not runtime.networks


def test_worker_transports_prepared_input_without_stage_recursion(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(worker.config, 'RUNTIME', tmp_path)
    monkeypatch.setattr(container, 'STATE', tmp_path / 'storage' / 'managed.json')
    monkeypatch.setattr(worker.config, 'VOLUME_ROOT', str(tmp_path / 'volumes'))
    observed = []

    def apply(prepared):
        observed.append(prepared)

    def execute(argv, **kwargs):
        with monkeypatch.context() as patch:
            index = argv.index('nvyr.helpers.containers')
            patch.setattr(worker.sys, 'argv', argv[index:])
            worker.main()
        return 0, ''

    monkeypatch.setattr(container, 'apply', apply)
    monkeypatch.setattr(worker, 'rc_cmd', execute)
    gathered = {'configuration': ReadOnlyTree(configuration()), 'recovery': False}
    result = run_apply(gathered)

    assert observed == [{'configuration': configuration(), 'recovery': False}]
    assert result is None
    assert capsys.readouterr().out == ''
    assert (tmp_path / 'storage').exists()
    assert (tmp_path / 'volumes').exists()
    assert not list(tmp_path.glob('request-*'))


def test_unconfigured_router_does_not_start_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(container, 'STATE', tmp_path / 'managed.json')
    monkeypatch.setattr(worker, 'run_apply', lambda *args, **kwargs: pytest.fail('Unexpected host worker'))
    context = SimpleNamespace(recovery=True, report=print)

    generated = container.generate({'container': {}, 'vrfs': []}, context)
    assert generated is None
    container.apply(generated, context)


def test_inventory_retains_native_identity_without_configuration_or_secrets(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    desired['name']['APP']['environment'] = {'SECRET': {'value': 'private-value'}}
    generated = runtime.generate(desired)
    runtime.apply(generated)

    saved = json.loads(runtime.state.read_text())
    cleanup = json.loads(generated['cleanup'])
    assert saved['objects'] == {'name': ['APP'], 'pod': [], 'network': ['LAN']}
    assert saved['interfaces']['pd-APP-0'] == ['container', 'APP']
    assert saved['images']['APP'] == runtime.available_image
    assert saved['inputs']['APP']['configuration'] == container.fingerprint(desired['name']['APP'])
    assert set(cleanup) == {'objects', 'interfaces'}
    assert 'private-value' not in runtime.state.read_text()
    assert 'private-value' not in generated['cleanup']
    assert not {'before', 'previous', 'configuration', 'before_text', 'record_text'} & generated.keys()


def test_recovery_preserves_image_id_without_saved_cli_configuration(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    pinned = runtime.read()['images']['APP']
    runtime.configuration = {}  # Boot starts from configd's saved target, not a previous live tree.
    runtime.available_image = 'b' * 64

    runtime.apply(runtime.generate(desired, recovery=True))

    assert runtime.read()['images']['APP'] == pinned


def test_registry_only_change_does_not_inspect_or_restart_workloads(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    runtime.owned = lambda *args: pytest.fail('Unchanged workload inspected')
    desired['registry'] = {'example.com': {'priority': '10'}}

    runtime.apply(runtime.generate(desired))

    assert not any(event[:2] == ('systemctl', 'stop') for event in runtime.events)
    assert not any(event[0] in ('ip', 'podman') for event in runtime.events)
