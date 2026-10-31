"""Automatic VRF conntrack map generation, stable allocations and reapplication."""

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import vrf_conntrack as ledger
from nvyr.config_scripts import vrf_conntrack
from nvyr.tree import ReadOnlyTree


@pytest.fixture(autouse=True)
def boot_id(tmp_path, monkeypatch):
    path = tmp_path / 'boot-id'
    path.write_text('boot')
    monkeypatch.setattr(ledger, 'BOOT_ID', path)
    return path


def gathered(config, directory):
    return vrf_conntrack.get_config(SimpleNamespace(effective=ReadOnlyTree(config), state_directory=directory))


def prepare(config, directory):
    values = gathered(config, directory)
    vrf_conntrack.verify(values, None)
    return vrf_conntrack.generate(values, None)


def configuration():
    """Include both small and full-width routing table IDs and different L3 providers."""
    return {
        'vrf': {'name': {'BLUE': {'table': '101'}, 'RED': {'table': '4294967295'}}},
        'interfaces': {
            'ethernet': {'eth1': {'vrf': 'BLUE', 'vif': {'10': {'vrf': 'RED'}, '20': {}}}},
            'dummy': {'dum0': {'vrf': 'RED'}},
            'virtual-ethernet': {'veth1': {'vrf': 'BLUE'}, 'veth2': {}},
            'bridge': {'br0': {'vrf': 'BLUE', 'member': {'interface': {'eth2': {}}}}},
        },
        'container': {'network': {'apps': {'vrf': 'RED'}, 'default': {}}},
    }


def test_members_and_shared_map(tmp_path):
    """No parent VRF inheritance for VIFs and no assignment for default devices."""
    config = configuration()
    assert vrf_conntrack.members(gathered(config, tmp_path)) == {
        'BLUE': 'BLUE', 'RED': 'RED', 'eth1': 'BLUE', 'eth1.10': 'RED',
        'dum0': 'RED', 'veth1': 'BLUE', 'br0': 'BLUE', 'pd-apps': 'RED',
    }
    rendered, prepared = prepare(config, tmp_path)
    assert rendered.count('map interfaces {') == 1
    assert 'ct zone set meta iifname map @interfaces' in rendered
    assert 'ct zone set meta oifname map @interfaces' in rendered
    assert rendered.count('priority -250') == 2
    assert rendered.count('ct state untracked return') == 2
    assert '"eth1.10" : 2' in rendered
    assert '"veth2"' not in rendered
    assert not prepared.path.exists()


def test_allocations_survive_restart_add_remove_and_table_changes(tmp_path, boot_id):
    """A different identity cannot inherit old connections, including after apply failure."""
    original = configuration()
    ledger.reserve(prepare(original, tmp_path)[1])

    config = {'vrf': {'name': {'AAA': {'table': '101'}, 'RED': {'table': '4294967295'}}}}
    _, prepared = prepare(config, tmp_path)
    assert prepared.ledger['zones'] == {'BLUE:101': 1, 'RED:4294967295': 2, 'AAA:101': 3}
    ledger.reserve(prepared)

    config['vrf']['name']['AAA']['table'] = '102'
    _, prepared = prepare(config, tmp_path)
    assert prepared.ledger['zones']['AAA:102'] == 4
    ledger.reserve(prepared)

    # Reboot clears kernel conntrack; retired reservations can then be reclaimed.
    boot_id.write_text('next')
    _, rebooted = prepare(config, tmp_path)
    assert rebooted.ledger['zones'] == {'AAA:102': 1, 'RED:4294967295': 2}


def test_failed_native_transaction_preserves_reservations(tmp_path, monkeypatch):
    """Use the shared apply path and retain IDs when its native transaction fails."""
    calls = []

    def fail(rendered, directory, **options):
        calls.append((rendered, directory, options))
        raise OSError('native transaction failed')

    monkeypatch.setattr(vrf_conntrack.nftables.manager, 'apply', fail)
    context = SimpleNamespace(state_directory=tmp_path)
    rendered, allocation = prepare(configuration(), tmp_path)

    with pytest.raises(OSError, match='native transaction failed'):
        vrf_conntrack.apply((rendered, allocation), context)

    assert calls == [(rendered, tmp_path, {'owner': 'vrf_conntrack'})]
    assert json.loads(allocation.path.read_text()) == allocation.ledger
    assert prepare(configuration(), tmp_path)[1].ledger == allocation.ledger


def test_removal_only_destroys_automatic_table(tmp_path):
    """Removing all VRFs neither flushes conntrack nor touches the firewall table."""
    rendered, prepared = prepare({}, tmp_path)
    assert rendered == 'destroy table inet nvyr_vrf_conntrack\n'


def test_exhaustion_and_corrupt_allocations_are_rejected(tmp_path, monkeypatch):
    """Checks report unavailable IDs without wrapping into another VRF's zone."""
    monkeypatch.setattr(vrf_conntrack, 'MAX_ZONE', 1)
    with pytest.raises(ValidationError, match='exhausted'):
        prepare(configuration(), tmp_path)
    assert not (tmp_path / 'vrf-conntrack.json').exists()

    (tmp_path / 'vrf-conntrack.json').write_text(json.dumps({'boot': 'boot', 'zones': {'BLUE:101': 0}}))
    with pytest.raises(ValidationError, match='Invalid VRF'):
        prepare(configuration(), tmp_path)


def test_lifecycle_reads_once_and_does_not_mutate_or_reserve_before_apply(tmp_path, monkeypatch):
    reads = []
    read = ledger.read_ledger

    def recorded(directory):
        reads.append(directory)
        return read(directory)

    monkeypatch.setattr(ledger, 'read_ledger', recorded)
    config = configuration() | {'system': {'host-name': 'unrelated'}, 'firewall': {'description': 'unrelated'}}
    values = gathered(config, tmp_path)
    before = deepcopy(values)
    assert 'system' not in values and 'firewall' not in values

    vrf_conntrack.verify(values, None)
    assert values == before and not values['path'].exists()
    rendered, allocation = vrf_conntrack.generate(values, None)
    assert values == before and not values['path'].exists()
    assert reads == [tmp_path]

    def installed(text, directory, **options):
        assert json.loads(allocation.path.read_text()) == allocation.ledger
        assert text == rendered and options == {'owner': 'vrf_conntrack'}

    monkeypatch.setattr(vrf_conntrack.nftables.manager, 'apply', installed)
    prepared = deepcopy(allocation)
    vrf_conntrack.apply((rendered, allocation), SimpleNamespace(state_directory=tmp_path))
    assert allocation == prepared and values == before


def test_reservation_failure_does_not_reach_nftables(tmp_path, monkeypatch):
    def fail(allocation):
        raise OSError('ledger write failed')

    generated = prepare(configuration(), tmp_path)
    monkeypatch.setattr(ledger, 'reserve', fail)
    monkeypatch.setattr(vrf_conntrack.nftables.manager, 'apply',
                        lambda *args, **kwargs: pytest.fail('nftables called without reservation'))

    with pytest.raises(OSError, match='ledger write failed'):
        vrf_conntrack.apply(generated, SimpleNamespace(state_directory=tmp_path))


@pytest.mark.parametrize('zones', [None, [], {'BLUE:101': True}, {'BLUE:101': '1'},
                                   {'BLUE:101': 65536}, {'BLUE:101': 1, 'RED:102': 1}])
def test_invalid_current_boot_ledger_is_rejected_without_changes(tmp_path, zones):
    path = tmp_path / 'vrf-conntrack.json'
    original = json.dumps({'boot': 'boot', 'zones': zones})
    path.write_text(original)

    with pytest.raises(ValidationError, match='Invalid VRF conntrack zone ledger'):
        prepare(configuration(), tmp_path)
    assert path.read_text() == original


def test_invalid_ledger_root_is_rejected(tmp_path):
    (tmp_path / 'vrf-conntrack.json').write_text('[]')
    with pytest.raises(ValidationError, match='Invalid VRF conntrack zone ledger'):
        prepare(configuration(), tmp_path)


def test_full_ledger_allows_existing_identity_but_does_not_reuse_gaps(tmp_path):
    path = tmp_path / 'vrf-conntrack.json'
    path.write_text(json.dumps({'boot': 'boot', 'zones': {'BLUE:101': 65535}}))
    config = {'vrf': {'name': {'BLUE': {'table': '101'}}}}
    assert prepare(config, tmp_path)[1].zones == {'BLUE': 65535}

    with pytest.raises(ValidationError, match='exhausted'):
        prepare(configuration(), tmp_path)


def test_missing_table_is_rejected_before_vrf_creation(tmp_path):
    with pytest.raises(ValidationError, match='a routing table is required'):
        prepare({'vrf': {'name': {'BLUE': {}}}}, tmp_path)
    assert not (tmp_path / 'vrf-conntrack.json').exists()


def test_commit_watches_membership_and_container_networks(controller, session):
    """The declarative consumer follows changed providers, without dependency cycles."""
    controller.execute('set vrf name BLUE table 101', session)
    result = controller.engine.commit(session)
    assert result['results']['vrf_conntrack']['success']

    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    result = controller.engine.commit(session)
    assert result['results']['dummy']['success']
    assert result['results']['vrf_conntrack']['success']

    controller.execute('delete interfaces dummy dum0 vrf', session)
    result = controller.engine.commit(session)
    assert result['results']['vrf_conntrack']['success']

    controller.execute('set container network apps subnet 198.18.0.0/24', session)
    controller.execute('set container network apps vrf BLUE disable-dns', session)
    result = controller.engine.commit(session)
    assert result['results']['container']['success']
    assert result['results']['vrf_conntrack']['success']
