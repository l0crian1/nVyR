"""GeoIP downloads, commit integration and runtime refresh failure boundaries."""

import asyncio
from dataclasses import replace
from io import BytesIO
import gzip
import hashlib
from pathlib import Path
from urllib.error import URLError

import pytest

from nvyr.config_scripts import firewall, firewall_failsafe
from nvyr.errors import BusyError, OperationalError, RecoveryError, RouterError, ValidationError
from nvyr.helpers import access, geoip, geoip_config, nftables, suggestors
from nvyr.helpers.nftables_formatters import nft_singleton_group
from tests.lifecycle import firewall_context


FIRST = b'192.0.2.0,192.0.2.255,US\n198.51.100.0,198.51.100.255,CA\n2001:db8::,2001:db8::ffff,US\n'
SECOND = FIRST.replace(b'192.0.2.255', b'192.0.2.127')


def configuration():
    return {'firewall': {'group': {'address-group': {
        'ipv4': {'USA': {'geoip': {'country': ['US']}}},
        'ipv6': {'USA': {'geoip': {'country': ['US']}}},
    }}}}


def page(metadata):
    return (f'<dl><dt>Format</dt><dd>CSV</dd><dt>SHA1SUM</dt><dd>{metadata["sha1"]}</dd></dl>'
            f'<a href="{metadata["url"]}">CSV</a>'
            '<dl><dt>Format</dt><dd>MMDB</dd><dt>SHA1SUM</dt><dd>' + '0' * 40 + '</dd></dl>').encode()


def release(payload, date='2026-10'):
    return {'release': date, 'sha1': hashlib.sha1(payload).hexdigest(),
            'url': f'https://download.db-ip.com/free/dbip-country-lite-{date}.csv.gz'}


def install(manager, payload=FIRST, *, active=True):
    metadata = release(payload)
    manager.directory.mkdir(parents=True, exist_ok=True)
    manager.database(metadata).write_bytes(gzip.compress(payload))
    manager.record('downloaded', metadata)
    if active:
        manager.publish(metadata)
    return metadata


@pytest.fixture
def manager(tmp_path, monkeypatch):
    instance = geoip.Manager(tmp_path / 'geoip')
    monkeypatch.setattr(geoip, 'manager', instance)
    return instance


@pytest.fixture
def loads(monkeypatch):
    calls = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, *args, **kwargs: calls.append(text))
    return calls


def serve(monkeypatch, payload=SECOND):
    requests = []
    metadata = release(payload)

    def fetch(url, destination, limit):
        requests.append(url)
        destination.write(page(metadata) if url == geoip.PAGE else gzip.compress(payload))

    monkeypatch.setattr(geoip, 'fetch', fetch)
    return metadata, requests


def reject_load(*args, **kwargs):
    raise RouterError('rejected')


def uncertain_load(*args, **kwargs):
    raise RecoveryError('timeout')


def context(configuration, directory, previous=None, *, recovery=False):
    previous = previous or {}
    result = firewall_context(configuration, previous, 'firewall', ('firewall',), recovery,
                              previous_effective=previous)
    return replace(result, state_directory=directory)


def test_country_schema_multi_completion_and_typos(controller, session):
    controller.execute('set firewall group address-group ipv4 USA geoip country US country CA', session)
    controller.execute('set firewall group address-group ipv6 USA geoip country US', session)
    assert geoip_config.groups(controller.engine.view(session))['ipv4', 'USA'] == ('CA', 'US')
    assert 'US' in {item.value for item in suggestors.geoip_countries(None)}
    choices = controller.completion('set firewall group address-group ipv4 USA geoip country ', session, explicit=True)
    assert 'GB' in dict(choices['candidates'])
    for code in ('XX', 'us', 'USA', 'US,CA'):
        with pytest.raises(RouterError):
            controller.execute('set firewall group address-group ipv4 USA geoip country ' + code, session)


def test_geoip_verification_rejects_empty_and_mixed_sources():
    with pytest.raises(ValidationError, match='at least one country'):
        geoip_config.verify('ipv4', 'TEST', {'geoip': {}})
    with pytest.raises(ValidationError, match='invalid GeoIP country'):
        geoip_config.verify('ipv4', 'TEST', {'geoip': {'country': ['XX']}})
    with pytest.raises(ValidationError, match='cannot be combined'):
        geoip_config.verify('ipv4', 'TEST', {'geoip': {'country': ['US']}, 'address': ['192.0.2.1']})
    with pytest.raises(ValidationError, match='cannot be combined'):
        geoip_config.verify('ipv4', 'TEST', {'geoip': {'country': ['US']}, 'dynamic': {}})


def test_commit_check_never_downloads(controller, engine, session, manager, monkeypatch):
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('verification downloaded data'))
    controller.execute('set firewall group address-group ipv4 USA geoip country US', session)
    result = engine.check(session)
    assert result['results']['firewall']['success']
    assert not manager.directory.exists()


def test_download_uses_uncompressed_hash_and_skips_unchanged_payload(manager, monkeypatch):
    metadata, requests = serve(monkeypatch)
    assert manager.download() == metadata
    assert manager.database(metadata).exists()
    assert manager.metadata('active') is None
    manager.download()
    assert requests == [geoip.PAGE, metadata['url'], geoip.PAGE]


def test_unrecognized_download_page_keeps_existing_cache(manager, monkeypatch):
    old = install(manager)
    monkeypatch.setattr(geoip, 'fetch', lambda url, stream, limit: stream.write(b'<html>changed</html>'))
    with pytest.raises(OperationalError, match='Cannot identify'):
        manager.download()
    assert manager.metadata('active')['sha1'] == old['sha1']
    assert manager.metadata('check')['error']


def test_checksum_failure_never_publishes_download(manager, monkeypatch):
    old = install(manager)
    metadata = release(SECOND)
    monkeypatch.setattr(geoip, 'fetch', lambda url, stream, limit:
                        stream.write(page(metadata) if url == geoip.PAGE else gzip.compress(FIRST)))
    with pytest.raises(OperationalError, match='checksum mismatch'):
        manager.download()
    assert manager.metadata('downloaded')['sha1'] == old['sha1']
    assert not manager.database(metadata).exists()


def test_truncated_download_keeps_active_generation(manager, monkeypatch):
    old = install(manager)
    metadata = release(SECOND)
    monkeypatch.setattr(geoip, 'fetch', lambda url, stream, limit:
                        stream.write(page(metadata) if url == geoip.PAGE else gzip.compress(SECOND)[:12]))
    with pytest.raises(OperationalError, match='GeoIP update failed'):
        manager.download()
    assert manager.metadata('active')['sha1'] == old['sha1']


@pytest.mark.parametrize('payload', [
    b'192.0.2.9,192.0.2.1,US\n', b'192.0.2.1,2001:db8::1,US\n',
    b'192.0.2.1,192.0.2.1,XX\n', b'not-an-address,192.0.2.1,US\n',
    b'192.0.2.1,192.0.2.1,US,extra\n', b'', b'x' * 1025,
])
def test_malformed_csv_is_rejected(manager, payload):
    metadata = install(manager, payload, active=False)
    with pytest.raises((ValueError, OperationalError)):
        geoip.read_rows(manager.database(metadata), metadata['sha1'])


def test_csv_size_limit(manager, monkeypatch):
    metadata = install(manager)
    monkeypatch.setattr(geoip, 'MAX_CSV', 10)
    with pytest.raises(OperationalError, match='size'):
        geoip.read_rows(manager.database(metadata), metadata['sha1'])


def test_apply_populates_both_families_in_original_transaction(manager, loads, tmp_path):
    install(manager, active=False)
    current = context(configuration(), tmp_path)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert len(loads) == 1
    text = loads[0]
    assert 'flags interval;' in text and 'auto-merge;' in text
    assert '192.0.2.0-192.0.2.255' in text and '2001:db8::-2001:db8::ffff' in text
    assert '198.51.100' not in text
    assert manager.metadata('active')


def test_commit_without_download_warns_and_keeps_empty_groups(controller, engine, session, manager, loads, monkeypatch):
    """An initial provider outage must not prevent publishing the firewall configuration."""
    def unavailable(url, destination, limit):
        raise URLError('provider unavailable')

    monkeypatch.setattr(geoip, 'fetch', unavailable)
    controller.execute('set firewall group address-group ipv4 USA geoip country US', session)
    controller.execute('set firewall group address-group ipv6 USA geoip country US', session)
    controller.execute('set firewall ipv4 input filter rule 10 source-address-group USA action drop', session)

    result = engine.commit(session)

    assert result['results']['firewall']['success']
    assert result['changed']
    assert not session.mutations
    assert geoip_config.groups(engine.running) == {('ipv4', 'USA'): ('US',), ('ipv6', 'USA'): ('US',)}
    assert any('Warning:' in message and 'will be empty' in message for message in result['messages'])
    assert len(loads) == 1
    assert 'flush set inet nvyr_filter ipv4_address_group_USA' in loads[0]
    assert 'flush set inet nvyr_filter ipv6_address_group_USA' in loads[0]
    assert 'add element inet nvyr_filter' not in loads[0]
    assert 'ip saddr @ipv4_address_group_USA' in loads[0]
    assert manager.metadata('active') is None
    assert manager.metadata('downloaded') is None
    assert 'provider unavailable' in manager.metadata('check')['error']

    # A later updater fills both groups even though their configuration is unchanged.
    metadata, requests = serve(monkeypatch)
    assert 'refreshed 2' in manager.update(engine)['text']
    assert '192.0.2.0-192.0.2.127' in loads[-1]
    assert '2001:db8::-2001:db8::ffff' in loads[-1]
    assert manager.metadata('active')['sha1'] == metadata['sha1']


def test_commit_uses_existing_cache_without_download(manager, loads, tmp_path, monkeypatch):
    """An existing database keeps all country members available without provider access."""
    install(manager)
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('commit contacted network'))
    messages = []
    current = replace(context(configuration(), tmp_path), report=messages.append)

    firewall.apply(firewall.generate(current.effective, current), current)

    assert '192.0.2.0-192.0.2.255' in loads[0]
    assert '2001:db8::-2001:db8::ffff' in loads[0]
    assert not messages


def test_first_successful_commit_populates_previously_empty_groups(manager, loads, tmp_path, monkeypatch):
    """Publishing a database must not leave older empty groups marked as up to date."""
    previous = configuration()
    effective = configuration()
    effective['firewall']['group']['address-group']['ipv4']['CANADA'] = {'geoip': {'country': ['CA']}}
    metadata, requests = serve(monkeypatch)
    current = context(effective, tmp_path, previous)

    firewall.apply(firewall.generate(current.effective, current), current)

    assert 'add element inet nvyr_filter ipv4_address_group_CANADA { 198.51.100.0-198.51.100.255 }' in loads[0]
    assert 'add element inet nvyr_filter ipv4_address_group_USA { 192.0.2.0-192.0.2.127 }' in loads[0]
    assert 'add element inet nvyr_filter ipv6_address_group_USA { 2001:db8::-2001:db8::ffff }' in loads[0]
    assert manager.metadata('active')['sha1'] == metadata['sha1']


def test_empty_geoip_fallback_does_not_hide_firewall_apply_failure(manager, tmp_path, monkeypatch):
    """The fallback handles missing data, not a rejected nftables transaction."""
    monkeypatch.setattr(nftables.manager, 'apply', reject_load)
    current = context(configuration(), tmp_path, recovery=True)

    with pytest.raises(RouterError, match='rejected'):
        firewall.apply(firewall.generate(current.effective, current), current)

    assert manager.metadata('active') is None


def test_corrupt_cached_database_is_not_replaced_with_empty_groups(manager, loads, tmp_path, monkeypatch):
    """An unreadable existing database remains an error rather than losing installed policy."""
    metadata = install(manager)
    manager.database(metadata).write_bytes(b'not a gzip file')
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('corrupt cache contacted network'))
    current = context(configuration(), tmp_path)

    with pytest.raises(OperationalError, match='Cannot read GeoIP cache'):
        firewall.apply(firewall.generate(current.effective, current), current)

    assert not loads


def test_initial_apply_failure_retries_downloaded_generation(manager, loads, tmp_path, monkeypatch):
    metadata, requests = serve(monkeypatch)
    current = context(configuration(), tmp_path)
    rendered = firewall.generate(current.effective, current)
    original_apply = nftables.manager.apply
    monkeypatch.setattr(nftables.manager, 'apply', reject_load)
    with pytest.raises(RouterError, match='rejected'):
        firewall.apply(rendered, current)
    assert manager.metadata('active') is None
    assert manager.metadata('downloaded')['sha1'] == metadata['sha1']
    monkeypatch.setattr(nftables.manager, 'apply', original_apply)
    firewall.apply(rendered, current)
    assert requests == [geoip.PAGE, metadata['url']]
    assert manager.metadata('active')['sha1'] == metadata['sha1']


def test_unchanged_group_is_not_flushed_on_other_firewall_changes(manager, loads, tmp_path):
    install(manager)
    before = configuration()
    after = configuration()
    after['firewall']['ipv4'] = {'input': {'filter': {'rule': {'10': {'action': 'accept'}}}}}
    current = context(after, tmp_path, before)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert 'flush set' not in loads[0]
    assert '192.0.2' not in loads[0]


def test_recovery_uses_cache_without_network(manager, loads, tmp_path, monkeypatch):
    install(manager)
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('recovery contacted network'))
    current = context(configuration(), tmp_path, recovery=True)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert '192.0.2.0-192.0.2.255' in loads[0]


def test_missing_recovery_cache_warns_and_loads_empty_groups(manager, loads, tmp_path, monkeypatch):
    """Reboot can restore a configuration committed during an outage without downloading."""
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('recovery contacted network'))
    messages = []
    current = replace(context(configuration(), tmp_path, recovery=True), startup=True, report=messages.append)

    firewall.apply(firewall.generate(current.effective, current), current)

    assert len(loads) == 1
    assert 'flush set inet nvyr_filter ipv4_address_group_USA' in loads[0]
    assert 'flush set inet nvyr_filter ipv6_address_group_USA' in loads[0]
    assert 'add element' not in loads[0]
    assert len(messages) == 1 and 'GeoIP cache is missing' in messages[0]
    assert manager.metadata('active') is None


def test_manual_update_and_unchanged_check(manager, engine, loads, monkeypatch):
    engine.running = configuration()
    install(manager)
    metadata, requests = serve(monkeypatch)
    assert 'refreshed 2' in manager.update(engine)['text']
    assert len(loads) == 1 and '192.0.2.0-192.0.2.127' in loads[0]
    assert 'delete chain' not in loads[0] and 'delete set' not in loads[0]
    assert manager.metadata('active')['sha1'] == metadata['sha1']
    assert 'unchanged' in manager.update(engine)['text']
    assert len(loads) == 1
    assert requests == [geoip.PAGE, metadata['url'], geoip.PAGE]


def test_failsafe_excludes_network_backed_groups(controller, session):
    """Pre-interface protection cannot request DNS or DB-IP downloads."""
    for command in (
        'set firewall fail-safe group address-group ipv4 EARLY geoip country US',
        'set firewall fail-safe group address-group ipv6 EARLY geoip country US',
        'set firewall fail-safe group domain-group ipv4 EARLY domain example.com',
        'set firewall fail-safe ipv4 input filter rule 10 source-domain-group EARLY',
        'set firewall fail-safe ipv6 name EARLY rule 10 destination-domain-group EARLY',
    ):
        with pytest.raises(RouterError):
            controller.execute(command, session)


def test_update_failure_keeps_old_active_and_retries_same_download(manager, engine, loads, monkeypatch):
    engine.running = configuration()
    old = install(manager)
    new, requests = serve(monkeypatch)
    original_apply = nftables.manager.apply
    monkeypatch.setattr(nftables.manager, 'apply', reject_load)
    with pytest.raises(RouterError, match='rejected'):
        manager.update(engine)
    assert manager.metadata('active')['sha1'] == old['sha1']
    assert manager.metadata('downloaded')['sha1'] == new['sha1']
    monkeypatch.setattr(nftables.manager, 'apply', original_apply)
    assert 'refreshed' in manager.update(engine)['text']
    assert requests.count(new['url']) == 1


def test_update_uses_configuration_after_download(manager, engine, loads, monkeypatch):
    engine.running = configuration()
    metadata = install(manager, SECOND, active=False)

    def download():
        engine.running['firewall']['group']['address-group']['ipv4']['USA']['geoip']['country'] = ['CA']
        return metadata

    monkeypatch.setattr(manager, 'download', download)
    manager.update(engine)
    assert '198.51.100.0-198.51.100.255' in loads[0]
    assert '192.0.2.0' not in loads[0]


def test_busy_or_unhealthy_router_blocks_updater(manager, engine, loads, monkeypatch):
    engine.running = configuration()
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('busy router downloaded data'))
    engine.busy = True
    with pytest.raises(BusyError):
        manager.update(engine)
    engine.busy = False
    engine.unhealthy = True
    with pytest.raises(BusyError):
        manager.update(engine)
    assert not loads


def test_commit_starting_during_download_defers_update(manager, engine, loads, monkeypatch):
    engine.running = configuration()
    metadata = install(manager, SECOND, active=False)

    def download():
        engine.busy = True
        return metadata

    monkeypatch.setattr(manager, 'download', download)
    with pytest.raises(BusyError):
        manager.update(engine)
    assert not loads and manager.metadata('active') is None


def test_operator_can_read_but_cannot_update(manager, engine):
    token = access.role.set('read-only')
    try:
        assert manager.status(engine)['attribution'] == geoip.ATTRIBUTION
        with pytest.raises(RouterError, match='net-admin'):
            manager.update(engine)
    finally:
        access.role.reset(token)


def test_uncertain_apply_requires_recovery(manager, engine, monkeypatch):
    engine.running = configuration()
    install(manager)
    serve(monkeypatch)
    monkeypatch.setattr(nftables.manager, 'apply', uncertain_load)
    with pytest.raises(RecoveryError):
        manager.update(engine)
    assert engine.unhealthy


def test_all_static_address_sets_merge_but_dynamic_sets_do_not():
    for family in ('ipv4', 'ipv6'):
        for definition in ({}, {'address': ['192.0.2.1' if family == 'ipv4' else '2001:db8::1']},
                           {'geoip': {'country': ['US']}}):
            rendered = nft_singleton_group('address-group', family, 'TEST', definition)
            assert 'flags interval;' in rendered and 'auto-merge;' in rendered
        dynamic = {'dynamic': {'timeout': '10m', 'size': '65536', 'gc-interval': '30s'}}
        assert 'auto-merge' not in nft_singleton_group('address-group', family, 'TEST', dynamic)


def test_timer_and_package_installation():
    root = Path(__file__).resolve().parents[1]
    timer = (root / 'packaging/nvyr-geoip-update.timer').read_text()
    assert 'OnCalendar=*-*-* 00:00:00' in timer
    assert 'Persistent=true' in timer
    assert 'geoip.nvyr.op update' in (root / 'packaging/nvyr-geoip-update.service').read_text()
    for name in ('nvyr-geoip-update.service', 'nvyr-geoip-update.timer'):
        assert name in (root / 'scripts/build-deb.sh').read_text()
    assert 'systemctl enable nvyr-geoip-update.timer' in (root / 'images/0100-router.hook.chroot').read_text()


@pytest.mark.parametrize('role', ['read-only', 'net-admin'])
def test_rpc_requires_authenticated_update_role(engine, manager, loads, monkeypatch, tmp_path, role):
    from nvyr.daemon import Server
    from nvyr.protocol import Client

    engine.running = configuration()
    engine.running['system'] = {'login': {'user': {'automation': {'role': role}}}}
    install(manager)
    serve(monkeypatch)

    async def scenario():
        path = tmp_path / 'geoip.sock'
        server = Server(engine, identity=lambda writer: ('automation', 'test'))
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        client = Client(path)
        try:
            status = await asyncio.to_thread(client.request, 'geoip-status')
            assert status['active']
            if role == 'read-only':
                with pytest.raises(RouterError, match='net-admin'):
                    await asyncio.to_thread(client.request, 'geoip-update')
                assert not loads
            else:
                result = await asyncio.to_thread(client.request, 'geoip-update')
                assert 'refreshed 2' in result['text']
                assert len(loads) == 1
            assert not engine.sessions
        finally:
            client.close()
            listener.close()
            await listener.wait_closed()
            await asyncio.sleep(0)

    asyncio.run(scenario())


def test_fetch_rejects_oversized_response(monkeypatch):
    response = BytesIO(b'oversized')
    response.url = geoip.PAGE
    monkeypatch.setattr(geoip, 'urlopen', lambda *args, **kwargs: response)
    with pytest.raises(OperationalError, match='size or duration'):
        geoip.fetch(geoip.PAGE, BytesIO(), 3)


def test_fetch_rejects_redirect_to_another_host(monkeypatch):
    response = BytesIO(b'data')
    response.url = 'https://example.com/data'
    monkeypatch.setattr(geoip, 'urlopen', lambda *args, **kwargs: response)
    with pytest.raises(OperationalError, match='unexpected download host'):
        geoip.fetch(geoip.PAGE, BytesIO(), 100)


def test_update_without_groups_never_downloads(manager, engine, monkeypatch):
    monkeypatch.setattr(manager, 'download', lambda: pytest.fail('unused updater downloaded data'))
    assert 'No GeoIP address-groups configured' in manager.update(engine)['text']
