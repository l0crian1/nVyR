"""Opt-in configd engine integration with real netlinkd and nftables backends."""

from tests.test_nftables_live import isolated, pytestmark


def test_real_membership_reapply_check_failure_confirm_and_restart():
    isolated('''
import sys
import time
from nvyr.config_scripts import interface_dummy, vrf
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, nftables
from nvyr.helpers.interfaces import NetlinkManager
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub

socket_path = directory / 'netlink.sock'
log = open(directory / 'netlink.log', 'w')
process = subprocess.Popen([sys.executable, '-m', 'nvyr.netlink_daemon',
    '--socket', str(socket_path), '--state-dir', str(directory / 'netlink'),
    '--resolver-file', str(directory / 'resolv.conf')], stdout=log, stderr=subprocess.STDOUT)
try:
    deadline = time.monotonic() + 10
    while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(.05)
    assert socket_path.exists(), (directory / 'netlink.log').read_text()
    interfaces.manager = NetlinkManager(socket_path)
    nftables.manager = Manager()
    schema = Schema.bundled()
    modules = {name: LifecycleStub() for name in schema.owners}
    modules.update(dummy=interface_dummy, vrf=vrf, firewall=firewall)
    engine = Engine(schema, modules, Store(directory / 'configd'))
    controller = Controller(engine)
    session = engine.open('root', 'test')
    def command(text):
        controller.execute(text, session)
    def commit():
        result = engine.commit(session)
        assert all(item['success'] for item in result['results'].values()), result
        return result
    def chain(name):
        return run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', name)

    command('set vrf name BLUE table 100')
    command('set interfaces dummy dum98')
    command('set firewall ipv4 input filter rule 10 inbound-interface dum98 action accept')
    command('set firewall ipv6 input filter rule 10 inbound-interface dum98 action accept')
    command('set firewall ipv4 output filter rule 10 outbound-interface dum98 action accept')
    commit()
    untouched = chain('ipv4_output')
    command('set interfaces dummy dum98 vrf BLUE')
    assert set(engine.check(session)['results']) == {'dummy', 'firewall'}
    assert 'sdifname' not in chain('ipv4_input')
    assert list(commit()['results']) == ['dummy', 'firewall']
    assert 'sdifname "dum98"' in chain('ipv4_input')
    assert 'sdifname "dum98"' in chain('ipv6_input')
    assert chain('ipv4_output') == untouched

    # A rejected consumer restores the successful interface edit in the kernel.
    original_verify = firewall.verify
    def fail(configuration, context):
        if not context.recovery:
            raise ValidationError('intentional consumer failure')
        original_verify(configuration, context)
    firewall.verify = fail
    command('delete interfaces dummy dum98 vrf')
    result = engine.commit(session)
    assert not result['changed'] and not result['results']['dummy']['success'], result
    assert json.loads(run('ip', '-j', 'link', 'show', 'dum98'))[0]['master'] == 'BLUE'
    assert 'sdifname "dum98"' in chain('ipv4_input')
    firewall.verify = original_verify
    engine.discard(session)

    # Commit-confirm must restore expressions as well as configuration and master.
    command('delete interfaces dummy dum98 vrf')
    result = engine.commit(session, minutes=1, confirmed_minutes=1)
    assert result['results']['firewall']['success'], result
    assert 'sdifname' not in chain('ipv4_input')
    engine.clock = lambda: engine.pending['deadline'] + 1
    engine.tick()
    assert engine.pending is None
    assert 'sdifname "dum98"' in chain('ipv4_input')

    # Restart recovery recreates deliberately lost native state from saved running intent.
    run('nft', 'delete', 'table', 'inet', 'nvyr_filter')
    restarted = Engine(schema, modules, Store(directory / 'configd'))
    assert 'sdifname "dum98"' in chain('ipv4_input')
    assert restarted.running['interfaces']['dummy']['dum98']['vrf'] == 'BLUE'
finally:
    process.terminate()
    process.wait(timeout=10)
    log.close()
''')
