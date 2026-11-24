"""MKA interoperability with an independent native Linux router across a veth link."""

from contextlib import contextmanager, ExitStack
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from functionaltests.mpls_peer import processes
from functionaltests.native_network import native_namespace
from nvyr.helpers.process import cmd, run
from smoketests.assertions import assert_operational_output
from smoketests.support import configuration_case, wait_for


@contextmanager
def supplicant(namespace, config):
    peer = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'wpa_supplicant', '-D', 'macsec_linux',
                             '-i', 'uplink', '-c', str(config)], stdout=subprocess.DEVNULL)
    try:
        yield
    finally:
        peer.terminate()
        peer.wait(timeout=10)


def capture_traffic(directory):
    capture = directory / 'lower.pcap'
    with subprocess.Popen(['tcpdump', '-ni', 'mka-test-port', '-U', '--immediate-mode', '-w', str(capture)],
                          stderr=subprocess.PIPE, text=True) as tcpdump:
        try:
            assert 'listening on' in tcpdump.stderr.readline()
            cmd(['ip', 'vrf', 'exec', 'MKA491', 'ping', '-n', '-c', '3', '-w', '6', '198.18.246.2'])
            cmd(['ip', 'vrf', 'exec', 'MKA491', 'ping', '-n', '-c', '2', '-w', '6', '2001:db8:246::2'])
        finally:
            tcpdump.terminate()
    # The inner echo traffic and OSPF hellos must travel in protected Ethernet frames.
    read = ['tcpdump', '-nr', str(capture)]
    assert subprocess.check_output([*read, 'ether proto 0x88e5'], stderr=subprocess.DEVNULL)
    cleartext = 'ip net 198.18.246.0/30 or ip6 net 2001:db8:246::/64 or ip proto 89'
    assert not subprocess.check_output([*read, cleartext], stderr=subprocess.DEVNULL)


def test_mka_routed_link(config, request, native_namespace, tmp_path):
    peer = ['ip', '-n', native_namespace]
    native = ['ip', 'netns', 'exec', native_namespace]
    key = '01' * 32
    config_file = tmp_path / 'peer.conf'
    config_file.write_text(f"""ap_scan=0
network={{
 key_mgmt=NONE
 eapol_flags=0
 macsec_policy=1
 mka_cak={key}
 mka_ckn=0491
 mka_priority=64
}}
""")
    with ExitStack() as cleanup:
        cmd(['ip', 'link', 'add', 'mka-test-port', 'type', 'veth', 'peer', 'name', 'uplink', 'netns', native_namespace])
        cleanup.callback(cmd, ['ip', 'link', 'del', 'mka-test-port'])
        cmd(['ip', 'link', 'set', 'mka-test-port', 'up'])
        cmd(peer + ['link', 'set', 'uplink', 'up'])
        cmd(peer + ['link', 'set', 'lo', 'up'])
        cmd(peer + ['addr', 'add', '198.18.247.2/32', 'dev', 'lo'])
        cmd(peer + ['link', 'add', 'link', 'uplink', 'name', 'secured', 'type', 'macsec', 'port', '1', 'encrypt', 'on'])
        cmd(peer + ['addr', 'add', '198.18.246.2/30', 'dev', 'secured'])
        cmd(peer + ['addr', 'add', '2001:db8:246::2/64', 'dev', 'secured', 'nodad'])
        # The FRR peer must be able to traverse its vty socket directory.
        frr_root = Path(cleanup.enter_context(TemporaryDirectory()))
        frr_root.chmod(0o755)
        cleanup.enter_context(processes(frr_root / 'peer', native_namespace, """
router ospf
 ospf router-id 198.18.247.2
exit
interface secured
 ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
exit
interface lo
 ip ospf area 0
 ip ospf passive
exit
""", daemons=('mgmtd', 'zebra', 'ospfd')))
        cleanup.enter_context(configuration_case(config, request, config.get_config()))
        config.set('set vrf name MKA491 table 42491')
        config.set('set interfaces macsec macsec491 source-interface mka-test-port vrf MKA491')
        config.set('set interfaces macsec macsec491 address 198.18.246.1/30 address 2001:db8:246::1/64')
        config.set(f'set interfaces macsec macsec491 mka preshared-key cak {key} ckn 0491')
        config.set('set interfaces macsec macsec491 mka key-server-priority 16')
        config.set('set interfaces macsec macsec491 replay-protection window 64')
        config.set('set vrf name MKA491 protocols ospf options router-id 198.18.247.1')
        config.set('set vrf name MKA491 protocols ospf interface macsec491 area 0 network point-to-point hello-interval 1 dead-interval 4')
        config.commit()

        def routes():
            return json.loads(cmd(['ip', '-j', 'route', 'show', 'vrf', 'MKA491', '198.18.247.2/32']))

        def converged():
            wait_for(routes, lambda rows: any(row.get('dev') == 'macsec491' and row.get('protocol') == 'ospf'
                                              for row in rows), description='OSPF prefix over MACsec', timeout=50)
            cmd(['ip', 'vrf', 'exec', 'MKA491', 'ping', '-n', '-c', '1', '-w', '3', '198.18.247.2'])

        index = Path('/sys/class/net/macsec491/ifindex').read_text()
        with supplicant(native_namespace, config_file):
            converged()
            capture_traffic(tmp_path)
            assert_operational_output('show macsec macsec491 detail', 'Secured', 'Yes', '0491', 'GCM-AES-128')
            assert_operational_output('show macsec macsec491 counters', 'OutPktsEncrypted', 'InPktsOK')

            # Different CAKs with the same CKN must isolate the peers.
            config.set('set interfaces macsec macsec491 mka preshared-key cak ' + '02' * 32)
            config.commit()
            wait_for(routes, lambda rows: not rows, description='OSPF withdrawal on CAK mismatch', timeout=30)
            assert run(['ip', 'vrf', 'exec', 'MKA491', 'ping', '-n', '-c', '1', '-w', '2', '198.18.246.2']) != 0
            config.set('set interfaces macsec macsec491 mka preshared-key cak ' + key)
            config.commit()
            converged()

        wait_for(routes, lambda rows: not rows, description='OSPF withdrawal after peer stop', timeout=30)
        with supplicant(native_namespace, config_file):
            converged()
            assert Path('/sys/class/net/macsec491/ifindex').read_text() == index
            channel = json.loads(cmd(native + ['ip', '-s', '-j', 'macsec', 'show', 'secured']))[0]
            assert sum(peer['InPktsOK'] for peer in channel['rx_sc']) > 0

            config.set('set interfaces macsec macsec491 disable')
            config.commit()
            assert 'UP' not in json.loads(cmd(['ip', '-j', 'link', 'show', 'macsec491']))[0]['flags']
            assert run(['systemctl', 'is-active', '--quiet', 'nvyr-macsec@macsec491']) != 0
            config.delete('delete interfaces macsec macsec491 disable')
            config.set('set interfaces macsec macsec491 transmit-mode integrity-only')
            config.commit()
            converged()
            channel = json.loads(cmd(['ip', '-s', '-j', 'macsec', 'show', 'macsec491']))[0]
            assert not channel['encrypt'] and channel['OutPktsProtected'] > 0
