"""Real generated reverse-path rules, isolated from the router's network namespace."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables environment')

PACKET_TEST = r'''
import ipaddress, socket, struct, time
from nvyr.helpers.nftables_normalizer import normalize

def checksum(data):
    """Compute the Internet checksum for the crafted IP and UDP headers."""
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def packet(source, destination, mac):
    """Spoof a source with valid checksums so only its reverse route differs."""
    src = ipaddress.ip_address(source).packed
    dst = ipaddress.ip_address(destination).packed
    udp = struct.pack('!HHHH', 42423, 42424, 12, 0) + b'test'
    if version == 4:
        pseudo = src + dst + struct.pack('!BBH', 0, 17, len(udp))
    else:
        pseudo = src + dst + struct.pack('!I3xB', len(udp), 17)
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]

    if version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 32, 1, 0, 64, 17, 0, src, dst)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, src, dst)
    ethernet = bytes.fromhex(mac.replace(':', '')) + bytes.fromhex('020000000001')
    return ethernet + struct.pack('!H', 0x800 if version == 4 else 0x86dd) + header + udp

def counters():
    """Read normalized rule counters, including the existing rule after validation."""
    document = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'nvyr_filter'))
    table = normalize(document)['tables']['inet']['nvyr_filter']
    chain = 'prerouting' if family == 'inet' else family + '_prerouting'
    records = table['chains'][chain]['rules']
    assert not any(record.get('unsupported') for record in records), records
    return {record['number']: record['counter']['packets'] for record in records
            if 'number' in record and 'counter' in record}

run('ip', 'link', 'set', 'lo', 'up')
peer = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
try:
    time.sleep(.1)
    # The peer injects raw frames only; suppress its autonomous IPv6 discovery.
    run('nsenter', '-t', str(peer.pid), '-n', 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=1',
        'net.ipv6.conf.default.disable_ipv6=1')
    for index in range(2):
        run('ip', 'link', 'add', f'r{index}', 'type', 'veth', 'peer', 'name', f'p{index}')
        run('ip', 'link', 'set', f'p{index}', 'netns', str(peer.pid))
        run('ip', 'link', 'set', f'r{index}', 'up')
        run('nsenter', '-t', str(peer.pid), '-n', 'ip', 'link', 'set', f'p{index}', 'up')
    destination = '10.10.0.1' if version == 4 else 'fd00:10::1'
    suffix = '/32' if version == 4 else '/128'
    run('ip', '-4', 'address', 'add', '10.10.0.1/32', 'dev', 'r0')
    run('ip', '-6', 'address', 'add', 'fd00:10::1/128', 'dev', 'r0', 'nodad')
    sources = ({'same': '192.0.2.10', 'other': '192.0.2.20', 'missing': '198.51.100.10'} if version == 4 else
               {'same': '2001:db8:1::10', 'other': '2001:db8:2::20', 'missing': '2001:db8:3::10'})
    table = '100' if vrf else 'main'
    if vrf:
        run('ip', 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100')
        run('ip', 'link', 'set', 'BLUE', 'up')
        run('ip', 'link', 'set', 'r0', 'master', 'BLUE')
        run('ip', 'link', 'set', 'r1', 'master', 'BLUE')
        run('ip', f'-{version}', 'route', 'add', 'unreachable', 'default', 'table', '100', 'metric', '4278198272')
        # A source known only in main must remain unreachable from BLUE.
        run('ip', f'-{version}', 'route', 'add', sources['missing'] + suffix, 'dev', 'lo')
    run('ip', f'-{version}', 'route', 'add', sources['same'] + suffix, 'dev', 'r0', 'table', table)
    run('ip', f'-{version}', 'route', 'add', sources['other'] + suffix, 'dev', 'r1', 'table', table)
    mac = json.loads(run('ip', '-j', 'link', 'show', 'r0'))[0]['address']

    for mode in ('strict', 'loose', 'disabled'):
        validation = {'default': default}
        if mode != default:
            validation['interface'] = {'r0': {'mode': mode}}
        tree = {'firewall': {family: {
            'source-validation': validation,
            'prerouting': {'raw': {'rule': {'10': {
                'action': 'continue', 'protocol': ['udp'], 'destination-port': ['42424'],
                'inbound-interface': ['r0'], 'counter': {},
            }}}},
        }}}
        if vrf:
            tree['vrf'] = {'name': {'BLUE': {'table': '100'}}}
        text = apply(tree)
        assert text.count('counter drop comment "source-validation-') <= 2

        for category, source in sources.items():
            before_counts = counters()
            data = packet(source, destination, mac)
            sender = "import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(('p0',0)); s.send(bytes.fromhex('%s'))" % data.hex()
            run('nsenter', '-t', str(peer.pid), '-n', 'python3', '-c', sender)
            after_counts = counters()
            should_pass = mode == 'disabled' or category == 'same' or (mode == 'loose' and category == 'other')
            received = after_counts['10'] - before_counts['10']
            assert received == int(should_pass), (family, version, vrf, default, mode, category, before_counts, after_counts)
            if not should_pass:
                number = 'source-validation-' + mode
                assert after_counts[number] - before_counts[number] == 1
            else:
                for number in after_counts:
                    if number.startswith('source-validation-'):
                        assert after_counts[number] == before_counts[number], (mode, category, before_counts, after_counts)

        # An unchanged commit preserves both the rules and their packet counts.
        saved_counts = counters()
        unchanged = apply(tree)
        assert 'source-validation-' not in unchanged
        assert counters() == saved_counts

    # Removal must release private sets without disturbing the remaining raw rule.
    del tree['firewall'][family]['source-validation']
    apply(tree)
    assert 'source_validation_' not in run('nft', 'list', 'ruleset')
    assert 'continue comment "10|"' in run('nft', '-s', 'list', 'ruleset')

    # Recovery must remove orphaned private sets even without a previous snapshot.
    tree['firewall'][family]['source-validation'] = {'default': 'strict', 'interface': {'r0': {'mode': 'loose'}}}
    apply(tree)
    previous = {}
    apply({}, recovery=True)
    assert 'source_validation_' not in run('nft', 'list', 'ruleset')
finally:
    peer.terminate()
    peer.wait()
'''


@pytest.mark.parametrize('version', [4, 6])
@pytest.mark.parametrize('shared', [False, True])
@pytest.mark.parametrize('vrf', [False, True])
@pytest.mark.parametrize('default', ['strict', 'loose', 'disabled'])
def test_generated_source_validation_packets_and_lifecycle(version, shared, vrf, default):
    """Check every default/override/route combination through real generation and apply."""
    family = 'inet' if shared else f'ipv{version}'
    parameters = f'version = {version}\nfamily = {family!r}\nvrf = {vrf!r}\ndefault = {default!r}\n'
    isolated(parameters + PACKET_TEST)
