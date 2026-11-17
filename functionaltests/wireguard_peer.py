"""WireGuard peers sharing the routed scenario's existing host namespaces."""
from contextlib import contextmanager

from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers.template import write
from smoketests.support import wait_for


@contextmanager
def peers(directory, namespace):
    directory.mkdir(mode=0o700)
    cmd(['ip', '-n', namespace, 'link', 'set', 'veth42076', 'up'])
    cmd(['ip', '-n', namespace, 'address', 'add', '198.18.79.2/24', 'dev', 'veth42076'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:79::2/64', 'dev', 'veth42076', 'nodad'])
    created = []
    try:
        for suffix, subnet in ((75, 78), (76, 77)):
            name = f'wg{suffix}'
            cmd(['ip', '-n', namespace, 'link', 'add', name, 'type', 'wireguard'])
            created.append((namespace, name))
            endpoint = '198.18.79.1' if suffix == 75 else '[2001:db8:79::1]'
            text = ('[Interface]\nPrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n'
                    f'ListenPort = 520{suffix}\n[Peer]\n'
                    'PublicKey = pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=\n'
                    f'AllowedIPs = 198.18.{subnet}.1/32, 2001:db8:{subnet}::1/128\n'
                    f'Endpoint = {endpoint}:520{suffix}\n')
            if suffix == 76:
                text += 'PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n'
            path = directory / (name + '.conf')
            write(path, text)
            cmd(['ip', 'netns', 'exec', namespace, 'wg', 'setconf', name, str(path)])
            cmd(['ip', '-n', namespace, 'address', 'add', f'198.18.{subnet}.2/30', 'dev', name])
            cmd(['ip', '-n', namespace, '-6', 'address', 'add', f'2001:db8:{subnet}::2/64', 'dev', name, 'nodad'])
            cmd(['ip', '-n', namespace, 'link', 'set', name, 'up'])

        # Independent peers need independent return routes to the same tunnel address.
        left = 'nvyr-routed-left'
        cmd(['ip', '-n', left, 'link', 'add', 'wg77', 'type', 'wireguard'])
        created.append((left, 'wg77'))
        path = directory / 'wg77.conf'
        write(path, '[Interface]\nPrivateKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n'
              'ListenPort = 52077\n[Peer]\n'
              'PublicKey = pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=\n'
              'AllowedIPs = 198.18.77.1/32, 2001:db8:77::1/128\n'
              'Endpoint = 198.18.73.1:52076\n')
        cmd(['ip', 'netns', 'exec', left, 'wg', 'setconf', 'wg77', str(path)])
        cmd(['ip', '-n', left, 'link', 'set', 'wg77', 'up'])
        cmd(['ip', '-n', left, 'address', 'add', '198.18.77.6/32', 'dev', 'wg77'])
        cmd(['ip', '-n', left, '-6', 'address', 'add', '2001:db8:77::6/128', 'dev', 'wg77', 'nodad'])
        cmd(['ip', '-n', left, 'route', 'add', '198.18.77.1/32', 'dev', 'wg77'])
        cmd(['ip', '-n', left, '-6', 'route', 'add', '2001:db8:77::1/128', 'dev', 'wg77'])
        for target_namespace, name, addresses in (
                (namespace, 'wg76', ('10.1.0.2/32', '10.0.0.99/32', 'fd42:100:0:2::2/128', 'fd42:100:0:1::99/128')),
                (left, 'wg77', ('10.0.0.2/32', '10.1.0.99/32', 'fd42:100:0:1::2/128', 'fd42:100:0:2::99/128'))):
            for address in addresses:
                family = ['-6'] if ':' in address else []
                flags = ['nodad'] if family else []
                cmd(['ip', '-n', target_namespace, *family, 'address', 'add', address, 'dev', name, *flags])
        # These destinations exist only behind the broad peer. A conflicting
        # AllowedIPs entry sends them to the specific peer, which discards them.
        for family, address in (('-4', '10.0.0.88/32'), ('-6', 'fd42:100:0:1::88/128')):
            flags = ['nodad'] if family == '-6' else []
            cmd(['ip', '-n', namespace, family, 'address', 'add', address, 'dev', 'wg76', *flags])
            cmd(['ip', '-n', left, family, 'route', 'add', 'blackhole', address])
        cmd(['ip', '-n', namespace, 'address', 'add', '198.18.78.99/32', 'dev', 'lo'])
        cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:78::99/128', 'dev', 'lo', 'nodad'])

        # nVyR's endpoints exist before these peers. Allow initial handshake retries before measuring traffic.
        for peer_namespace, destination in ((namespace, '198.18.78.1'), (namespace, '198.18.77.1'),
                                             (left, '198.18.77.1')):
            wait_for(lambda: rc_cmd(['ip', 'netns', 'exec', peer_namespace, 'ping', '-n',
                                     '-c', '1', '-W', '1', destination]),
                     lambda result: result[0] == 0, timeout=20, description=f'{peer_namespace} tunnel to {destination}')
        yield
    finally:
        for target_namespace, name in reversed(created):
            cmd(['ip', '-n', target_namespace, 'link', 'delete', name])
