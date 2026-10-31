"""Kea runtime readiness, instance lifecycle, and persistent lease ownership."""

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import dhcp_hosts
from nvyr.helpers.process import cmd, run
from nvyr.helpers.template import write

RUNTIME = Path('/run/nvyr-kea')


def instance_name(family, vrf):
    # Hex encoding keeps arbitrary allowed VRF names safe in systemd instances.
    return f'{family}-{vrf.encode().hex()}'


def inventory():
    """Read live addresses and follow master relationships to the owning VRF."""
    devices = json.loads(cmd(['ip', '-d', '-j', 'address', 'show']))
    names = {item['ifname']: item for item in devices}
    indexes = {item['ifindex']: item for item in devices}
    result = {}
    for name, device in names.items():
        current = device
        visited = set()
        vrf = 'default'
        while current:
            if current['ifindex'] in visited:
                raise RouterError(f'Interface master cycle while resolving DHCP listener {name}')
            visited.add(current['ifindex'])
            if current.get('linkinfo', {}).get('info_kind') == 'vrf':
                vrf = current['ifname']
                break
            master = current.get('master')
            current = indexes.get(master) if isinstance(master, int) else names.get(master)
        result[name] = {'vrf': vrf, 'addresses': [item['local'] for item in device.get('addr_info', ())],
                        'tentative': [item['local'] for item in device.get('addr_info', ()) if item.get('tentative')],
                        'dadfailed': [item['local'] for item in device.get('addr_info', ()) if item.get('dadfailed')],
                        'up': 'UP' in device.get('flags', ()),
                        'running': device.get('operstate') in ('UP', 'UNKNOWN'),
                        'vrf-device': device.get('linkinfo', {}).get('info_kind') == 'vrf'}
    return result


def wait_listeners(family, listeners, timeout=10):
    """Wait for kernel IPv6 address readiness, without changing DAD policy."""
    if family != 6:
        return
    deadline = time.monotonic() + timeout
    while True:
        devices = inventory()
        pending = []
        for listener in listeners:
            name, _, selected = listener.partition('/')
            device = devices.get(name, {})
            addresses = [value for value in device.get('addresses', ())
                         if ipaddress.ip_address(value).version == 6 and ipaddress.ip_address(value).is_link_local]
            required = addresses + ([selected] if selected else [])
            if set(required) & set(device.get('dadfailed', ())):
                raise RouterError(f'DHCPv6 interface {name}: IPv6 duplicate-address detection failed')
            # An unplugged, enabled port may not acquire link-local readiness yet.
            if device.get('up') and device.get('running') is False:
                continue
            if not addresses or set(required) & set(device.get('tentative', ())):
                pending.append(name)
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise RouterError('DHCPv6 listener addresses did not become ready: ' + ', '.join(pending))
        time.sleep(0.1)


@dataclass(frozen=True)
class Plan:
    family: int
    desired: dict
    rebind: bool = False


def control(path, command, arguments=None, *, timeout=10):
    request = {'command': command}
    if arguments is not None:
        request['arguments'] = arguments
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(json.dumps(request).encode())
        response = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                raise RouterError('Kea closed its control connection before replying')
            response.extend(chunk)
            if len(response) > 64 * 1024 * 1024:
                raise RouterError('Kea control response exceeds 64 MiB')
            try:
                result = json.loads(response)
                break
            except (ValueError, UnicodeDecodeError):
                continue
    if result.get('result') != 0:
        raise RouterError(f"Kea {command} failed: {result.get('text', result)}")
    return result


def sockets_ready(status):
    """A responsive control endpoint alone does not establish successful binding."""
    sockets = status.get('arguments', {}).get('sockets', {})
    state = sockets.get('status')
    if state == 'ready':
        return True
    if state == 'retrying':
        return False
    raise RouterError(f'Kea service sockets are {state or "unavailable"}: {sockets.get("errors", [])}')


def waiting_for_carrier(status, listeners):
    """Accept only Kea's explicit link-down retry, never unrelated socket errors."""
    sockets = status.get('arguments', {}).get('sockets', {})
    errors = sockets.get('errors', [])
    if sockets.get('status') != 'retrying' or not errors:
        return []

    devices = inventory()
    offline = {}
    for listener in listeners:
        name = listener.split('/', 1)[0]
        device = devices.get(name, {})
        if device.get('up') and device.get('running') is False:
            offline[f'the interface {name} is not running'] = name

    if all(error in offline for error in errors):
        return sorted({offline[error] for error in errors})
    return []


class Manager:
    def __init__(self, directory=RUNTIME, *, execute=run, request=control, update_hosts=None):
        self.directory = Path(directory)
        self.execute = execute
        self.request = request
        self.update_hosts = update_hosts or dhcp_hosts.reconcile

    def _active(self, instance):
        return self.execute(['systemctl', 'is-active', '--quiet', f'nvyr-kea@{instance}.service']) == 0

    def _install(self, instance, text):
        path = self.directory / f'{instance}.json'
        control_path = self.directory / f'{instance}.sock'
        unit = f'nvyr-kea@{instance}.service'
        if text is None:
            if self.execute(['systemctl', 'stop', unit], timeout=20):
                raise RouterError(f'Could not stop DHCP instance {instance}')
            path.unlink(missing_ok=True)
            control_path.unlink(missing_ok=True)
            return

        write(path, text)
        if self._active(instance):
            # Native reconfiguration keeps the lease backend and daemon alive.
            self.request(control_path, 'config-set', json.loads(text))
        else:
            control_path.unlink(missing_ok=True)
            self.execute(['systemctl', 'reset-failed', unit])
            if self.execute(['systemctl', 'start', unit], timeout=20):
                raise RouterError(f'Could not start DHCP instance {instance}')

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                status = self.request(control_path, 'status-get')
            except OSError:
                if not self._active(instance):
                    break
            else:
                if sockets_ready(status):
                    return
                configuration = json.loads(text)[f'Dhcp{instance[0]}']
                pending = waiting_for_carrier(status, configuration['interfaces-config']['interfaces'])
                if pending:
                    return pending
            time.sleep(0.1)
        raise RouterError(f'DHCP instance {instance} did not become ready; check {unit}')

    def apply(self, plan, state_directory, *, recovery=False, report=None):
        """Install a family's desired instances after validating native configs.

        Listener changes release old sockets before replacements start. An
        interface awaiting carrier is reported as pending rather than failed.
        Ordinary failures restore attempted instances and their hostfile state;
        recovery failures or incomplete rollback require engine recovery.
        """
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        old = {path.stem: path.read_text() for path in self.directory.glob(f'{plan.family}-*.json')}
        targets = old.keys() | plan.desired.keys()
        if not targets:
            return

        # Never compete with a separately managed packaged daemon.
        for unit in (f'isc-kea-dhcp{plan.family}-server.service', f'kea-dhcp{plan.family}-server.service'):
            if self.execute(['systemctl', 'is-active', '--quiet', unit]) == 0:
                raise RouterError(f'{unit} is active outside nVyR management; stop it first')

        for instance, text in plan.desired.items():
            configuration = json.loads(text)[f'Dhcp{plan.family}']
            wait_listeners(plan.family, configuration['interfaces-config']['interfaces'])
            lease = configuration['lease-database']['name']
            Path(lease).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(dir=self.directory, prefix='.check-') as folder:
                path = Path(folder) / f'{instance}.json'
                write(path, text)
                if self.execute(['env', f'KEA_CONTROL_SOCKET_DIR={self.directory}',
                                 f'KEA_DHCP_DATA_DIR={Path(lease).parent}',
                                 f'/usr/sbin/kea-dhcp{plan.family}', '-t', str(path)], timeout=20):
                    raise RouterError(f'Kea rejected configuration for instance {instance}')

        changed = []
        waiting = {}
        default_instance = instance_name(4, 'default')
        update_hosts = default_instance in targets
        try:
            # Release old sockets before starting their replacements. In particular,
            # moving a listener between VRFs must not overlap the previous binding.
            stopped = set()
            for instance in sorted(old):
                text = plan.desired.get(instance)
                old_interfaces = json.loads(old[instance])[f'Dhcp{plan.family}']['interfaces-config']
                new_interfaces = json.loads(text)[f'Dhcp{plan.family}']['interfaces-config'] if text else None
                if new_interfaces != old_interfaces:
                    changed.append(instance)
                    self._install(instance, None)
                    stopped.add(instance)

            for instance in sorted(targets):
                text = plan.desired.get(instance)
                if text is None and instance in stopped:
                    continue
                if not recovery and not plan.rebind and text == old.get(instance) and self._active(instance):
                    continue
                if instance not in changed:
                    changed.append(instance)
                pending = self._install(instance, text)
                if pending:
                    waiting[instance] = pending

            # Reconcile after native installation, including disable/deletion and
            # domain/subnet changes that do not generate a client lease event.
            if update_hosts:
                self.update_hosts(self.directory / f'{default_instance}.json')
        except Exception as error:
            failures = []
            # Stop all attempted replacements before restoring any previous socket.
            for instance in reversed(changed):
                try:
                    self._install(instance, None)
                except Exception as rollback:
                    failures.append(str(rollback))
            for instance in changed:
                if instance not in old:
                    continue
                try:
                    self._install(instance, old[instance])
                except Exception as rollback:
                    failures.append(str(rollback))
            if update_hosts:
                try:
                    self.update_hosts(self.directory / f'{default_instance}.json')
                except Exception as rollback:
                    failures.append(str(rollback))
            if recovery or failures:
                raise RecoveryError(f'DHCP recovery required: {error}; rollback: {failures}') from error
            raise RouterError(f'DHCP apply failed; previous instances restored: {error}') from error

        if report:
            for instance, interfaces in waiting.items():
                vrf = bytes.fromhex(instance.split('-', 1)[1]).decode()
                report(f'DHCPv{plan.family} ({vrf}): waiting for carrier on {", ".join(interfaces)}.')


def main():
    """Systemd entry point; isolate INET sockets in the selected Linux VRF."""
    instance = sys.argv[1]
    family, encoded = instance.split('-', 1)
    if family not in ('4', '6'):
        raise ValueError('Invalid DHCP family')
    vrf = bytes.fromhex(encoded).decode()
    if instance != instance_name(int(family), vrf):
        raise ValueError('Invalid DHCP instance')
    os.environ['KEA_CONTROL_SOCKET_DIR'] = str(RUNTIME)
    os.environ['KEA_PIDFILE_DIR'] = str(RUNTIME)
    path = RUNTIME / (instance + '.json')
    configuration = json.loads(path.read_text())
    lease = configuration['Dhcp' + family]['lease-database']['name']
    os.environ['KEA_DHCP_DATA_DIR'] = str(Path(lease).parent)
    command = ['/usr/sbin/kea-dhcp' + family, '-c', str(path)]
    if vrf != 'default':
        command = ['/usr/sbin/ip', 'vrf', 'exec', vrf, *command]
    os.execv(command[0], command)


manager = Manager()
