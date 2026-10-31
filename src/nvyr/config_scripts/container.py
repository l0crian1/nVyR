"""Validate, generate and apply container configuration.

Quadlet and systemd own the native object lifecycle. Generation prepares changed
definitions and snapshots installed files; one host call applies that result.
"""

from copy import deepcopy
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.render import json_text
from nvyr.tree import lookup
from nvyr.helpers import container_config as config, containers as worker, filesystem
from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers.template import render, write
from nvyr.helpers.verification import require_fields


RUNTIME = Path('/run/nvyr-containers')
STATE = Path('/config/podman/managed.json')
QUADLETS = Path('/run/containers/systemd')
REGISTRIES = Path('/etc/containers/registries.conf.d/90-nvyr.conf')
GENERATOR = '/usr/lib/systemd/system-generators/podman-system-generator'


def read_state():
    """Read native inventory; configd remains the sole owner of configuration."""
    if not STATE.exists():
        return {'objects': {}, 'interfaces': {}, 'images': {}, 'inputs': {}}
    return json.loads(STATE.read_text())


def inventory(configuration):
    """Retain only the names needed to recognize and clean up native objects."""
    return {'objects': {kind: sorted(lookup(configuration, (kind,), {})) for kind in ('network', 'pod', 'name')},
            'interfaces': config.interface_owners(configuration)}


def get_config(context):
    """Collect intended settings, prior settings and affected native objects."""
    desired = lookup(context.effective, ('container',), {})
    previous = dict(lookup(context.previous_effective, ('container',), {}))
    if context.recovery:
        # Include objects created before interrupted publication, even on deletion.
        applied = read_state()
        pending = STATE.with_suffix('.pending.json')
        interrupted = json.loads(pending.read_text()) if pending.exists() else {}
        for kind in ('network', 'pod', 'name'):
            names = set(applied['objects'].get(kind, ())) | set(interrupted.get('objects', {}).get(kind, ()))
            previous[kind] = {**dict.fromkeys(names, {}), **lookup(previous, (kind,), {})}

    changed = {}
    for kind in ('network', 'pod', 'name'):
        names = lookup(previous, (kind,), {}).keys() | lookup(desired, (kind,), {}).keys()
        affected = set(names) if context.recovery else set()
        for path in context.get_changed(('container', kind)):
            affected.update(names if len(path) <= 2 else (path[2],))
        changed[kind] = affected

    # Replacing a network affects its consumers; replacing a pod affects its members.
    for tree in (previous, desired):
        for name, section in lookup(tree, ('pod',), {}).items():
            if changed['network'].intersection(lookup(section, ('network',), {})):
                changed['pod'].add(name)
    for tree in (previous, desired):
        for name, section in lookup(tree, ('name',), {}).items():
            if (changed['network'].intersection(lookup(section, ('network',), {}))
                    or lookup(section, ('pod',), None) in changed['pod']):
                changed['name'].add(name)

    return {'container': desired, 'previous': previous,
            'changed': {kind: sorted(names) for kind, names in changed.items()},
            'vrfs': list(lookup(context.effective, ('vrf', 'name'), {}))}


def verify_registries(configuration):
    registries = lookup(configuration, ('registry',), {})
    priorities = set()
    for name, settings in registries.items():
        require_fields(settings, ('priority',), f'container registry {name}')
        priority = str(settings['priority'])
        # Equal priorities would leave registry precedence ambiguous.
        if int(priority) in priorities:
            raise ValidationError('container registry priorities must be unique')
        priorities.add(int(priority))


def verify_options(container, path):
    # Keeping the image resolver file conflicts with generating explicit server entries.
    if 'disable-dns' in container and lookup(container, ('name-server',), None):
        raise ValidationError(f'{path}: disable-dns conflicts with name-server')
    # Podman rejects --dns, including none, when the container has network=none.
    if (lookup(container, ('name-server',), None) or 'disable-dns' in container) and not (
            lookup(container, ('network',), None) or 'allow-host-networking' in container):
        raise ValidationError(f'{path}: DNS options require a network attachment or allow-host-networking')

    destinations = []
    for source, settings in lookup(container, ('device',), {}).items():
        destination = lookup(settings, ('destination',), source)
        destinations.append(PurePosixPath(destination))

    for destination in lookup(container, ('tmpfs',), {}):
        destinations.append(PurePosixPath(destination))

    destinations.extend(PurePosixPath(settings['destination']) for settings in lookup(container, ('volume',), {}).values()
                        if 'destination' in settings)
    for index, destination in enumerate(destinations):
        # Mounts and devices must not shadow one another at duplicate or nested destinations.
        if any(destination == other or destination in other.parents or other in destination.parents
               for other in destinations[:index]):
            raise ValidationError(f'{path}: mount and device destinations must not overlap')


def verify(configuration, context):
    """Check relationships and constraints beyond individual schema values."""
    vrfs = configuration['vrfs']
    configuration = configuration['container']
    verify_registries(configuration)

    networks = lookup(configuration, ('network',), {})
    claimed = []
    for name, network in networks.items():
        path = f'container network {name}'
        # Dependencies guard deletion; new references must resolve before generation.
        if 'vrf' in network and network['vrf'] not in vrfs:
            raise ValidationError(f'{path}: VRF {network["vrf"]} is not configured')
        # Aardvark cannot bind a bridge address in a VRF; require explicit network DNS opt-out.
        if 'vrf' in network and 'disable-dns' not in network:
            raise ValidationError(f'{path}: VRF networks require disable-dns because Aardvark cannot bind VRF addresses')
        # The IPv6 minimum depends on the subnets; the schema checks the general MTU range.
        if 'mtu' in network and int(network['mtu']) < 1280 and any(
                ':' in prefix for prefix in lookup(network, ('subnet',), {})):
            raise ValidationError(f'{path}: IPv6 networks require an mtu of at least 1280')

        # Explicit subnets make the configured network reproducible across boots.
        if not lookup(network, ('subnet',), None):
            raise ValidationError(f'{path}: requires at least one subnet')
        for prefix, settings in network['subnet'].items():
            subnet = ipaddress.ip_network(prefix)
            # Overlapping container bridges make host routing ambiguous.
            for other, owner in claimed:
                if other.version == subnet.version and other.overlaps(subnet):
                    raise ValidationError(f'{path}: subnet {prefix} overlaps {owner} {other}')
            claimed.append((subnet, name))
            # The native gateway must be a usable member of its associated subnet.
            gateway = ipaddress.ip_address(lookup(settings, ('gateway',), str(subnet.network_address + 1)))
            if gateway not in subnet or gateway == subnet.network_address or (
                    subnet.version == 4 and gateway == subnet.broadcast_address):
                raise ValidationError(f'{path}: gateway {gateway} is not usable in {prefix}')

    addresses = set()
    ports = []
    bridge_names = {config.bridge_name(name) for name in networks}
    pods = lookup(configuration, ('pod',), {})
    containers = lookup(configuration, ('name',), {})
    # Pods and containers share native names and the pd-<name>-<id> interface namespace.
    if pods.keys() & containers.keys():
        raise ValidationError('Pod and container names must be distinct: ' + ', '.join(sorted(pods.keys() & containers.keys())))
    # Quadlet reserves <pod>-infra for the native namespace-holding container.
    infra_conflicts = {name + '-infra' for name in pods} & (pods.keys() | containers.keys())
    if infra_conflicts:
        raise ValidationError('Names conflict with pod infrastructure containers: ' + ', '.join(sorted(infra_conflicts)))

    owners = [('pod', name, section) for name, section in pods.items()]
    owners.extend(('name', name, section) for name, section in containers.items())
    for kind, name, container in owners:
        path = f'container {kind} {name}'
        # Pod members inherit all network-namespace settings from a configured pod.
        if 'pod' in container:
            # Resolve new references before a service is generated.
            if container['pod'] not in pods:
                raise ValidationError(f'{path}: pod {container["pod"]} is not configured')
            # Native members cannot override the pod's shared network settings.
            conflicts = {'network', 'port', 'allow-host-networking', 'host-name', 'name-server', 'disable-dns'} & container.keys()
            if conflicts:
                raise ValidationError(f'{path}: pod membership conflicts with {", ".join(sorted(conflicts))}; configure these on the pod')
        verify_options(container, path)

        # Only workload containers require an image; pods provide shared namespaces.
        if kind == 'name':
            require_fields(container, ('image',), path)
        # Host-networked containers cannot also attach bridges or publish ports.
        if 'allow-host-networking' in container and (lookup(container, ('network',), None) or lookup(container, ('port',), None)):
            raise ValidationError(f'{path}: allow-host-networking conflicts with network and port')
        # Publishing requires a network namespace connected to a bridge.
        if lookup(container, ('port',), None) and not lookup(container, ('network',), None):
            raise ValidationError(f'{path}: port publishing requires a network attachment')

        for variable, settings in lookup(container, ('environment',), {}).items():
            require_fields(settings, ('value',), f'{path} environment {variable}')

        for volume, settings in lookup(container, ('volume',), {}).items():
            location = f'{path} volume {volume}'
            require_fields(settings, ('source', 'destination'), location)
            owner = lookup(settings, ('owner',), None)
            # An owner node (especially recursive) must specify what ownership to change.
            if owner is not None and not ('user' in owner or 'group' in owner):
                raise ValidationError(f'{location} owner: specify user or group')

        attachment_ids = {}
        for network, settings in lookup(container, ('network',), {}).items():
            identifier = str(lookup(settings, ('id',), '0'))
            # Defaults participate in uniqueness checks just like explicitly configured IDs.
            if identifier in attachment_ids:
                other = attachment_ids[identifier]
                raise ValidationError(f'{path}: networks {other} and {network} use duplicate id {identifier}; assign unique IDs from 0 to 9')
            attachment_ids[identifier] = network

            # A bridge and a host veth share the Linux namespace (for example APP-0 and APP id 0).
            interface = config.veth_name(name, settings)
            if interface in bridge_names:
                raise ValidationError(f'{path} network {network}: interface {interface} conflicts with a configured container network bridge')

            # Dependencies protect deletion; verify also rejects references that never existed.
            if network not in networks:
                raise ValidationError(f'{path}: network {network} is not configured')
            subnets = networks[network]['subnet']
            families = set()
            for value in lookup(settings, ('address',), ()):
                address = ipaddress.ip_address(value)
                matches = [(ipaddress.ip_network(prefix), data) for prefix, data in subnets.items()
                           if address in ipaddress.ip_network(prefix)]
                # Podman accepts at most one explicitly selected address per family on a network.
                if address.version in families:
                    raise ValidationError(f'{path}: network {network} accepts one static address per family')
                families.add(address.version)
                # Static addresses must be allocatable on this network, not its gateway or broadcast.
                if not matches:
                    raise ValidationError(f'{path}: address {value} is outside network {network}')
                subnet, data = matches[0]
                gateway = ipaddress.ip_address(lookup(data, ('gateway',), str(subnet.network_address + 1)))
                if address in (subnet.network_address, gateway) or (
                        address.version == 4 and address == subnet.broadcast_address):
                    raise ValidationError(f'{path}: address {value} is reserved on network {network}')
                # Duplicate active static assignments cannot coexist on the same bridge.
                if 'disable' not in container:
                    key = (network, address)
                    if key in addresses:
                        raise ValidationError(f'{path}: address {value} is already assigned on network {network}')
                    addresses.add(key)

        for port, settings in lookup(container, ('port',), {}).items():
            location = f'{path} port {port}'
            require_fields(settings, ('protocol', 'source-port', 'destination-port'), location)
            address = ipaddress.ip_address(lookup(settings, ('source-address',), '0.0.0.0'))
            # Reject competing active host sockets before interrupting any containers.
            if 'disable' in container:
                continue
            for other_address, protocol, number in ports:
                if protocol == settings['protocol'] and number == int(settings['source-port']) and (
                        address == other_address or address.is_unspecified or other_address.is_unspecified):
                    raise ValidationError(f'{location}: published host port conflicts with another container')
            ports.append((address, settings['protocol'], int(settings['source-port'])))


def registry_text(configuration):
    # Disable prompts so unattended pulls try the explicitly ordered search list.
    registries = lookup(configuration, ('registry',), {})
    ordered = sorted(registries, key=lambda name: int(registries[name]['priority'])) or ['docker.io']
    return ('unqualified-search-registries = ' + json.dumps(ordered)
            + '\nshort-name-mode = "disabled"\n')


def image_id(reference):
    data = json.loads(cmd(['podman', 'image', 'inspect', reference]))
    if not data or not data[0].get('Id'):
        raise RouterError(f'Image {reference} is unavailable; use add container image first')
    return data[0]['Id']


def render_container(name, section, image):
    image_user = None
    if lookup(section, ('uid',), 'auto') == 'auto' and lookup(section, ('gid',), 'auto') != 'auto':
        metadata = json.loads(cmd(['podman', 'image', 'inspect', image]))
        image_user = metadata[0].get('Config', {}).get('User', '')
    return render('containers/container.container.j2', {
        'name': name, 'configuration': section, 'image': image, 'image_user': image_user})


def validate_units(prepared):
    """Check the exact generated bytes with Podman's native Quadlet generator."""
    if not any(prepared[key] for key in ('networks', 'pods', 'containers')):
        return
    with tempfile.TemporaryDirectory(dir=RUNTIME, prefix='check-') as folder:
        expected = []
        for name, text in prepared['networks'].items():
            unit = config.network_unit_name(name)
            write(Path(folder) / (unit + '.network'), text)
            expected.append(unit + '-network.service')
        for name, text in prepared['pods'].items():
            unit = config.pod_unit_name(name)
            write(Path(folder) / (unit + '.pod'), text)
            expected.append(unit + '.service')
        for name, settings in prepared['containers'].items():
            unit = config.unit_name(name)
            write(Path(folder) / (unit + '.container'), settings['text'])
            expected.append(unit + '.service')
        # Unchanged definitions remain available for native dependency resolution.
        output = cmd(['env', f'QUADLET_UNIT_DIRS={folder}:{QUADLETS}', GENERATOR, '--dryrun'])
        for unit in expected:
            if unit not in output:
                raise RouterError(f'Podman could not generate {unit}: {output.strip()}')


def volume_mounts(name, section, image=None):
    mounts = []
    accounts = None
    for volume, settings in sorted(lookup(section, ('volume',), {}).items()):
        source = Path(settings['source'])
        if not source.is_absolute():
            source = Path(config.VOLUME_ROOT) / source
        internal = source.is_relative_to(config.VOLUME_ROOT)
        mount = {'source': str(source), 'target': config.mount_path(name, volume), 'create': internal}
        owner = lookup(settings, ('owner',), {})
        for kind, key in (('user', 'uid'), ('group', 'gid')):
            value = lookup(owner, (kind,), None)
            if value is None:
                continue
            if value.isascii() and value.isdigit():
                mount[key] = int(value)
            else:
                if accounts is None:
                    accounts = json.loads(cmd(worker.worker_command('accounts', image)))
                if value not in accounts[kind]:
                    raise RouterError(f'Container {name} volume {volume}: {kind} {value!r} does not exist in image {image}')
                mount[key] = accounts[kind][value]
        mount['recursive'] = 'recursive' in owner
        if 'mode' in settings:
            mount['mode'] = int(settings['mode'], 8)
        mounts.append(mount)
    return mounts


def installed_files(previous, changed, images):
    """Snapshot exact installed definitions for compensation, without re-rendering."""
    snapshot = {'registry': REGISTRIES.read_text() if REGISTRIES.exists() else registry_text(previous),
                'networks': {}, 'pods': {}, 'containers': {}}
    for kind, suffix, naming, destination in (
            ('network', '.network', config.network_unit_name, 'networks'),
            ('pod', '.pod', config.pod_unit_name, 'pods'),
            ('name', '.container', config.unit_name, 'containers')):
        for name in changed[kind]:
            path = QUADLETS / (naming(name) + suffix)
            if not path.exists():
                continue
            value = path.read_text()
            if kind == 'name':
                environment = Path(config.environment_path(name))
                value = {'text': value,
                         'environment': environment.read_text() if environment.exists() else None,
                         'mounts': volume_mounts(name, lookup(previous, ('name', name), {}), lookup(images, (name,), None))}
            snapshot[destination][name] = value
    return snapshot


def fingerprint(*values):
    """Compare captured inputs without keeping another copy of their contents."""
    return sha256(json_text(values).encode()).hexdigest()


def generate(configuration, context):
    """Capture native inputs and prepare application and rollback before any changes."""
    recovery = context.recovery
    pending_path = STATE.with_suffix('.pending.json')
    # An unconfigured router needs neither Podman nor a host worker.
    if not configuration['container'] and not STATE.exists() and not pending_path.exists():
        return None

    previous = configuration['previous']
    changed = deepcopy(configuration['changed'])
    configuration = configuration['container']
    old = read_state()
    pending = pending_path.read_text() if pending_path.exists() else None
    if pending is not None and not recovery:
        raise RecoveryError('An interrupted container operation needs recovery. Restart configd before retrying.')

    images = {}
    environment = {}
    inputs = {}
    for name, section in lookup(configuration, ('name',), {}).items():
        if not config.enabled(section, configuration):
            continue
        if 'environment-file' in section:
            contents = filesystem.read_text(config.VOLUME_ROOT, section['environment-file'])
            # Environment files are textual input to Podman, never binary option data.
            if '\x00' in contents:
                raise RouterError('Environment file must not contain NUL bytes')
            environment[name] = contents
        inputs[name] = {'configuration': fingerprint(section), 'environment': fingerprint(environment.get(name))}
        previous_input = old['inputs'].get(name, {})
        if previous_input.get('environment') != inputs[name]['environment'] and name not in changed['name']:
            changed['name'].append(name)
        for device in lookup(section, ('device',), {}):
            # Device mappings must exist as real devices before working containers are stopped.
            metadata = Path(device).lstat()
            if not (stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode)):
                raise RouterError(f'Container device is not a character or block device: {device}')
        # Unchanged instances keep their image digest across unrelated commits and restarts.
        if inputs[name]['configuration'] == previous_input.get('configuration') and name in old['images']:
            images[name] = old['images'][name]
        else:
            try:
                images[name] = image_id(section['image'])
            except RouterError:
                if not recovery:
                    raise
                images[name] = section['image']

    forward = {'registry': registry_text(configuration), 'networks': {}, 'pods': {}, 'containers': {}}
    for name in changed['network']:
        if name in lookup(configuration, ('network',), {}):
            forward['networks'][name] = render('containers/network.network.j2', {
                'name': name, 'configuration': configuration['network'][name]})
    for name in changed['pod']:
        section = lookup(configuration, ('pod', name), None)
        if section is not None and 'disable' not in section:
            forward['pods'][name] = render('containers/pod.pod.j2', {'name': name, 'configuration': section})
    for name in changed['name']:
        section = lookup(configuration, ('name', name), None)
        if section is not None and config.enabled(section, configuration):
            try:
                forward['containers'][name] = {'text': render_container(name, section, images[name]),
                                              'environment': environment.get(name),
                                              'mounts': volume_mounts(name, section, images[name])}
            except RouterError as error:
                if not recovery:
                    raise
                context.report(f'Container unavailable: {name}: {error}')

    record = inventory(configuration)
    record.update(images=images, inputs=inputs)
    forward['inventory'] = json_text(record)
    if (not recovery and not any(changed.values()) and forward['inventory'] == json_text(old)
            and REGISTRIES.exists() and REGISTRIES.read_text() == forward['registry']):
        return None

    validate_units(forward)
    rollback = installed_files(previous, changed, old['images']) if not recovery else None
    if rollback is not None:
        rollback['inventory'] = json_text(old)

    # Configd owns the recovery target. Retain only native cleanup identities here.
    cleanup = inventory(previous)
    interrupted = json.loads(pending) if pending is not None else {}
    for kind in ('network', 'pod', 'name'):
        cleanup['objects'][kind] = sorted(set(cleanup['objects'][kind]) | set(record['objects'][kind]))
    cleanup['interfaces'] = {**old['interfaces'], **interrupted.get('interfaces', {}),
                             **cleanup['interfaces'], **record['interfaces']}

    return {'changed': changed, 'recovery': recovery, 'forward': forward, 'rollback': rollback,
            'expected': fingerprint(old, pending), 'cleanup': json_text(cleanup)}


def owned(kind, name):
    status, output = rc_cmd(['podman', kind, 'exists', name])
    if status == 1:
        return False
    if status:
        raise RouterError(output.strip() or f'Cannot inspect {kind} {name}')
    data = json.loads(cmd(['podman', kind, 'inspect', name]))
    item = data[0] if isinstance(data, list) else data
    if kind == 'network':
        labels = item.get('labels', {})
    elif kind == 'pod':
        labels = item.get('Labels', {})
    else:
        labels = item.get('Config', {}).get('Labels', {})
    if (labels or {}).get('nvyr.managed') != 'true':
        raise RouterError(f'{kind} {name} exists outside nVyR management')
    return True


def validate_pod_members(name, members):
    data = json.loads(cmd(['podman', 'pod', 'inspect', name]))
    pod = data[0] if isinstance(data, list) else data
    # An interrupted move can leave a known managed container in its former pod.
    for member in pod.get('Containers', []):
        if member['Id'] == pod.get('InfraContainerID'):
            continue
        if member['Name'] not in members or not owned('container', member['Name']):
            raise RouterError(f'Pod {name} contains unmanaged member {member["Name"]}')


def validate_ownership(previous, desired, changed):
    """Reject foreign Podman objects and occupied host names before stopping workloads."""
    owned_objects = set()
    for section, kind in (('network', 'network'), ('name', 'container'), ('pod', 'pod')):
        for name in changed[section]:
            # Removing prefixes must never allow adoption or removal of manually created objects.
            if owned(kind, name):
                owned_objects.add((kind, name))

    # A native name may already belong to the other kind outside this configuration.
    for section, other_section, other_kind in (('pod', 'name', 'container'), ('name', 'pod', 'pod')):
        for name in set(changed[section]) & set(desired['objects'].get(section, ())):
            if owned(other_kind, name) and name not in previous['objects'].get(other_section, ()):
                raise RouterError(f'{other_kind} {name} already uses the requested name')

    # Removing a pod also removes its members; never delete a manually joined workload.
    for name in changed['pod']:
        if ('pod', name) not in owned_objects:
            continue
        members = set(previous['objects'].get('name', ())) | set(desired['objects'].get('name', ()))
        validate_pod_members(name, members)

    native_kinds = {'network': 'network', 'pod': 'pod', 'name': 'container'}
    affected = {(native_kinds[kind], name)
                for kind, names in changed.items() for name in names}
    desired_interfaces = {name: owner for name, owner in desired['interfaces'].items() if tuple(owner) in affected}
    # No host interfaces are needed when all bridge networks and attachments are removed.
    if not desired_interfaces:
        return

    previous_interfaces = previous['interfaces']
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    for link in links:
        interface = link['ifname']
        # Existing interfaces outside the requested names are irrelevant to this transaction.
        if interface not in desired_interfaces:
            continue

        owner = tuple(previous_interfaces.get(interface, ()))
        # Only a previously managed and still owned object may retain or release this name.
        if owner not in owned_objects:
            raise RouterError(f'Container interface {interface} already exists outside nVyR container management')

        expected_kind = 'bridge' if owner[0] == 'network' else 'veth'
        # A different device kind indicates the name was reused outside Podman.
        if link.get('linkinfo', {}).get('info_kind') != expected_kind:
            raise RouterError(f'Container interface {interface} exists with an unexpected device type')


def configure_registry(text):
    REGISTRIES.parent.mkdir(parents=True, exist_ok=True)
    write(REGISTRIES, text)


def unmount(name):
    directory = Path(config.MOUNT_ROOT) / name.encode().hex()
    if directory.exists():
        for path in directory.iterdir():
            if os.path.ismount(path):
                cmd(['umount', str(path)])
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        directory.rmdir()


def remove_quadlets(changed, *, recovery=False):
    """Stop known units in systemd dependency order, then remove their definitions."""
    definitions = []
    units = []
    for kind, suffix, naming in (('name', '.container', config.unit_name),
                                 ('pod', '.pod', config.pod_unit_name),
                                 ('network', '.network', config.network_unit_name)):
        for name in changed[kind]:
            definitions.append(QUADLETS / (naming(name) + suffix))
            units.append(naming(name) + ('-network.service' if kind == 'network' else '.service'))

    if units:
        # Include exited network units and pending restarts, not just running processes.
        loaded = json.loads(cmd(['systemctl', 'list-units', '--all', '--output=json', *units]))
        if loaded:
            cmd(['systemctl', 'stop', *(unit['unit'] for unit in loaded)], timeout=180)
    for path in definitions:
        path.unlink(missing_ok=True)

    # Runtime Quadlets disappear across boot; remove any interrupted native objects.
    if recovery:
        for kind, native_kind in (('name', 'container'), ('pod', 'pod')):
            for name in changed[kind]:
                if owned(native_kind, name):
                    cmd(['podman', native_kind, 'rm', '--force', name], timeout=45)
    for name in changed['name']:
        unmount(name)
        Path(config.environment_path(name)).unlink(missing_ok=True)


def prepare(name, prepared):
    """Install a generated unit and its captured environment and volume bindings."""
    if prepared['environment'] is not None:
        path = Path(config.environment_path(name))
        filesystem.protected_directory(path.parent)
        write(path, prepared['environment'])
    for mount in prepared['mounts']:
        filesystem.bind_path('/', mount['source'].lstrip('/'), mount['target'],
                             create=mount['create'], uid=lookup(mount, ('uid',), -1), gid=lookup(mount, ('gid',), -1),
                             mode=lookup(mount, ('mode',), None), recursive=mount['recursive'])
    write(QUADLETS / (config.unit_name(name) + '.container'), prepared['text'])


def execute_change(prepared, changed, *, recovery=False, report=print):
    """Install definitions and let systemd resolve their native dependencies."""
    configure_registry(prepared['registry'])
    remove_quadlets(changed, recovery=recovery)
    # Quadlet does not modify an existing network's parameters, or remove it by default.
    for name in changed['network']:
        if owned('network', name):
            cmd(['podman', 'network', 'rm', name])

    QUADLETS.mkdir(parents=True, exist_ok=True, mode=0o700)
    units = []
    for name, text in prepared['networks'].items():
        unit = config.network_unit_name(name)
        write(QUADLETS / (unit + '.network'), text)
        units.append(unit + '-network.service')
    for name, text in prepared['pods'].items():
        unit = config.pod_unit_name(name)
        write(QUADLETS / (unit + '.pod'), text)
        units.append(unit + '.service')
    for name, settings in prepared['containers'].items():
        try:
            prepare(name, settings)
            units.append(config.unit_name(name) + '.service')
        except (OSError, RouterError) as error:
            if not recovery:
                raise
            report(f'Container unavailable: {name}: {error}')
    cmd(['systemctl', 'daemon-reload'])
    if units:
        rc_cmd(['systemctl', 'reset-failed', *units])
        try:
            cmd(['systemctl', 'start', *units], timeout=180)
        except RouterError as error:
            if not recovery:
                raise
            report(f'Container unavailable: {error}')


def check_mount_sources(prepared):
    """Check existing host sources before stopping any workload, in the host namespace."""
    for settings in prepared['containers'].values():
        for mount in settings['mounts']:
            try:
                descriptor = filesystem.open_source('/', mount['source'].lstrip('/'))
            except FileNotFoundError:
                if mount['create']:
                    continue
                raise RouterError(f'Container bind source does not exist: {mount["source"]}') from None
            os.close(descriptor)


def apply(generated, context=None, *, report=print):
    """Apply prepared files, or transport them to the host when called by configd.

    The worker calls this stage without a CommitContext, under its operation lock.
    Only execution crosses that boundary; generation always runs once in configd.
    """
    if generated is None:
        return
    if context is not None:
        return worker.run_apply(generated, recovery=context.recovery, report=context.report)

    pending_path = STATE.with_suffix('.pending.json')
    pending = pending_path.read_text() if pending_path.exists() else None
    previous = read_state()
    # Another worker may have applied between generation and application.
    if fingerprint(previous, pending) != generated['expected']:
        raise RouterError('Container state changed after generation; retry the commit')
    if pending is not None:
        interrupted = json.loads(pending)
        previous['interfaces'].update(interrupted.get('interfaces', {}))
        for kind, names in interrupted.get('objects', {}).items():
            previous['objects'][kind] = sorted(set(previous['objects'].get(kind, ())) | set(names))
    validate_ownership(previous, json.loads(generated['forward']['inventory']), generated['changed'])
    recovery = generated['recovery']
    if not recovery:
        check_mount_sources(generated['forward'])
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write(pending_path, generated['cleanup'])

    try:
        execute_change(generated['forward'], generated['changed'], recovery=recovery, report=report)
        write(STATE, generated['forward']['inventory'])
        pending_path.unlink()
    except Exception as error:
        if recovery:
            raise RouterError(f'Container recovery incomplete: {error}') from error
        try:
            execute_change(generated['rollback'], generated['changed'], report=report)
            write(STATE, generated['rollback']['inventory'])
            pending_path.unlink(missing_ok=True)
        except Exception as rollback:
            raise RecoveryError(f'Container apply failed: {error}; rollback failed: {rollback}') from error
        raise RouterError(f'Container apply failed; previous configuration restored: {error}') from error
