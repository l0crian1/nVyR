"""Interface IP policy shared by validation, netlinkd and kernel settings.

Configuration stores only explicit overrides. The daemon combines them with
the current global policy each time a link is created or reconciled.
"""

from collections.abc import Mapping
from contextlib import contextmanager
import errno
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import secrets

from nvyr.errors import RecoveryError, ValidationError
from nvyr.helpers.kernel_settings import Manager, validate_value
from nvyr.helpers.kernel_settings_map import INTERFACE_SETTINGS, SETTINGS
from nvyr.helpers.validators import interface_ipv6_value
from nvyr.storage import atomic_json
from nvyr.tree import lookup


SPECIAL = {'eui64', 'interface-identifier', 'link-local-address', 'no-default-link-local'}
KINDS = {'ethernet', 'dummy', 'virtual-ethernet', 'bridge', 'vlan'}


def verify(options, *, addresses=(), kind=None):
    """Validate dependent settings independently of the CLI transport."""
    # The daemon accepts the same structured options as configuration scripts.
    if not isinstance(options, Mapping) or set(options) - {'ip', 'ipv6'}:
        raise ValidationError('Invalid interface IP options')

    # Loopback and VRF devices do not have the Ethernet-like address contract.
    if options and kind is not None and kind not in KINDS:
        raise ValidationError(f'{kind}: IP options are not supported')

    for family, values in options.items():
        # Unknown keys must not silently disappear on a direct daemon request.
        if not isinstance(values, Mapping):
            raise ValidationError(f'{family}: expected an options node')
        allowed = {path[1] for path in INTERFACE_SETTINGS if path[0] == family}
        if family == 'ipv6':
            allowed |= SPECIAL
        if set(values) - allowed:
            raise ValidationError(f'{family}: unknown IP option')

    for path, name in INTERFACE_SETTINGS.items():
        value = lookup(options, path, None)
        if value is None:
            continue
        spec = SETTINGS[name]
        if spec['kind'] == 'presence':
            # Valueless leaves use a Boolean, never an arbitrary truthy value.
            if value is not True:
                raise ValidationError(f'{" ".join(path)}: expected a valueless option')
        elif not validate_value(spec, value):
            # Native bounds also apply to programmatic configuration clients.
            raise ValidationError(f'{" ".join(path)}: invalid value {value!r}')

    ipv6 = options.get('ipv6', {})
    # Linux rejects SLAAC tokens on dummy devices, which have no multicast link.
    if kind == 'dummy' and 'interface-identifier' in ipv6:
        raise ValidationError('dummy: IPv6 interface-identifier requires a multicast-capable interface')

    dad = ipv6.get('duplicate-address-detection', {})
    # DAD is a node with two specific children, never an arbitrary dictionary.
    if not isinstance(dad, Mapping) or set(dad) - {'disable', 'probes'}:
        raise ValidationError('ipv6 duplicate-address-detection: invalid options')

    # Probe counts have no effect when duplicate detection is disabled.
    if 'disable' in dad and 'probes' in dad:
        raise ValidationError('ipv6 duplicate-address-detection: disable conflicts with probes')

    for name in SPECIAL & ipv6.keys():
        value = ipv6[name]
        if name == 'no-default-link-local':
            # Presence switches may not carry a value through the daemon API.
            if value is not True:
                raise ValidationError(f'ipv6 {name}: expected a valueless option')
            continue
        values = value if name == 'eui64' else [value]
        # EUI-64 is multi, while token and explicit link-local values are singletons.
        if not isinstance(values, (list, tuple)) or not values:
            raise ValidationError(f'ipv6 {name}: expected an address value')

        # Each value must match its specific prefix, token or link-local grammar.
        if any(not isinstance(item, str) or not interface_ipv6_value(item, name) for item in values):
            raise ValidationError(f'ipv6 {name}: invalid address or prefix')

    # Disabling IPv6 must not silently discard configured IPv6 policy or addresses.
    if 'disable' in ipv6 and (set(ipv6) != {'disable'} or any(ipaddress.ip_interface(a).version == 6 for a in addresses)):
        raise ValidationError('ipv6 disable conflicts with IPv6 addresses and options')

    # These controls only make sense when router advertisements are accepted.
    accepts_ra = 'autoconf' in ipv6 or 'accept-router-advertisements' in ipv6
    if not accepts_ra and {'no-default-route', 'no-ra-mtu'} & ipv6.keys():
        raise ValidationError('IPv6 RA options require autoconf or accept-router-advertisements')

    # Tokens and privacy addresses both need an autonomous advertised prefix.
    if 'autoconf' not in ipv6 and {'interface-identifier', 'temporary-addresses'} & ipv6.keys():
        raise ValidationError('IPv6 interface-identifier and temporary-addresses require autoconf')

    # Stable privacy and a fixed token select different SLAAC address algorithms.
    stable = ipv6.get('address-generation') == 'stable-privacy'
    if stable and 'interface-identifier' in ipv6:
        raise ValidationError('IPv6 stable-privacy conflicts with interface-identifier')

    # Linux mode 1 suppresses link-local generation but uses EUI-64 for SLAAC.
    if stable and {'no-default-link-local', 'link-local-address'} & ipv6.keys():
        raise ValidationError('IPv6 stable-privacy requires automatic link-local generation')


def format_options(options):
    """Copy verified IP options without retaining references to configuration views."""
    result = {family: dict(values) for family, values in options.items()}
    ipv6 = result.get('ipv6', {})
    if 'duplicate-address-detection' in ipv6:
        ipv6['duplicate-address-detection'] = dict(ipv6['duplicate-address-detection'])
    if 'eui64' in ipv6:
        ipv6['eui64'] = list(dict.fromkeys(ipv6['eui64']))

    return result


def normalize(options, *, addresses=(), kind=None):
    """Validate untrusted daemon input before formatting it."""
    verify(options, addresses=addresses, kind=kind)
    return format_options(options)


def overrides(options):
    """Return registered explicit values, including inverted presence switches."""
    result = {}
    for path, name in INTERFACE_SETTINGS.items():
        value = lookup(options, path, None)
        if value is not None:
            result[name] = True if SETTINGS[name]['kind'] == 'presence' else value
    if 'autoconf' in options.get('ipv6', {}):
        result['interface ipv6 accept-router-advertisements'] = True
    return result


def effective(options, globals):
    values = {name: globals.get(name, SETTINGS[name]['default']) for name in INTERFACE_SETTINGS.values()}
    return values | overrides(options)


def eui64(prefix, mac):
    """Derive a modified EUI-64 host identifier, retaining the supplied /64."""
    octets = bytearray.fromhex(mac.replace(':', ''))
    octets[0] ^= 2
    identifier = int.from_bytes(octets[:3] + b'\xff\xfe' + octets[3:], 'big')
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Network(prefix).network_address) | identifier)) + '/64'


def addresses(options, mac):
    ipv6 = options.get('ipv6', {})
    result = [eui64(prefix, mac) for prefix in ipv6.get('eui64', ())]
    if 'link-local-address' in ipv6:
        result.append(ipv6['link-local-address'] + '/64')
    return result


class Controller:
    """Netlinkd's per-device writer; global changes use the same serialized owner."""

    def __init__(self, settings=None, secret='/config/ipv6-stable-secret.json',
                 profile='/run/sysctl.d/95-nvyr-interfaces.conf'):
        self.settings = settings or Manager()
        self.secret = Path(secret)
        self.profile = Path(profile)

    @contextmanager
    def profile_transaction(self, owners, globals):
        """Publish overrides before link creation so late udev sysctl cannot undo them."""
        from nvyr.helpers.template import write

        lines = ['# Managed by nvyr-netlinkd; explicit device policy follows global defaults.']
        for links in owners.values():
            for name, spec in sorted(links.items()):
                if spec['kind'] not in KINDS:
                    continue
                values = effective(spec.get('ip-options', {}), globals)
                # Only settings also written by boot/global profiles need exact exceptions.
                values = {key: value for key, value in values.items()
                          if SETTINGS[key]['owner'] == 'firewall'
                          or key in ('interface ip disable-forwarding', 'interface ipv6 accept-router-advertisements')}
                for key, value in self.settings.resolve(values).items():
                    path = self.settings.path(key, interface=name).relative_to(self.settings.root)
                    lines.append(f'{path.as_posix()} = {value}')
        text = '\n'.join(lines) + '\n'
        previous = self.profile.read_text() if self.profile.exists() else None
        changed = text != previous
        if changed:
            self.profile.parent.mkdir(parents=True, exist_ok=True)
            write(self.profile, text, mode=0o644)
        try:
            yield
        except Exception as error:
            try:
                if changed:
                    if previous is None:
                        self.profile.unlink(missing_ok=True)
                    else:
                        write(self.profile, previous, mode=0o644)
            except Exception as restore_error:
                raise RecoveryError(f'Could not restore interface kernel profile: {restore_error}') from error
            raise

    def stable_secret(self, name):
        if not self.secret.exists():
            atomic_json(self.secret, {'secret': secrets.token_hex(32)})
        key = bytes.fromhex(json.loads(self.secret.read_text())['secret'])
        digest = hmac.new(key, name.encode(), hashlib.sha256).digest()[:16]
        return str(ipaddress.IPv6Address(digest))

    def apply(self, kernel, name, options, globals):
        """Set address behavior before IPv6 activation or static address installation."""
        settings = self.settings
        values = settings.resolve(effective(options, globals))
        ipv6 = options.get('ipv6', {})
        accepts_ra = values['interface ipv6 accept-router-advertisements'] == '2'
        ra = settings.path('interface ipv6 accept-router-advertisements', interface=name)
        default_route = settings.path('interface ipv6 no-default-route', interface=name)
        remove_ra = not accepts_ra and ra.read_text().strip() == '2'
        remove_default = ('no-default-route' in ipv6 and default_route.read_text().strip() != '0')
        # Linux permits clearing a token only while router advertisements are enabled.
        if remove_ra:
            kernel.ipv6_token(name, '::')

        suppress_local = 'no-default-link-local' in ipv6 or 'link-local-address' in ipv6
        mode_key = 'interface ipv6 address-generation'
        if suppress_local:
            values[mode_key] = '1'

        mode = settings.path(mode_key, interface=name)
        disable = settings.path('interface ipv6 disable', interface=name)
        mode_changed = mode.read_text().strip() != values[mode_key]
        # Changing the generation algorithm must retire addresses from the old one.
        if mode_changed and disable.read_text().strip() != '1':
            settings._write(disable, '1')
            kernel.refresh_addresses()

        if ipv6.get('address-generation') == 'stable-privacy':
            path = mode.with_name('stable_secret')
            secret = self.stable_secret(name)
            try:
                previous = path.read_text().strip()
            except OSError as error:
                if error.errno != errno.EIO:  # Linux reports EIO for an unset secret.
                    raise
                previous = None
            if previous != secret:
                settings._write(path, secret)

        # Disable is written last so a newly enabled link sees all address settings.
        enabled = values.pop('interface ipv6 disable')
        for key, value in values.items():
            if (key == 'interface ipv6 hop-limit' and 'hop-limit' not in ipv6
                    and ('autoconf' in ipv6 or 'accept-router-advertisements' in ipv6)):
                continue  # Preserve hop limits learned from router advertisements.
            path = settings.path(key, interface=name)
            if path.read_text().strip() != value:
                settings._write(path, value)
        if disable.read_text().strip() != enabled:
            settings._write(disable, enabled)
            kernel.refresh_addresses()

        if enabled == '0' and accepts_ra:
            kernel.ipv6_token(name, ipv6.get('interface-identifier', '::'))
        if remove_ra or remove_default:
            kernel.ipv6_ra_routes(name, default_only=not remove_ra)
