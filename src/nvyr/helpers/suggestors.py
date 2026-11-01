"""Reusable completion suggestors; no command history or validation lives here."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from inspect import signature
import json
from datetime import datetime, timezone

from nvyr.lexer import lex
from nvyr.helpers.process import cmd
from nvyr.tree import MISSING, lookup

REGISTRY = {}


@dataclass(frozen=True)
class Suggestion:
    value: str
    description: str = "Suggested value"


@dataclass(frozen=True)
class Context:
    store: object = None
    commit_id: int = 0
    configuration: object = None


def configuration_section(context, path):
    """Read an optional section from a tree or a lazy completion projection."""
    configuration = context.configuration
    value = configuration(path) if callable(configuration) else lookup(configuration, path)
    # Missing projections use a truthy sentinel, so `value or {}` cannot handle them.
    return {} if value is MISSING else value


def register(name):
    def decorate(function):
        REGISTRY[name] = function
        return function

    return decorate


@register('geoip-countries')
def geoip_countries(context):
    from nvyr.helpers.geoip_config import COUNTRIES

    return [Suggestion(country, 'DB-IP country code ' + country) for country in sorted(COUNTRIES)]


@register('cpu-policy')
def cpu_policy(context, setting):
    from nvyr.helpers import cpu_settings

    descriptions = cpu_settings.GOVERNORS if setting == 'governor' else cpu_settings.PREFERENCES
    return [Suggestion(value, descriptions[value]) for value in cpu_settings.available(setting)]


@register('time-zones')
def time_zones(context):
    from nvyr.helpers import timezones

    return [Suggestion(name, 'Coordinated Universal Time' if name == 'UTC' else 'IANA time zone')
            for name in timezones.available()]


@register("interfaces")
def interfaces(context, prefix=""):
    from nvyr.helpers.interfaces import instances, visible_link

    devices = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    names = {device['ifname'] for device in devices}
    aliases = {device['ifname']: device.get('ifalias') or '' for device in devices}

    # Share native metadata filtering with the interface operational display.
    excluded = {
        device['ifname'] for device in devices
        if not visible_link(device)
    }

    configuration = context.configuration
    if callable(configuration):
        profiles = configuration(('interfaces',))
    else:
        profiles = lookup(configuration or {}, ('interfaces',), {})

    if isinstance(profiles, Mapping):
        for definitions in profiles.values():
            names.update(name for name, _ in instances(definitions))

    return [Suggestion(name, aliases.get(name, '')) for name in sorted(names - excluded) if name.startswith(prefix)]


@register('container-capabilities')
def container_capabilities(context):
    from nvyr.helpers.validators import CONTAINER_CAPABILITIES

    return [
        Suggestion(name, description)
        for name, description in sorted(CONTAINER_CAPABILITIES.items())
    ]


@register('container-images')
def container_images(context):
    import json

    from nvyr.errors import RouterError
    from nvyr.helpers.containers import worker_command
    from nvyr.helpers.process import cmd

    try:
        images = json.loads(cmd(worker_command('images'), timeout=5))
    except (OSError, RouterError, ValueError):
        return []

    names = set()
    for image in images:
        for name in image.get('Names') or ():
            if '<none>' not in name:
                names.add(name)
    return [Suggestion(name, '') for name in sorted(names)]


@register('installed-packages')
def installed_packages(context):
    """Use the same package identifiers and summaries as the operational table."""
    from nvyr.errors import RouterError
    from nvyr.helpers.packages import inventory

    try:
        records = inventory()
    except (OSError, RouterError):
        return []

    return [Suggestion(record['package'], record['description']) for record in records]


@register('config-path')
def config_path(context, path):
    """Suggest configured names at an absolute path in this completion's view."""
    parts = tuple(token.value for token in lex(path))
    configuration = context.configuration
    value = (configuration(parts) if callable(configuration) else
             lookup(configuration, parts))

    if not isinstance(value, Mapping):
        return []

    return [Suggestion(name, '') for name in value]


@register('container-instances')
def container_instances(context):
    """Service selectors accept both workload containers and shared pods."""
    values = []
    for path, description in (('container name', 'Container'), ('container pod', 'Pod')):
        values.extend(Suggestion(item.value, description) for item in config_path(context, path))
    return sorted(values, key=lambda item: item.value)


@register('dhcp-pools')
def dhcp_pools(context, family=4):
    """Include shared-network names from default and named routing instances."""
    service = 'dhcp-server' if family == 4 else 'dhcpv6-server'
    names = set(configuration_section(context, ('service', service, 'shared-network')))
    for scope in configuration_section(context, ('vrf', 'name')).values():
        names.update(scope.get('service', {}).get(service, {}).get('shared-network', {}))
    return [Suggestion(name, '') for name in sorted(names)]


@register('policy-community-lists')
def policy_community_lists(context, large=False):
    """Standard and expanded lists share one native name namespace."""
    kind = 'large-community-list' if large else 'community-list'
    names = {}
    for mode in ('standard', 'expanded'):
        for suggestion in config_path(context, f'policy {kind} {mode}'):
            names[suggestion.value] = Suggestion(suggestion.value, f'{mode.capitalize()} {kind}')
    return [names[name] for name in sorted(names)]


def bgp_names(context, kind):
    """Suggest configured peers across instances, identifying their VRF ownership."""
    protocols = configuration_section(context, ('protocols',))
    vrfs = configuration_section(context, ('vrf', 'name'))

    instances = {'default': protocols.get('bgp', {})}
    for vrf, values in vrfs.items():
        instances[vrf] = lookup(values, ('protocols', 'bgp'), {})

    owners = {}
    for vrf, instance in instances.items():
        for name in instance.get(kind, {}):
            owners.setdefault(name, []).append(vrf)
    return [Suggestion(name, 'VRF: ' + ', '.join(sorted(vrfs))) for name, vrfs in sorted(owners.items())]


@register('bgp-peers')
def bgp_peers(context):
    return bgp_names(context, 'neighbor')


@register('bgp-peer-groups')
def bgp_peer_groups(context):
    return bgp_names(context, 'peer-group')


@register('dynamic-firewall-groups')
def dynamic_firewall_groups(context, kind, family):
    """Only installed configuration can identify a runtime cleanup target."""
    path = ('firewall', 'group', kind, family)
    configuration = context.configuration
    groups = configuration(path) if callable(configuration) else lookup(configuration, path, {})
    if not isinstance(groups, Mapping):
        return []

    return [Suggestion(name, '') for name, definition in groups.items() if 'dynamic' in definition]


@register('installed-images')
def installed_images(context):
    from nvyr.helpers.images import Images
    from nvyr.errors import RouterError

    try:
        catalog = Images().catalog()
        return [Suggestion(entry['name'], '') for entry in catalog['images'].values()]
    except (OSError, RouterError):
        return []


@register('image-files')
def image_files(context):
    from pathlib import Path

    try:
        return [Suggestion(path.name, '') for path in Path('/config/nvyr-images').glob('*.iso') if path.is_file()]
    except OSError:
        return []


@register("commit-history")
def commit_history(context):
    if context.store is None:
        return []

    # The CLI syntax is an offset, not an absolute commit ID. Use the existing files
    # as the only index, including retention gaps; do not fabricate a numeric range.
    return [Suggestion(str(context.commit_id - record["id"]),
                       datetime.fromtimestamp(record["timestamp"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
            for record in context.store.history_metadata(context.commit_id)]


@dataclass(frozen=True)
class BoundSuggestor:
    """Supply request-local configuration without mutating shared callbacks."""

    function: object
    context: object

    @property
    def __signature__(self):
        parameters = list(signature(self.function).parameters.values())[1:]
        return signature(self.function).replace(parameters=parameters)

    def __call__(self, **arguments):
        return self.function(self.context(), **arguments)

    def suggest(self, configuration, **arguments):
        context = replace(self.context(), configuration=configuration)
        return self.function(context, **arguments)


def registry(context=None):
    """Bind context once and expose only schema-supplied arguments to callers."""
    context = context or Context
    return {name: BoundSuggestor(function, context) for name, function in REGISTRY.items()}
