"""Shared rendering for trusted service templates and atomic configuration writes.

Render in generate(); install the resulting text in apply(). Templates and helpers
are trusted application code, not user-supplied configuration expressions.
Nftables helpers translate configuration already checked by the schema and verify().
"""

import ipaddress
import os
from pathlib import Path
import tempfile
from threading import RLock

from jinja2 import Environment, FileSystemLoader, PackageLoader, StrictUndefined, TemplateError

from nvyr.errors import RouterError
from nvyr.helpers import nftables_formatters as nft
from nvyr.helpers import nftables_helpers
from nvyr.helpers import nftables_zones as zones
from nvyr.helpers import nftables_source_validation as source_validation
from nvyr.helpers.vrf_conntrack import map_elements as vrf_conntrack_elements
from nvyr.helpers import container_formatters, container_config
from nvyr.helpers import logging_formatters
from nvyr.helpers.validators import container_memory_bytes
from nvyr.helpers import policy_formatters
from nvyr.helpers import bgp_formatters, bgp_parameters, bgp_peer
from nvyr.helpers import frr_static
from nvyr.render import json_text
from nvyr.storage import sync_directory


class RenderingError(RouterError):
    code = 'template'


class TemplateRenderer:
    """An isolated renderer, optionally loading from a service's template directory."""

    def __init__(self, searchpath=None):
        self._loader = (PackageLoader('nvyr', 'templates') if searchpath is None
                        else FileSystemLoader(searchpath))
        self._functions = {'json_text': json_text,
                           'logging_severity': logging_formatters.severity,
                           'logging_program_condition': logging_formatters.program_condition,
                           'logging_services': logging_formatters.SERVICES,
                           'logging_root': logging_formatters.ROOT,
                           'container_attachment': container_formatters.attachment,
                           'container_network_gateway': container_formatters.network_gateway,
                           'container_network_ipv6': container_formatters.network_ipv6,
                           'container_bridge_name': container_config.bridge_name,
                           'container_published_port': container_formatters.published_port,
                           'container_capabilities': container_formatters.capabilities,
                           'container_image_user': container_formatters.image_user,
                           'container_entrypoint': container_formatters.entrypoint,
                           'container_arguments': container_formatters.arguments,
                           'container_tmpfs_options': container_formatters.tmpfs_options,
                           'container_quoted': container_formatters.quoted,
                           'container_memory_bytes': container_memory_bytes,
                           'container_unit_name': container_config.unit_name,
                           'container_pod_unit_name': container_config.pod_unit_name,
                           'container_mount_path': container_config.mount_path,
                           'container_environment_path': container_config.environment_path,
                           'frr_static_prefix': frr_static.route_prefix,
                           'frr_static_path': frr_static.route_path,
                           'policy_community_values': policy_formatters.community_values,
                           'policy_filter_operand': policy_formatters.filter_operand,
                           'policy_matches': policy_formatters.matches,
                           'policy_actions': policy_formatters.actions,
                           'bgp_parameter_commands': bgp_parameters.commands,
                           'bgp_enabled': bgp_parameters.enabled,
                           'bgp_families': bgp_parameters.families,
                           'bgp_dampening_command': bgp_parameters.dampening_command,
                           'bgp_peer_name': bgp_peer.name,
                           'bgp_peer_address': bgp_peer.address,
                           'bgp_timer_pair': bgp_formatters.timer_pair,
                           'bgp_peer_timer_defaults': bgp_formatters.peer_timer_defaults,
                           'bgp_peer_commands': bgp_formatters.peer_commands,
                           'bgp_peer_family_commands': bgp_formatters.peer_family_commands,
                           'bgp_family_commands': bgp_formatters.family_commands,
                           'ip_address': ipaddress.ip_address,
                           'ip_network': ipaddress.ip_network,
                           'nft_cleanup': nft.nft_cleanup,
                           'nft_chain_declarations': nft.nft_chain_declarations,
                           'nft_limit_sets': nft.nft_limit_sets,
                           'nft_named_state': nft.nft_named_state,
                           'nft_helper_objects': nftables_helpers.render_objects,
                           'nft_helper_assignment': nftables_helpers.assignment,
                           'nft_singleton_name': nft.nft_singleton_name,
                           'nft_rule': nft.nft_rule, 'nft_comment': nft.nft_comment,
                           'nft_nat_rule': nft.nft_nat_rule,
                           'nft_nat_dispatch': nft.nft_nat_dispatch,
                           'nft_family_dispatch': nft.nft_family_dispatch,
                             'nft_hook_declaration': nft.nft_hook_declaration,
                           'nft_filter_hooks': nft.NFT_FILTER_HOOKS,
                           'nft_active_hooks': nft.nft_active_hooks,
                           'nft_hook_families': nft.nft_hook_families,
                           'nft_zone_maps': zones.render_maps,
                           'nft_source_validation_sets': source_validation.render_sets,
                           'nft_source_validation_rules': source_validation.render_rules,
                           'vrf_conntrack_elements': vrf_conntrack_elements,
                           'nft_zone_dispatch': zones.dispatch,
                           'nft_chain_body': nft.nft_chain_body,
                           'nft_map': nft.nft_map, 'nft_map_name': nft.nft_map_name,
                           'singleton_groups': nft.singleton_groups,
                           'nft_singleton_group': nft.nft_singleton_group,
                           'nft_match_group': nft.nft_match_group,
                           'nft_match_group_name': nft.nft_match_group_name,
                           'nft_icmp_group': nft.nft_icmp_group,
                           'nft_icmp_group_name': nft.nft_icmp_group_name,
                           'nft_state_policy': nft.nft_state_policy,
                           'nft_default_rule': nft.nft_default_rule,
                           'nft_named_chain': nft.nft_named_chain,
                           'nft_flowtable_name': nft.nft_flowtable_name,
                           'nft_flowtable': nft.nft_flowtable,
                           'numeric_items': lambda values: sorted(values.items(), key=lambda item: (int(item[0]), item[0]))}
        self._lock = RLock()
        self._environment = self._make_environment()

    def _make_environment(self):
        environment = Environment(loader=self._loader, undefined=StrictUndefined,
                                  autoescape=False, keep_trailing_newline=True)
        environment.globals.update(self._functions)

        return environment

    def register(self, name, function=None):
        """Register a callable directly or as @renderer.register('name')."""
        if not isinstance(name, str) or not name.isidentifier():
            raise ValueError('Template function name must be a Python identifier')

        def install(callback):
            if not callable(callback):
                raise TypeError('Template function must be callable')

            with self._lock:
                if name in self._environment.globals:
                    raise ValueError(f'Template function already registered: {name}')

                self._functions[name] = callback

                # Never mutate an environment after templates have been loaded.
                self._environment = self._make_environment()

            return callback

        return install if function is None else install(function)

    def render(self, name, variables=None):
        """Render a named UTF-8 template. Context is local to this render."""
        with self._lock:
            environment = self._environment

        try:
            return environment.get_template(name).render(variables or {})
        except TemplateError as error:
            raise RenderingError(f'Cannot render template {name!r}: {error}') from error

    def render_to_file(self, name, path, variables=None, *, mode=0o600):
        """Finish rendering before touching the destination; then replace atomically."""
        write(path, self.render(name, variables), mode=mode)


def write(path, text, *, mode=0o600):
    """Install UTF-8 text atomically, preserving an existing file's uid/gid on Unix.

    Parent directories must already exist. New files belong to the caller; mode
    is explicit even when replacing a file. Service scripts manage new ownership.
    """
    path = Path(path)
    temporary = None

    try:
        previous = path.stat() if path.exists() else None
        descriptor, temporary = tempfile.mkstemp(prefix='.nvyr-', dir=path.parent)

        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()

            if previous is not None and hasattr(os, 'fchown'):
                os.fchown(stream.fileno(), previous.st_uid, previous.st_gid)

            os.chmod(temporary, mode)
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        sync_directory(path.parent)
    except OSError as error:
        raise RenderingError(f'Cannot write configuration {str(path)!r}: {error}') from error
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


# Configuration scripts share these helpers; isolated renderers use the same pipeline.
_default = TemplateRenderer()
register = _default.register
render = _default.render
render_to_file = _default.render_to_file
