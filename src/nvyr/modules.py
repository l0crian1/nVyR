"""Commit context and explicit configuration script registry."""

from dataclasses import dataclass, field
from collections.abc import Callable
from nvyr.errors import Warning
from nvyr.tree import MISSING, ReadOnlyTree, changes, deleted, lookup
from nvyr.helpers.dependencies import Dependencies


@dataclass(frozen=True)
class CommitContext:
    """Read-only configuration views and lifecycle metadata for one script owner.

    Effective trees include defaults; previous is the explicit before-image.
    Sections restrict change inspection to this owner's projections, while the
    full trees remain available for cross-feature validation. Script registrations
    aggregate all configured declaring paths, including their bound tag values.
    """
    effective: ReadOnlyTree
    previous: ReadOnlyTree
    owner: str
    root: tuple
    recovery: bool = False
    report: Callable[[str | Warning], None] = print
    previous_effective: ReadOnlyTree = field(kw_only=True)
    state_directory: object = None
    check_only: bool = field(default=False, kw_only=True)
    # Recovery also covers live rollback; startup alone precedes interface replay.
    startup: bool = field(default=False, kw_only=True)
    scripts: ReadOnlyTree = field(default_factory=lambda: ReadOnlyTree({}), kw_only=True)
    previous_scripts: ReadOnlyTree = field(default_factory=lambda: ReadOnlyTree({}), kw_only=True)
    sections: ReadOnlyTree | None = field(default=None, kw_only=True, repr=False)
    previous_sections: ReadOnlyTree | None = field(default=None, kw_only=True, repr=False)

    dependencies: Dependencies | None = field(default=None, kw_only=True, repr=False)
    reapply_paths: frozenset = field(default_factory=frozenset, kw_only=True)
    _changed_cache: dict = field(default_factory=dict, init=False, repr=False, compare=False)

    def get_changed(self, path=None):
        """Read-only effective changes owned by this script, optionally scoped.

        Absolute paths map to previous/effective values. MISSING identifies an
        added or removed value; whole added/deleted subtrees appear once.
        Results are computed lazily and cached per requested scope.
        """
        scope = None if path is None else tuple(path)
        if scope in self._changed_cache:
            return self._changed_cache[scope]

        if self.sections is None:
            before = {self.root: lookup(self.previous_effective, self.root)}
            after = {self.root: lookup(self.effective, self.root)}
        else:
            before, after = self.previous_sections, self.sections

        result = {}
        for root in sorted(before.keys() | after.keys()):
            old, new = before.get(root, MISSING), after.get(root, MISSING)
            location = root
            if scope is not None:
                if scope[:len(root)] == root:
                    suffix = scope[len(root):]
                    old, new = lookup(old, suffix), lookup(new, suffix)
                    location = scope
                elif root[:len(scope)] != scope:
                    continue

            for location, old_value, new_value in changes(old, new, location):
                result[location] = {'previous': old_value, 'effective': new_value}

        self._changed_cache[scope] = ReadOnlyTree(result)
        return self._changed_cache[scope]

    def get_deleted(self):
        """Return effective removals under this owner, keyed by absolute paths.

        Whole removed subtrees appear once; multi-leaves contain only removed
        values. Scalar replacements are not deletions. Calculated only on call.
        """
        if self.sections is None:
            return deleted(lookup(self.previous_effective, self.root),
                           lookup(self.effective, self.root), self.root)

        result = {}
        for path, before in self.previous_sections.items():
            result.update(deleted(before, self.sections.get(path, MISSING), path))

        return ReadOnlyTree(result)


def registry(schema):
    """Bind every schema owner to its trusted configuration script."""
    from nvyr.config_scripts import (
        container, firewall, firewall_failsafe, logging, interface_ethernet, interface_dummy, interface_virtual_ethernet,
        interface_bridge, interface_loopback, protocols_static, protocols_bgp, policy,
        service_ssh, service_dhcp, system_dns, system_login, system_hostname, system_configuration, system_ntp, system_cpu,
        system_timezone, vrf, vrf_conntrack,
    )

    modules = {
        'time-zone': system_timezone,
        'cpu': system_cpu,
        'logging': logging,
        'container': container,
        'firewall': firewall,
        'firewall_failsafe': firewall_failsafe,
        'ethernet': interface_ethernet,
        'dummy': interface_dummy,
        'loopback': interface_loopback,
        'virtual-ethernet': interface_virtual_ethernet,
        'bridge': interface_bridge,
        'vrf': vrf,
        'vrf_conntrack': vrf_conntrack,
        'static': protocols_static,
        'bgp': protocols_bgp,
        'policy': policy,
        'ssh': service_ssh,
        'dhcp-server': service_dhcp,
        'dhcpv6-server': service_dhcp,
        'dns': system_dns,
        'ntp': system_ntp,
        'login': system_login,
        'system': system_hostname,
        'configuration': system_configuration,
    }
    missing = schema.owners.keys() - modules.keys()
    if missing:
        raise ValueError(f'No configuration script registered for: {", ".join(sorted(missing))}')

    return {name: modules[name] for name in schema.owners}
