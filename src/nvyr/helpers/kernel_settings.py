"""Apply registered kernel settings with defaults and compensating rollback.

The owning config script controls the transaction lifetime. Procfs writes are
individual kernel operations, not an atomic batch. Keep the context open until
the owner's remaining apply steps have succeeded.
"""

from contextlib import contextmanager
import json
from pathlib import Path
import re
from threading import RLock

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers.kernel_settings_map import SETTINGS, assignments, native_value, sysctl_lines
from nvyr.storage import atomic_json
from nvyr.tree import lookup


def validate_value(spec, value):
    """Validate native bounds as well as the CLI grammar before any writes."""
    # Presence leaves carry a Boolean, never an arbitrary truthy value.
    if spec['kind'] == 'presence':
        return isinstance(value, bool)
    # Declared choices include the inverse mapping used by ignore-style sysctls.
    if spec['values']:
        return isinstance(value, str) and value in spec['values']
    # Auto is only meaningful for memory-sized connection tracking capacities.
    if spec['kind'] == 'auto-integer' and value == 'auto':
        return True
    # Bound the text before parsing integers, including direct helper callers.
    if not isinstance(value, str) or len(value) > 32:
        return False
    pattern = r'[0-9]+(?:ms|[smhd])' if spec['kind'] == 'milliseconds' else r'[0-9]+[smhd]'
    if spec['kind'] not in ('seconds', 'milliseconds'):
        pattern = r'[0-9]+'
    # Only exact units are accepted; fractional and compound durations are ambiguous.
    if re.fullmatch(pattern, value) is None:
        return False
    number = int(native_value(spec, value))
    # Conservative jiffy bounds work with all supported kernel timer frequencies.
    return spec['minimum'] <= number <= spec['maximum']


def firewall_values(configuration):
    """Resolve every managed setting, including resets after deleting firewall."""
    options = lookup(configuration, ('firewall', 'global-options'), {})
    result = {}
    for name, spec in SETTINGS.items():
        if spec['owner'] != 'firewall':
            continue
        value = lookup(options, tuple(name.split()), spec['default'])
        # Standalone callers and verification must enforce the same native bounds.
        if not validate_value(spec, value):
            raise ValidationError(f'firewall global-options {name}: invalid kernel setting value {value!r}')
        result[name] = value
    return result


class Manager:
    """Registered procfs writes and a runtime sysctl.d profile for new devices."""

    def __init__(self, root='/proc/sys', *, profile='/run/sysctl.d/90-nvyr-firewall.conf',
                 baseline='/run/nvyr-kernel-settings/auto.json'):
        self.root = Path(root)
        self.profile = Path(profile)
        self.baseline = Path(baseline)
        self.lock = RLock()

    def path(self, name, **parameters):
        """Resolve placeholders without interpreting dots inside interface names."""
        spec = SETTINGS[name]
        for value in parameters.values():
            # A parameter must remain one Linux interface component, never a path.
            if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value) is None or value in ('.', '..'):
                raise ValidationError(f'Invalid kernel path component {value!r}')
        return self.root.joinpath(*(part.format_map(parameters) for part in spec['path']))

    def initialize(self):
        """Remember native auto capacities once per boot, before configuration."""
        if self.baseline.exists():
            return json.loads(self.baseline.read_text())
        values = {}
        for name, spec in SETTINGS.items():
            if spec['kind'] == 'auto-integer':
                values[name] = self.path(name).read_text().strip()
        atomic_json(self.baseline, values)
        return values

    def resolve(self, values):
        """Resolve schema defaults and boot-sized auto values into native strings."""
        result = {}
        baseline = None
        for name, value in values.items():
            spec = SETTINGS[name]
            # All owners must validate before converting or writing native values.
            if not validate_value(spec, value):
                raise ValidationError(f'{name}: invalid kernel setting value {value!r}')
            native = native_value(spec, value)
            if native is None:
                if baseline is None:
                    baseline = self.initialize()
                native = baseline[name]
            result[name] = native
        return result

    def targets(self, values, overrides=None):
        """Expand existing interfaces; preserve the global default and all gate.

        Overrides are keyed by interface, then registered setting name. The CLI
        supplies them through netlinkd's authoritative interface definitions.
        """
        result = {}
        for name, value in values.items():
            for relative, native in assignments(SETTINGS[name], value):
                if '*' not in relative:
                    result[self.root / relative] = native
                    continue
                parent, leaf = relative.split('*/')
                for directory in sorted((self.root / parent).iterdir()):
                    if directory.name not in ('all', 'default') and directory.is_dir():
                        path = directory / leaf
                        if path.exists():
                            result[path] = native
        for interface, settings in (overrides or {}).items():
            for name, value in self.resolve(settings).items():
                # Scalar system settings cannot be overridden for a single link.
                if '{interface}' not in SETTINGS[name]['path']:
                    raise ValidationError(f'{name}: not an interface setting')
                result[self.path(name, interface=interface)] = value
        return result

    def _write(self, path, value):
        """Write procfs in place; atomic file replacement is not a kernel API."""
        try:
            path.write_text(value + '\n')
        except FileNotFoundError:
            # Interfaces may disappear independently while firewall is applying.
            if not self._vanished_interface(path):
                raise

    def _vanished_interface(self, path):
        """Only disappearing device instances may bypass missing-file errors."""
        parts = path.relative_to(self.root).parts
        return (len(parts) == 5 and parts[0] == 'net' and parts[2] in ('conf', 'neigh')
                and parts[3] not in ('all', 'default') and not path.parent.exists())

    def _restore_new_interfaces(self, previous, targets):
        """An interface created during apply must also regain its old inheritance."""
        for name, spec in SETTINGS.items():
            if '{interface}' not in spec['path']:
                continue
            default = self.path(name, interface='default')
            if default not in previous:
                continue
            for path in self.targets({name: previous[default]}):
                if path not in targets:
                    self._write(path, previous[default])

    @contextmanager
    def transaction(self, values, *, overrides=None, profile_overrides=True):
        """Restore procfs and future-interface policy if any owner apply step fails."""
        # Template formatters import interface inventory; defer the write helper
        # until application so importing the interface policy has no cycle.
        from nvyr.helpers.template import write

        with self.lock:
            previous = {}
            changed = []
            profile_changed = False
            old_profile = self.profile.read_text() if self.profile.exists() else None
            try:
                native = self.resolve(values)
                targets = self.targets(native, overrides)
                # Read every target before changing anything, detecting missing modules early.
                for path in targets:
                    try:
                        previous[path] = path.read_text().strip()
                    except FileNotFoundError:
                        if not self._vanished_interface(path):
                            raise

                lines = sysctl_lines(native)
                for interface, settings in ((overrides or {}) if profile_overrides else {}).items():
                    for name, value in self.resolve(settings).items():
                        path = self.path(name, interface=interface).relative_to(self.root)
                        lines.append(f'{path.as_posix()} = {value}')
                text = '# Managed by nVyR; reconstructed from saved configuration.\n' + '\n'.join(lines) + '\n'
                if text != old_profile:
                    self.profile.parent.mkdir(parents=True, exist_ok=True)
                    profile_changed = True
                    write(self.profile, text, mode=0o644)

                for path, value in targets.items():
                    if path in previous and previous[path] != value:
                        changed.append(path)
                        self._write(path, value)
                yield
            except Exception as error:
                failures = []
                try:
                    if profile_changed:
                        if old_profile is None:
                            self.profile.unlink(missing_ok=True)
                        else:
                            write(self.profile, old_profile, mode=0o644)
                except Exception as restore_error:
                    failures.append(str(restore_error))
                for path in reversed(changed):
                    try:
                        if path.exists() and path.read_text().strip() != previous[path]:
                            self._write(path, previous[path])
                    except OSError as restore_error:
                        failures.append(f'{path}: {restore_error}')
                try:
                    if changed:
                        self._restore_new_interfaces(previous, targets)
                except OSError as restore_error:
                    failures.append(str(restore_error))
                if failures:
                    raise RecoveryError('Could not restore kernel settings: ' + '; '.join(failures)) from error
                if isinstance(error, OSError):
                    raise RouterError(f'Could not apply kernel settings: {error}') from error
                raise


class RemoteManager:
    """Keep firewall and interface writes serialized by netlinkd's event loop."""

    @contextmanager
    def transaction(self, values):
        from nvyr.helpers.interfaces import manager as interfaces

        previous = interfaces.request('replace-kernel-settings', values=values)['previous']
        try:
            yield
        except Exception as error:
            try:
                interfaces.request('replace-kernel-settings', values=previous)
            except Exception as restore_error:
                raise RecoveryError(f'Could not restore kernel settings: {restore_error}') from error
            raise


manager = RemoteManager()


def main():
    """Boot initialization runs after conntrack loads and before configd starts."""
    Manager().initialize()
