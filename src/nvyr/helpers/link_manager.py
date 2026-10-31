"""Serialized desired-state reconciliation, ownership and compensating rollback.

configd owns user configuration. This journal records only actuation intent and
original attributes. RTNL operations are acknowledged individually: a group of
kernel changes is NOT atomic. Failed groups are compensated before returning.
"""

from copy import deepcopy
import json
import ipaddress
from itertools import groupby
import logging
import os
from pathlib import Path
import re
import time
import uuid

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.storage import atomic_json, sync_directory
from nvyr.helpers.netlink import TYPES, interface_name, normalize, read_attributes
from nvyr.helpers.dhcp_options import lease_routes, lease_spec
from nvyr.helpers import interface_ip, kernel_settings
from nvyr.helpers.kernel_settings_map import SETTINGS

log = logging.getLogger(__name__)


class Manager:
    def __init__(self, kernel, dhcp, directory='/var/lib/nvyr-netlink', *, boot=None, naming=None, types=None):
        self.kernel, self.dhcp = kernel, dhcp
        self.types = TYPES if types is None else types
        self.path = Path(directory) / 'state.json'
        self.updates = self.path.with_name('records.jsonl')
        self.naming = naming or (lambda name: None)
        self.boot = boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.error = None
        self.resolver = None

        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            'format': 2, 'boot': self.boot, 'owners': {}, 'records': {}, 'pending': {}}

        if self.state.get('format') != 2:
            raise RouterError('Unsupported netlinkd journal format')

        if self.path.exists():
            if not isinstance(self.state.get('epoch'), str) or not self.state['epoch']:
                raise RouterError('Missing netlinkd journal checkpoint ID')
        else:
            self.save()

        # Small durable record updates avoid rewriting all owners/records for
        # every created link. Checkpoint IDs fence an old log after a crash.
        if self.updates.exists():
            with self.updates.open('rb+') as stream:
                valid = 0

                for line in stream:
                    if not line.endswith(b'\n'):
                        break  # Interrupted append; no later operation was issued.

                    epoch, name, record = json.loads(line)
                    if epoch == self.state.get('epoch'):
                        if record is None:
                            self.state['records'].pop(name, None)
                        else:
                            self.state['records'][name] = record

                    valid = stream.tell()

                stream.truncate(valid)

        if self.state['boot'] != self.boot:
            # Do not replay an unsaved running configuration across boots. configd
            # supplies the saved configuration after this daemon becomes ready.
            self.state = {'format': 2, 'boot': self.boot, 'owners': {}, 'records': {}, 'pending': {}}
            self.save()

        self.observed = {}
        self.failures = {}
        self._index()

    def save(self):
        checkpoint = dict(self.state, format=2, epoch=uuid.uuid4().hex)
        atomic_json(self.path, checkpoint)
        self.state = checkpoint

        # A crash before truncation is harmless: the previous epoch is ignored.
        with self.updates.open('wb') as stream:
            stream.flush()
            os.fsync(stream.fileno())

        sync_directory(self.updates.parent)

    def replace_kernel_settings(self, values):
        """Apply global policy without overwriting managed interface overrides."""
        # This RPC owns firewall globals only; per-interface options arrive with links.
        expected = kernel_settings.firewall_values({})
        if not isinstance(values, dict) or values.keys() != expected.keys():
            raise ValidationError('Kernel settings must contain exactly the firewall global settings')
        overrides = {}
        for links in self.state['owners'].values():
            for name, spec in links.items():
                if self.kernel.device(name) is not None:
                    overrides[name] = {key: value for key, value in interface_ip.overrides(spec.get('ip-options', {})).items()
                                       if SETTINGS[key]['owner'] == 'firewall'}

        previous = self.state.get('kernel-settings', expected)
        with (self.kernel.ip_profile(self.state['owners'], values),
              kernel_settings.Manager().transaction(values, overrides=overrides, profile_overrides=False)):
            self.state['kernel-settings'] = values
            try:
                self.save()
            except Exception:
                self.state['kernel-settings'] = previous
                raise
        return {'previous': previous}

    def save_record(self, name):
        with self.updates.open('ab') as stream:
            stream.write((json.dumps([self.state['epoch'], name, self.state['records'].get(name)],
                                     separators=(',', ':')) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())

    def _index(self):
        self.claims = {name: owner for owner, links in self.state['owners'].items() for name in links}
        self.observed = {name: value for name, value in self.observed.items() if name in self.claims}
        self.failures = {name: value for name, value in self.failures.items()
                         if name in self.claims or name == 'DNS'}
        self.indices = {rec['index']: name for name, rec in self.state['records'].items()}
        self.dhcp_names = {name for owner, links in self.state['owners'].items() for name, spec in links.items()
                           if spec['dhcp4'] and not spec['disabled'] and owner not in self.state['pending']}
        self.dependents = {}

        for owner, links in self.state['owners'].items():
            for name, spec in links.items():
                driver = self.types[spec['kind']]
                definition = dict(spec, name=name)
                for dependency in (*driver.dependencies(definition), *driver.companions(definition)):
                    self.dependents.setdefault(dependency, set()).add(name)

    def fingerprint(self, name, device):
        if device is None:
            return None

        owner = self.claims.get(name)
        spec = self.state['owners'].get(owner, {}).get(name)
        if spec is None:
            return None

        return (device['index'], device['kind'], device['up'], device['carrier'],
                read_attributes(device['message'], self.types[spec['kind']].keymap))

    def affected(self, messages):
        """Ignore unmanaged traffic/statistics and coalesce relevant link changes."""
        names = set()

        for message in messages:
            event = message.get('event', '')
            if event in ('RTM_NEWLINK', 'RTM_DELLINK'):
                name = message.get_attr('IFLA_IFNAME')
                old_name = self.indices.get(message['index'])
                if old_name and old_name != name:
                    names.add(old_name)  # Rename away from an owned name.

                if name not in self.claims and name not in self.dependents:
                    continue

                if (event == 'RTM_DELLINK' or name not in self.claims
                        or self.fingerprint(name, self.kernel.decode_link(message)) != self.observed.get(name)):
                    names.add(name)
            elif event in ('RTM_NEWADDR', 'RTM_DELADDR'):
                name = self.indices.get(message['index'])
                if name:
                    names.add(name)
            elif event in ('RTM_NEWROUTE', 'RTM_DELROUTE'):
                # Only DHCP routes belong to this daemon, never FRR routes.
                if message.get('proto') == 16:
                    name = self.indices.get(message.get_attr('RTA_OIF'))
                    if name:
                        names.add(name)

        queue = list(names)

        while queue:
            for child in self.dependents.get(queue.pop(), ()):
                if child not in names:
                    names.add(child)
                    queue.append(child)

        affected = names & self.claims.keys()
        if affected and log.isEnabledFor(logging.DEBUG):
            log.debug('Kernel notifications require drift check: %s', ', '.join(sorted(affected)))

        return affected

    def _owner(self, owner):
        if not isinstance(owner, str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', owner):
            raise ValidationError('Invalid interface configuration owner')

    def dhcp_control(self, name, action):
        """Serialize client signals with interface commits and recovery."""
        interface_name(name)
        if self.state['pending']:
            raise RouterError('Interface recovery is required before controlling DHCP clients')

        definition = next((links[name] for links in self.state['owners'].values() if name in links), None)
        if not definition or not definition['dhcp4'] or definition['disabled']:
            raise RouterError(f'{name}: DHCPv4 is not enabled on this interface')

        with self.kernel.snapshot():
            device = self.kernel.device(name)
            record = self.state['records'].get(name)
            if not device or not record or device['index'] != record['index']:
                raise RouterError(f'{name}: managed interface is absent or has been replaced')

            self.dhcp.control(name, action, device['index'], device['attributes']['mac'])

    def validate(self, owner, links, *, recovery=False, require_external=True):
        self._owner(owner)
        links = normalize(links, self.types)
        claims = dict(self.state['owners'])

        for claimant, pending in self.state['pending'].items():
            claims[claimant] = claims.get(claimant, {}) | pending['before'] | pending['after']

        for name, spec in links.items():
            if any(claimant != owner and name in mapping for claimant, mapping in claims.items()):
                raise ValidationError(f'{name}: already claimed by another configuration owner')

            record = self.state['records'].get(name)
            if record and (record['owner'] != owner or record['kind'] != spec['kind']):
                raise ValidationError(f'{name}: already claimed by {record["owner"]} as {record["kind"]}')

            driver = self.types[spec['kind']]
            previous = self.state['owners'].get(owner, {}).get(name)
            driver.validate(dict(spec, name=name), links, previous)
            device = self.kernel.device(name)
            if device:
                if not driver.matches(device):
                    raise ValidationError(f'{name}: existing kernel interface has a different type')

                if driver.virtual and (not record or record['index'] != device['index']):
                    raise ValidationError(f'{name}: existing interface is not owned by nVyR')

                driver.validate_device(self.kernel, dict(spec, name=name))

                if not driver.virtual:
                    self.naming(name)
            elif not driver.virtual and not recovery:
                raise ValidationError(f'{name}: interface does not exist')

        self._ordered(links, require_external=require_external)

        return links

    def _ordered(self, links, *, require_external=True):
        ordered, visiting, visited = [], set(), set()

        def visit(name):
            if name in visited:
                return

            if name in visiting:
                raise ValidationError(f'{name}: cyclic interface dependencies')

            spec = links[name]
            driver = self.types[spec['kind']]
            members = [name]
            members.extend(peer for peer in driver.companions(dict(spec, name=name))
                           if peer in links and peer not in visited)
            # A kernel-created pair is one lifecycle unit: both endpoints must
            # precede every child, so reverse order removes all children first.
            visiting.update(members)
            for member in members:
                definition = links[member]
                member_driver = self.types[definition['kind']]
                for dependency in member_driver.dependencies(dict(definition, name=member)):
                    if dependency in links:
                        visit(dependency)
                    elif require_external and self.kernel.device(dependency) is None:
                        raise ValidationError(f'{member}: missing dependency {dependency}')

            visiting.difference_update(members)
            ordered.extend(members)
            visited.update(members)

        try:
            for name in sorted(links):
                visit(name)

            return ordered
        finally:
            # The recursive closure otherwise retains this configuration and
            # manager until cyclic GC, including after a failed validation.
            visit = None

    def _routes(self, name, record, desired):
        if not desired and not record.get('routes'):
            return

        present = self.kernel.routes(name)

        for route in record.get('routes', []):
            if route not in desired and route in present:
                self.kernel.route('del', name, route)

        # Record intent BEFORE adding a route so a crash cannot orphan it.
        if record.get('routes') != desired:
            record['routes'] = desired
            self.save_record(name)

        for route in desired:
            if route not in present:
                self.kernel.route('add', name, route)

    def reconcile_owner(self, owner, links, *, allow_missing=True, wait=False):
        self._attachments(owner, links)
        target = self.validate(owner, links, recovery=allow_missing)
        records = self.state['records']
        obsolete = {name: rec['definition'] for name, rec in records.items()
                    if rec['owner'] == owner and name not in links}
        ordered = reversed(self._ordered(obsolete, require_external=False))

        for kind, group in groupby(ordered, key=lambda name: records[name]['kind']):
            names = list(group)
            driver = self.types[kind]

            # Keep reverse dependency order. Only independent links of the same
            # type may be handed to a driver's bulk removal hook.
            members = set(names)
            dependent = any(set(driver.dependencies(dict(obsolete[name], name=name))) & members
                            for name in names)
            batches = ([name] for name in names) if dependent or not driver.virtual else [names]

            for batch in batches:
                self._remove_links(batch)

        for name in self._ordered(target):
            self.reconcile_link(owner, name, target[name], allow_missing=allow_missing, links=target)

        self.kernel.flush_addresses()
        waiting = []

        if wait:
            waiting = [name for name in target
                       if self.kernel.device(name) is not None and not self.kernel.ready(name)]

        # Start DAD on all links before waiting, rather than serializing its
        # one-second kernel timer once per newly configured IPv6 interface.
        deadline = time.monotonic() + 5

        while waiting:
            if time.monotonic() >= deadline:
                raise RouterError(f'{waiting[0]}: timed out waiting for IPv6 address detection')

            time.sleep(.05)

            self.kernel.refresh_addresses()
            waiting = [name for name in waiting if not self.kernel.ready(name)]

    def _remove_links(self, names):
        records = self.state['records']
        driver = self.types[records[names[0]]['kind']]
        present = []

        for name in names:
            record = records[name]
            self.dhcp.stop(name)
            device = self.kernel.device(name)
            if device:
                if driver.virtual and (device['index'] != record['index'] or not driver.matches(device)):
                    raise RouterError(f'{name}: refusing to delete an interface that replaced the owned device')

                driver.validate_device(self.kernel, dict(record['definition'], name=name))

                if not driver.virtual:
                    self.naming(name)
                    self._routes(name, record, [])
                    driver.release(self.kernel, dict(record['definition'], name=name), record['baseline'])
                    if record['kind'] in interface_ip.KINDS:
                        self.kernel.ip_policy(name, {}, self.state.get('kernel-settings', {}))

                # Deleting a virtual device removes its addresses/routes in the
                # same kernel operation; do not tear them down individually.
                log.debug('%s: %s owned %s interface', name,
                          'delete' if driver.virtual else 'release', record['kind'])
                present.append(name)

        try:
            if len(present) == 1:
                driver.remove(self.kernel, present[0])
            else:
                driver.remove_many(self.kernel, present)
        finally:
            # Some deletes may have succeeded before another failed. Refresh
            # every affected link before compensation, retaining journal records
            # until the entire batch has completed successfully.
            errors = []

            for name in present:
                try:
                    self.kernel.refresh(name)
                except Exception as error:
                    errors.append(error)

            if errors:
                raise errors[0]

        for name in names:
            del records[name]
            self.save_record(name)

    def _record_link(self, owner, name, definition, device):
        """Persist ownership before configuring a newly created endpoint."""
        records = self.state['records']
        record = records.get(name)
        driver = self.types[definition['kind']]

        if record is None or record['index'] != device['index']:
            if record:
                self.indices.pop(record['index'], None)

            record = {'owner': owner, 'kind': definition['kind'], 'index': device['index'],
                      'baseline': driver.snapshot(self.kernel, dict(definition, name=name), device),
                      'routes': [], 'definition': definition}
            records[name] = record
            self.indices[device['index']] = name
            self.save_record(name)

        return record

    def reconcile_link(self, owner, name, definition, *, allow_missing, links=None):
        """Bring one managed link and its DHCP-derived state into agreement.

        Missing physical devices/dependencies may remain pending during recovery.
        ``links`` supplies companion definitions when one kernel operation creates
        a pair. Baselines and created links are journaled before attributes change.
        """
        records = self.state['records']
        spec = dict(definition, name=name)
        driver = self.types[spec['kind']]
        device = self.kernel.device(name)
        record = records.get(name)

        # Missing physical parents during recovery keep their children pending too.
        missing = [dependency for dependency in driver.dependencies(spec)
                   if self.kernel.device(dependency) is None]
        if missing:
            if allow_missing:
                self.dhcp.stop(name)
                return
            raise ValidationError(f'{name}: missing dependency {missing[0]}')

        if device is None:
            self.dhcp.stop(name)

            if not driver.virtual:
                if allow_missing:
                    log.debug('%s: physical interface absent; waiting for hotplug', name)
                    return

                raise RouterError(f'{name}: interface disappeared during apply')

            log.debug('%s: %s %s interface', name, 'recreate missing' if record else 'create', spec['kind'])
            driver.create(self.kernel, spec)
            # A pair is one kernel creation; journal BOTH ends before applying attributes.
            definitions = links if links is not None else {name: definition}
            for created in (name, *driver.companions(spec)):
                self.kernel.refresh(created)
                self._record_link(owner, created, definitions[created], self.kernel.device(created))

            device = self.kernel.device(name)

        record = self._record_link(owner, name, definition, device)

        if record['definition'] != definition:
            log.debug('%s: configuration changed', name)
            record['definition'] = definition
            self.save_record(name)

        active_dhcp = spec['dhcp4'] and not spec['disabled']
        previous_lease = self.dhcp.lease(name, device['index']) if active_dhcp else None
        configured_spec = lease_spec(spec, previous_lease)
        if driver.configure(self.kernel, configured_spec, record['baseline']):
            self.kernel.refresh(name)

        if spec['kind'] in interface_ip.KINDS:
            self.kernel.ip_policy(name, spec['ip-options'], self.state.get('kernel-settings', {}))

        if spec['disabled'] or not spec['dhcp4']:
            self.dhcp.stop(name)
            lease = None
        else:
            self.kernel.state(name, True)
            self.dhcp.start(name, device['index'], self.kernel.device(name)['attributes']['mac'],
                            spec['dhcp-options'])
            lease = self.dhcp.lease(name, device['index'])

        # Identity changes fence the old lease. Restore its MTU immediately, without
        # toggling the configured/leased MTU on every ordinary reconciliation.
        final_spec = lease_spec(spec, lease)
        if final_spec != configured_spec and driver.configure(self.kernel, final_spec, record['baseline']):
            self.kernel.refresh(name)

        addresses = driver.addresses(spec)
        if not spec['disabled']:
            addresses.extend(interface_ip.addresses(spec['ip-options'], self.kernel.device(name)['attributes']['mac']))

        if lease:
            addresses.append(lease['address'])

        if not lease:
            self._routes(name, record, [])

        # Compare addresses by value, including equivalent prefix spellings
        # from programmatic clients. A static address must never acquire a
        # DHCP expiration merely because the lease uses another spelling.
        static_lease = lease and any(ipaddress.ip_interface(value) == ipaddress.ip_interface(lease['address'])
                                     for value in spec['addresses'])
        self.kernel.set_addresses(name, addresses, disabled=spec['disabled'],
                                  lease=lease if not static_lease else None, ip_options=spec['ip-options'])
        self.kernel.state(name, not spec['disabled'])

        if lease:
            routes = lease_routes(lease, spec['dhcp-options'])
            vrf = spec['attributes'].get('vrf')
            if vrf:
                master = self.kernel.device(vrf)
                table = read_attributes(master['message'], self.types['vrf'].keymap)['table']
                routes = [dict(route, table=table) for route in routes]

            self._routes(name, record, routes)

    def replace(self, owner, links, *, recovery=False):
        with self.kernel.snapshot():
            try:
                links = normalize(links, self.types)
                owners = self.state['owners'] | {owner: links}
                with self.kernel.ip_profile(owners, self.state.get('kernel-settings', {})):
                    return self._replace(owner, links, recovery=recovery)
            finally:
                self._index()

                for name in self.state['owners'].get(owner, {}):
                    self.observed[name] = self.fingerprint(name, self.kernel.device(name))

                self.reconcile_dns()

    def _replace(self, owner, links, *, recovery=False):
        """Replace one owner's desired links, journaling before kernel mutations.

        Ordinary apply failures attempt to restore the previous owner state.
        Recovery failures retain the pending record without attempting another
        rollback; uncertain restoration raises RecoveryError for configd to handle.
        """
        links = self.validate(owner, links, recovery=recovery)

        if self.state['pending'] and not recovery:
            raise RecoveryError('netlinkd has an incomplete transaction; restart configd to recover')

        before = deepcopy(self.state['owners'].get(owner, {}))
        started = time.monotonic()
        log.debug('%s: %s configuration (%d previous, %d requested interfaces)',
                  owner, 'recover' if recovery else 'apply', len(before), len(links))
        self.state['pending'][owner] = {'before': before, 'after': links}
        self.save()

        try:
            self.reconcile_owner(owner, links, allow_missing=recovery, wait=True)
            self.state['owners'][owner] = links
            self.state['pending'].pop(owner, None)
            self.save()
            self.error = None
            log.debug('%s: configuration applied in %.3fs', owner, time.monotonic() - started)
        except Exception as error:
            log.warning('%s: interface %s failed: %s', owner, 'recovery' if recovery else 'apply', error)
            self.state['owners'][owner] = before
            self.state['pending'][owner] = {'before': before, 'after': links}

            if recovery:
                try:
                    self.save()
                except Exception:
                    log.exception('Could not persist failed interface recovery')

                raise RecoveryError(f'Interface recovery failed: {error}') from error

            try:
                # Discard queued address work from the failed target before
                # reconciling the previous configuration.
                self.kernel.flush_addresses(verify=False)
                self.reconcile_owner(owner, before, wait=True)
                self.state['pending'].pop(owner, None)
                self.save()
                log.info('%s: previous interface configuration restored', owner)
            except Exception as rollback:
                self.state['pending'][owner] = {'before': before, 'after': links}

                try:
                    self.save()
                except Exception:
                    log.exception('Could not persist failed interface rollback')

                raise RecoveryError(f'Interface apply failed ({error}); rollback failed ({rollback}); restart configd to recover') from rollback

            raise RouterError(f'Interface apply failed; previous configuration restored: {error}') from error

    def reconcile(self, names=None):
        started = time.monotonic()
        log.debug('Reconcile %s: %d interfaces', 'audit' if names is None else 'targeted',
                  len(self.claims) if names is None else len(names))

        with self.kernel.snapshot(names):
            self._reconcile(names)

        log.debug('Reconciliation finished in %.3fs; %d failures', time.monotonic() - started, len(self.failures))

        if names is None and self.updates.stat().st_size > 1024 * 1024:
            self.save()

    def _reconcile(self, names):
        self._attachments()
        previous_failures = dict(self.failures)

        if names is None:
            self.failures = {name: message for name, message in self.failures.items()
                             if name in self.claims or name == 'DNS'}

        checked = set()

        # Dependencies span owners: restore a VRF before its Ethernet/dummy
        # members, regardless of which owner was first configured or loaded.
        selected = self.claims.keys() if names is None else names & self.claims.keys()
        target = {}
        queue = list(selected)

        while queue:
            name = queue.pop()
            owner = self.claims[name]
            if name in target or owner in self.state['pending']:
                continue

            spec = self.state['owners'][owner][name]
            target[name] = spec
            driver = self.types[spec['kind']]
            definition = dict(spec, name=name)
            for dependency in (*driver.dependencies(definition), *driver.companions(definition)):
                if dependency in self.claims and dependency not in target:
                    queue.append(dependency)

        for name in self._ordered(target, require_external=False):
            owner = self.claims[name]
            try:
                driver = self.types[target[name]['kind']]
                companions = driver.companions(dict(target[name], name=name))
                links = {member: target[member] for member in (name, *companions)}
                self.validate(owner, links, recovery=True)
                self.reconcile_link(owner, name, target[name], allow_missing=True, links=links)
                checked.add(name)
                self.observed[name] = self.fingerprint(name, self.kernel.device(name))
                self.failures.pop(name, None)
            except Exception as error:
                log.debug('%s: reconciliation exception', name, exc_info=True)
                message = f'{name}: {error}'
                self.failures[name] = message

        try:
            self.kernel.flush_addresses()
        except Exception as error:
            self.failures.update({name: str(error) for name in checked})

        for name in checked:
            try:
                if self.kernel.device(name) is not None:
                    self.kernel.ready(name)  # Report asynchronous DAD failures.
            except Exception as error:
                self.failures[name] = str(error)

        for name, message in self.failures.items():
            if name != 'DNS' and previous_failures.get(name) != message:
                log.error('Interface reconciliation failed: %s: %s', name, message)

        for name in checked:
            if name in previous_failures and name not in self.failures:
                log.info('%s: interface reconciliation recovered', name)

        self.reconcile_dns()

    def _attachments(self, owner=None, links=None):
        """Resolve cross-owner master relationships for apply, rollback and audits."""
        owners = dict(self.state['owners'])
        if owner is not None:
            owners[owner] = links
        attachments = {}
        for definitions in owners.values():
            for name, spec in definitions.items():
                driver = self.types[spec['kind']]
                for member, master in driver.attachments(dict(spec, name=name)).items():
                    # One link has only one master, regardless of its configuration owner.
                    if member in attachments and attachments[member] != master:
                        raise ValidationError(f'{member}: multiple configured masters')
                    attachments[member] = master
        self.kernel.attachments = attachments
        self.kernel.owned_master_indices = {
            record['index'] for record in self.state['records'].values()
            if self.types[record['kind']].attachments(dict(record['definition'], name='owned'))}

    def reconcile_dns(self):
        if self.resolver is not None:
            try:
                self.resolver.reconcile()
                self.failures.pop('DNS', None)
            except Exception as error:
                message = f'DNS: {error}'
                if not self.error or message not in self.error:
                    log.exception('DNS reconciliation failed')

                self.failures['DNS'] = message

        self.error = '; '.join(sorted(set(self.failures.values()))) or None

    def dns_servers(self, name):
        """Only current, enabled, owned DHCP interfaces contribute resolver data."""
        for owner, links in self.state['owners'].items():
            spec = links.get(name)
            if spec is None or owner in self.state['pending'] or spec['disabled'] or not spec['dhcp4']:
                continue

            device = self.kernel.device(name)
            record = self.state['records'].get(name)
            if device is None or record is None or record['index'] != device['index']:
                return []

            lease = self.dhcp.lease(name, device['index'])

            return lease.get('dns', []) if lease else []

        return []

    def status(self):
        return {'owners': self.state['owners'], 'pending': self.state['pending'], 'error': self.error,
                'dns': self.resolver.state if self.resolver is not None else None}
