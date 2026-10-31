"""Authoritative session state, intents, commit units and restart recovery."""

from dataclasses import dataclass, field
from collections import deque
from copy import deepcopy
import logging
import math
import threading
import time
import uuid

from nvyr.errors import BusyError, ConfirmationRequired, LockError, RouterError, ValidationError, RecoveryError, SessionExpiredError
from nvyr.errors import Warning
from nvyr.lexer import lex, quote
from nvyr.modules import CommitContext
from nvyr.render import diff_commands
from nvyr.tree import MISSING, Mutation, MutationJournal, ReadOnlyTree, changes, lookup, overlay, projected_value
from nvyr.helpers import access, passwords, accounts, validators, reapply
from nvyr.helpers.dependencies import Dependencies

log = logging.getLogger(__name__)
DEFAULT_SESSION_TIMEOUT = 8 * 60 * 60


@dataclass
class Session:
    id: str
    user: str
    vty: str
    draft: bool
    commit_id: int
    mutations: MutationJournal = field(default_factory=MutationJournal)
    edit: tuple = ()
    alive: bool = True
    expires_at: float | None = None
    expired: bool = False
    dependency_cache: tuple | None = field(default=None, repr=False)

    def identity(self):
        return {"session": self.id, "user": self.user, "vty": self.vty}


class Engine:
    def __init__(self, schema, modules, store, *, clock=time.time, boot_id=None,
                 session_clock=time.monotonic, session_timeout=DEFAULT_SESSION_TIMEOUT):
        self.schema, self.modules, self.store, self.clock = schema, modules, store, clock
        self.dependencies = Dependencies(schema)
        self.session_clock = session_clock
        self.session_timeout = self._session_timeout(session_timeout)

        self.mutex = threading.RLock()
        self.sessions, self.lock_owner = {}, None
        self.busy, self.unhealthy = False, False
        self.activity = None
        self.events, self.event_id = deque(maxlen=256), 0
        self.boot_id = boot_id

        state = store.read("state.json", {"id": 0, "configuration": {}})
        self.running, self.commit_id = state["configuration"], state["id"]
        schema.validate_configuration(self.running)

        self.pending = store.read("confirmed.json")
        self.scheduled = None
        scheduled = store.read('scheduled.json')
        if scheduled:
            store.delete('scheduled.json')
            log.warning('Scheduled commit by %s cancelled because configd restarted', scheduled['user'])

        transaction = store.read("transaction.json")

        # A crash may leave a completed history write before state publication.
        # Keep that immutable evidence and allocate a recovery ID; never reuse it.
        if transaction and store.latest_id() > self.commit_id:
            self.commit_id = store.latest_id() + 1

        if transaction:
            # apply may have succeeded immediately before a crash; restore all units.
            self._restore(transaction["before"], reason="interrupted-commit", force=True)
            store.delete("transaction.json")

        if self.pending:
            # Conservative restart policy: never extend a disconnected confirmation lease.
            self._restore(self.pending["before"], reason="unconfirmed-restart", force=True)
            self.pending = None
            store.delete("confirmed.json")

        if boot_id is not None and state.get("boot_id") != boot_id:
            self._restore(accounts.boot_configuration(store.read("boot.json", {}), self.running), reason="boot", force=True)
        elif not transaction:
            self._run_recovery(self.running, self.running, set(schema.owners), startup=True)

        self._persist("startup", "configd")

    def _persist(self, reason, user, *, comment=None):
        for session in self.sessions.values():
            session.dependency_cache = None

        self.store.record(self.commit_id, self.running, reason=reason, user=user, comment=comment)
        self.store.write("state.json", {"id": self.commit_id, "configuration": self.running, "boot_id": self.boot_id})

        # Use the published tree, not another owner's possibly failed proposal.
        # This engine setting also applies when the system branch is absent.
        node = lookup(self.schema.root, ('children', 'system', 'children', 'configuration',
                                         'children', 'commit-revisions'), None)
        if node is not None:
            retention = lookup(self.running, ('system', 'configuration', 'commit-revisions'), node['default']['value'])
            self.store.prune(int(retention))

    @staticmethod
    def _session_timeout(value):
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value > 0
        except OverflowError:
            valid = False

        if not valid:
            raise ValidationError('Session timeout must be a positive finite number of seconds')

        return value

    def open(self, user, vty, draft=False, *, timeout=None):
        access.require('configure')

        with self.mutex:
            timeout = self.session_timeout if timeout is None else self._session_timeout(timeout)
            session = Session(uuid.uuid4().hex, user, vty, draft, self.commit_id)
            session.expires_at = self.session_clock() + timeout
            self.sessions[session.id] = session
            self._live_lock()

            if not draft and self.lock_owner is None and not self.pending and not self.scheduled and not self.busy:
                self.lock_owner = session.id

            return session

    def close(self, session, *, expired=False):
        with self.mutex:
            session.alive = False
            session.expired = session.expired or expired
            session.mutations.clear()
            session.dependency_cache = None
            session.edit = ()
            self.sessions.pop(session.id, None)

            if self.lock_owner == session.id and not self.scheduled and (expired or not self.pending):
                self.lock_owner = None

    def _expire_sessions(self):
        now = self.session_clock()

        for session in list(self.sessions.values()):
            if now >= session.expires_at:
                self.close(session, expired=True)

    def check_session(self, session):
        with self.mutex:
            if session.alive and session.expires_at is not None and self.session_clock() >= session.expires_at:
                self.close(session, expired=True)

            if session.expired:
                raise SessionExpiredError('Configuration session expired. Exit configuration mode and open a new session.')

            if not session.alive:
                raise RouterError('Configuration session is closed')

    def _live_lock(self):
        self._expire_sessions()

        if self.pending or self.scheduled:
            return  # Lease remains pinned even after the transport disappears.

        owner = self.sessions.get(self.lock_owner)
        if not owner or not owner.alive:
            self.lock_owner = None

    def _idle(self, session):
        self.check_session(session)
        access.require('configure')

        if self.unhealthy:
            raise BusyError("Configuration changes are unavailable until recovery completes. Check the system logs and restart the configuration service after correcting the failure.")

        reserved_execution = (self.scheduled is not None and self.scheduled['executing']
                              and session is self.scheduled['session']
                              and self.activity and self.activity['operation'] == 'scheduled-commit')
        if self.busy and not reserved_execution:
            raise BusyError("A commit or rollback is in progress. Wait for it to finish, then try again.")

    def _holder(self, session):
        self._live_lock()
        self.check_session(session)

        if session.draft:
            raise LockError("Draft sessions cannot change or save running configuration. Use 'configure' for a normal configuration session.")

        if self.lock_owner != session.id:
            owner = self.sessions.get(self.lock_owner)
            details = owner.identity() if owner else {"session": self.lock_owner}
            message = (f"The commit lock is held by {owner.user} on {owner.vty} (session {owner.id})."
                       if owner else "This session does not hold the commit lock.")
            raise LockError(message + " Use request-session-lock to request it.", details=details)

    def request_lock(self, session, expected_owner=None):
        with self.mutex:
            self._idle(session)

            if session.draft:
                raise LockError("Draft sessions cannot acquire the commit lock. Use 'configure' for a normal configuration session.")

            self._live_lock()

            if self.scheduled:
                raise LockError('Cancel or wait for the scheduled commit before transferring the commit lock')

            if self.pending:
                raise LockError("The commit lock cannot be transferred while a commit-confirm rollback timer is active. Wait for confirmation or rollback.")

            if self.lock_owner not in {None, session.id}:
                owner = self.sessions[self.lock_owner]
                if expected_owner != owner.id:
                    raise ConfirmationRequired(f"Take the commit lock from {owner.user} on {owner.vty} (session {owner.id})?", details=owner.identity())

            self.lock_owner = session.id

            return session.identity()

    def view(self, session):
        with self.mutex:
            self.check_session(session)
            return overlay(self.running, session.mutations)

    def release_lock(self, session):
        with self.mutex:
            self._idle(session)
            self._holder(session)
            if self.scheduled:
                raise LockError('Cancel or wait for the scheduled commit before releasing the commit lock')
            if self.pending:
                raise LockError('Confirm or wait for rollback before releasing the commit lock')

            self.lock_owner = None

    def configuration_status(self, session):
        """Detailed, on-demand status; keep full-tree work out of notification polling."""
        with self.mutex:
            access.require('configure')
            self.check_session(session)
            self._live_lock()
            candidate = self.view(session)
            changed = sorted(self.schema.ownership.snapshot(self.running).changed(
                self.schema.ownership.snapshot(candidate)))
            holder = self.sessions.get(self.lock_owner)
            activity = dict(self.activity) if self.activity else None
            if activity:
                activity['elapsed'] = max(0, self.session_clock() - activity.pop('started'))

            return {
                'session': session.identity(), 'draft': session.draft,
                'remaining': max(0, session.expires_at - self.session_clock()),
                'commit_id': self.commit_id, 'changed': changed,
                'unsaved': self.running != self.store.read('boot.json', {}),
                'deadline': self.pending['deadline'] if self.pending else None,
                'confirm_remaining': max(0, self.pending['deadline'] - self.clock()) if self.pending else None,
                'scheduled': self.scheduled_status(),
                'lock': holder.identity() if holder else ({'session': self.lock_owner} if self.lock_owner else None),
                'activity': activity, 'unhealthy': self.unhealthy,
            }

    def references(self, session, tokens):
        """Inspect provider consumers in running plus this session's pending changes."""
        with self.mutex:
            access.require('configure')
            self.check_session(session)
            cursor = self.schema.resolve(list(session.edit) + list(tokens))

            if cursor.node['kind'] != 'tag_node':
                raise ValidationError('Reference inspection requires a tag-node instance.')

            if cursor.expect != 'child':
                raise ValidationError('Specify the tag-node instance to inspect.')

            if 'dependency' not in cursor.node:
                raise ValidationError('This object does not register dependencies.')

            get, keys = self.dependencies.candidate_readers(access.visible(self.running), session.mutations)
            if get(cursor.path) is MISSING:
                raise ValidationError(f"Object is not configured: {' '.join(map(quote, cursor.path))}")

            identity = (cursor.node['dependency'], self.dependencies.identity(cursor.node, cursor.path))
            records = self.dependencies.collect(get, keys, 'depends', identities={identity})
            paths = {self.schema.command_path(path) + (value,) if self.schema.resolve(path).node['kind'] == 'leaf_node' else self.schema.command_path(path)
                     for _, value, path in records}

            return sorted(paths)

    def _start_activity(self, operation, session=None, *, started=None):
        self.busy = True
        self.activity = {'operation': operation, 'started': self.session_clock() if started is None else started,
                         'session': session.identity() if session else None, 'owner': None}

    def _activity_owner(self, owner):
        with self.mutex:
            if self.activity:
                self.activity['owner'] = owner

    def _finish_activity(self):
        with self.mutex:
            if self.scheduled and self.scheduled['executing']:
                # Keep runtime updates out of the gap between scheduled verification and apply.
                self._start_activity('scheduled-commit', self.scheduled['session'])
                return
            self.busy = False
            self.activity = None

    def _append(self, session, *mutations, check_dependencies=True):
        if any(mutation.owner == 'login' or mutation.kind in {'set', 'delete'} and
               self.schema.ownership.touches(mutation.path, 'login') for mutation in mutations):
            access.require('manage login accounts')
            access.protect_login(self.view(session), overlay(self.running, [*session.mutations, *mutations]))

        if check_dependencies and mutations:
            self.dependencies.check_mutations(self.running, session, mutations)

        for mutation in mutations:
            if self.dependencies.affects(mutation.path, 'depends'):
                # Delete references from the cached index using only this branch.
                # Bulk interface removal must not rescan all references, whether
                # or not those interfaces contain a VRF assignment.
                if mutation.kind == 'delete' and session.dependency_cache is not None:
                    get, keys = self.dependencies.candidate_readers(self.running, session.mutations)
                    removed = self.dependencies.collect(get, keys, 'depends', mutation.path)
                    references = session.dependency_cache[2]
                    for kind, value, path in removed:
                        identity = (kind, value)
                        paths = references.get(identity)
                        if paths is not None:
                            paths.discard(path)
                            if not paths:
                                del references[identity]
                else:
                    session.dependency_cache = None

            session.mutations.append(mutation)

            # Exclusion containers have no standalone meaning after their last value is removed.
            if mutation.kind in {'delete', 'subtract'}:
                for index, word in enumerate(mutation.path):
                    if word != 'not':
                        continue
                    scope = mutation.path[:index + 1]
                    if not self.schema.resolve(scope).node.get('_negation_branch'):
                        continue
                    branches = [mutation.path[:index + 2], scope] if len(mutation.path) > index + 1 else [scope]
                    for branch in branches:
                        if projected_value(self.running, session.mutations, branch) == {}:
                            session.mutations.append(Mutation('delete', branch, owner=mutation.owner))

    def mutate(self, session, operation, tokens, *, absolute=False, check_dependencies=True):
        """Stage CLI intents against the session's projected configuration.

        Anchored set commands are parsed and dependency-checked as a group before
        staging. Deletes may remove one multi-value member or an entire subtree;
        none of these operations applies configuration to the host.
        """
        with self.mutex:
            self._idle(session)

            if operation == "set":
                cursors = self.schema.set_paths(tokens, root=() if absolute else session.edit)
                mutations = []

                for cursor in cursors:
                    if not cursor.owner and not self.schema.ownership.supports(cursor.path):
                        raise ValidationError("This setting is not supported by this router build.")

                    kind = "ensure" if cursor.node["kind"] != "leaf_node" else ("add" if cursor.node.get("multi") else "set")
                    path, value = cursor.path, cursor.value

                    if cursor.owner == 'login':
                        access.require('manage login accounts')

                    if cursor.node.get('input_only'):
                        path = path[:-1] + ('encrypted-password',)
                        value = passwords.hash_password(value)

                    mutations.append(Mutation(kind, path, value, cursor.owner or ''))

                # Parse and validate the entire line before staging any of its intents.
                if check_dependencies:
                    self.dependencies.check_mutations(self.running, session, mutations)

                messages = []

                for cursor, mutation in zip(cursors, mutations):
                    current = projected_value(self.running, session.mutations, mutation.path)

                    if mutation.kind == 'ensure':
                        duplicate = current is not MISSING
                    elif mutation.kind == 'add':
                        duplicate = current is not MISSING and mutation.value in current
                    else:
                        duplicate = current == mutation.value

                    if duplicate:
                        command = 'set ' + ' '.join(map(quote, self.schema.command_path(cursor.path)))

                        if cursor.node['kind'] == 'leaf_node' and not cursor.node.get('valueless'):
                            command += ' ' + quote('<redacted>' if cursor.node.get('secret') else cursor.value)

                        messages.append(f'Configuration already exists: {command}\n')
                        continue

                    self._append(session, mutation, check_dependencies=False)

                return messages

            words = list(tokens) if absolute else list(session.edit) + list(tokens)
            cursor = self.schema.configuration_path(words, operation)

            if operation == "edit":
                session.edit = cursor.path
                return

            if operation == "delete":
                if self.schema.ownership.touches(cursor.path, 'login'):
                    access.require('manage login accounts')

                current = projected_value(self.running, session.mutations, cursor.path)
                negative = None

                if cursor.node.get('negatable') and cursor.expect in {'value', 'tag'}:
                    negative = cursor.path[:-1] + ('not', cursor.path[-1])

                # A whole-field delete also removes exclusions, even when no positive values exist.
                missing = current is MISSING
                if negative is not None:
                    missing = missing and projected_value(self.running, session.mutations, negative) is MISSING

                selected_value = cursor.expect == 'done' and not cursor.node.get('valueless')
                if selected_value and cursor.node.get('multi'):
                    missing = current is MISSING or cursor.value not in current

                if missing:
                    path = ' '.join(map(quote, self.schema.command_path(cursor.path)))
                    if selected_value:
                        value = '<redacted>' if cursor.node.get('secret') else cursor.value
                        path += ' ' + quote(value)

                    return [f'Nothing to delete: {path} is not configured.\n']

                if negative is not None:
                    self._append(session, Mutation('delete', negative, owner=cursor.owner or ''),
                                 check_dependencies=check_dependencies)
                if cursor.expect == "done" and not cursor.node.get("valueless"):
                    if cursor.node.get("multi"):
                        self._append(session, Mutation("subtract", cursor.path, cursor.value, cursor.owner), check_dependencies=check_dependencies)
                        return

                    if current != cursor.value:
                        raise ValidationError(f"Value {cursor.value!r} is not configured at {' '.join(cursor.path)!r}. Use show to check the current setting.")

                self._append(session, Mutation("delete", cursor.path, owner=cursor.owner or ''),
                             check_dependencies=check_dependencies)

    def discard(self, session):
        with self.mutex:
            self._idle(session)
            session.mutations.clear()
            session.dependency_cache = None

    def up(self, session):
        self.check_session(session)

        for length in range(len(session.edit) - 1, -1, -1):
            path = session.edit[:length]
            if self.schema.editable(self.schema.resolve(path)):
                session.edit = path
                return

    def rename(self, session, source, destination):
        self._transfer_tag(session, source, destination, move=True)

    def copy(self, session, source, destination):
        self._transfer_tag(session, source, destination, move=False)

    def _transfer_tag(self, session, source, destination, *, move):
        with self.mutex:
            self._idle(session)
            operation = 'rename' if move else 'copy'
            left = self.schema.resolve(list(session.edit) + source)
            right = self.schema.resolve(list(session.edit) + destination)
            if left.node is not right.node or left.node["kind"] != "tag_node" or left.expect != "child" or right.expect != "child":
                raise ValidationError(f"{operation.capitalize()} must keep the same object type. Specify an existing object and a new name under the same configuration section.")

            if move and not left.node.get('rename', True):
                raise ValidationError(f"Renaming is not supported for: {' '.join(left.path[:-1])}")

            value = projected_value(self.running, session.mutations, left.path)
            if value is MISSING:
                raise ValidationError(f"Cannot {operation} {' '.join(left.path)!r}: it is not configured.")

            if projected_value(self.running, session.mutations, right.path) is not MISSING:
                raise ValidationError(f"Cannot {operation} to {' '.join(right.path)!r}: that name is already configured.")

            mutations = [Mutation('set', right.path, value, right.owner)]
            if move:
                mutations.insert(0, Mutation('delete', left.path, owner=left.owner))

            # Published subtrees are immutable; later edits copy their changed paths.
            self._append(session, *mutations)

    def stage_configuration(self, session, configuration, *, replace=False):
        with self.mutex:
            self._idle(session)
            configuration = passwords.normalize(configuration)
            self.schema.validate_configuration(configuration)

            if replace:
                access.protect_login(self.running, configuration)

            from nvyr.render import set_commands

            staged = Session("load", session.user, session.vty, session.draft, session.commit_id)

            if replace:
                lines = diff_commands(self.schema, self.running, configuration)
            else:
                lines = set_commands(self.schema, configuration)
                staged.mutations = MutationJournal(session.mutations)

            for line in lines:
                tokens = lex(line)
                # Loads are validated as one resulting tree, so serialization
                # order cannot reject a valid removal of references and providers.
                self.mutate(staged, tokens[0].value, tokens[1:], absolute=True, check_dependencies=False)

            self.dependencies.check_trees(self.view(session), self.view(staged))
            self.check_session(session)
            session.mutations = staged.mutations
            session.dependency_cache = None

    def rollback(self, session, ago):
        self.stage_configuration(session, self.store.historical(self.commit_id, ago), replace=True)

    def save(self, session):
        with self.mutex:
            self._idle(session)
            self._holder(session)

            if self.scheduled:
                raise LockError('Cancel or wait for the scheduled commit before saving')

            if self.pending:
                raise LockError("Confirm the pending commit before saving")

            if session.mutations:
                raise ValidationError("Commit or discard this session's pending changes before save")

            self.store.write("boot.json", self.running, metadata={'dependencies': self.dependencies.document(self.running)})

    def _lifecycle(self, owner, effective, previous, recovery=False, report=None, *, check_only=False, snapshots=None, reapply_paths=(), startup=False):
        """Run one owner's lifecycle with read-only trees and registration context.

        ``effective`` includes defaults; ``previous`` is the explicit running
        configuration. Verification-only calls stop before generate/apply.
        Recovery is also used for live rollback; startup identifies boot replay.
        """
        def report_message(message):
            # Transport plain text over RPC, retaining severity for unattended replay.
            if report is not None:
                report(str(message) if isinstance(message, Warning) else message)
            elif isinstance(message, Warning):
                log.warning("%s: %s", owner, message)
            else:
                log.info("%s: %s", owner, message)

        current, prior = snapshots or (self.schema.ownership.snapshot(effective),
                                       self.schema.ownership.snapshot(self.schema.defaults(previous)))
        context = CommitContext(ReadOnlyTree(effective), ReadOnlyTree(previous), owner, self.schema.owners[owner][0], recovery,
                                report_message,
                                previous_effective=ReadOnlyTree(prior.configuration),
                                state_directory=self.store.directory, check_only=check_only, startup=startup,
                                scripts=ReadOnlyTree(current.registrations),
                                previous_scripts=ReadOnlyTree(prior.registrations),
                                sections=ReadOnlyTree(current.sections.get(owner, {})),
                                previous_sections=ReadOnlyTree(prior.sections.get(owner, {})),
                                dependencies=self.dependencies, reapply_paths=frozenset(reapply_paths))
        module = self.modules[owner]
        configuration = module.get_config(context)
        module.verify(configuration, context)
        if check_only:
            return

        generated = module.generate(configuration, context)
        module.apply(generated, context)

    def check(self, session, *, report=None):
        """Verify changed owners without publishing, persisting or applying intent."""
        with self.mutex:
            self._idle(session)
            if self.scheduled and session is not self.scheduled['session']:
                raise LockError('Cancel or wait for the scheduled commit before checking another configuration')
            if self.pending:
                raise LockError('Confirm or wait for rollback before checking another configuration')

            before = self.running
            intended = self.view(session)
            access.protect_login(before, intended)
            effective = self.schema.defaults(intended)
            affected = self.schema.ownership.snapshot(before).changed(self.schema.ownership.snapshot(intended))
            snapshots = (self.schema.ownership.snapshot(effective),
                         self.schema.ownership.snapshot(self.schema.defaults(before)))
            reapplies = reapply.plan(self.dependencies, snapshots[1].configuration, effective)
            ordered = reapplies.order(affected, self.schema)
            commit_id = self.commit_id
            self._start_activity('check', session)

        results, messages = {}, []

        try:
            for owner in ordered:
                self._activity_owner(owner)
                try:
                    self._lifecycle(owner, effective, before, report=report or messages.append, check_only=True,
                                    snapshots=snapshots, reapply_paths=reapplies.paths.get(owner, ()))
                    results[owner] = {'success': True}
                except RouterError as error:
                    results[owner] = {'success': False, 'error': str(error)}
                except Exception:
                    log.exception('Unexpected failure in %s configuration check', owner)
                    results[owner] = {'success': False, 'error': 'Unable to verify this configuration; check the system logs for details.'}

            return {'commit_id': commit_id, 'results': results, 'messages': messages}
        finally:
            self._finish_activity()

    def commit(self, session, *, expected_id=None, minutes=None, confirmed_minutes=None, progress=None, comment=None):
        """Apply changed owners and publish independent successes.

        Ordinary owner failures are returned in results and their edits remain
        pending. Failed dependencies can require restoring successful owners.
        An uncertain recovery or publication failure retains the journal and
        marks the engine unhealthy rather than publishing an unverified state.
        Commit-confirm deadlines use minutes; committing does not save boot config.
        """
        started = self.session_clock()
        with self.mutex:
            self._idle(session)
            self._holder(session)

            if self.scheduled and session is not self.scheduled['session']:
                raise LockError('Cancel or wait for the scheduled commit before another commit')

            if comment is not None and (not isinstance(comment, str) or not validators.text(comment)):
                raise ValidationError('Commit comment must be nonempty single-line text without control characters')

            if self.pending:
                raise LockError("Confirm or wait for rollback before another commit")

            if session.commit_id != self.commit_id and expected_id != self.commit_id:
                raise ConfirmationRequired(f"Running configuration changed to commit {self.commit_id} since your last commit. Apply your pending changes to the current configuration?", details={"commit_id": self.commit_id})

            if minutes is not None and (not isinstance(minutes, (float, int)) or not 0 < minutes <= 1440):
                raise ValidationError("Enter a rollback timeout greater than zero and no more than 1440 minutes.")

            if minutes is not None and confirmed_minutes != minutes:
                unit = "minute" if minutes == 1 else "minutes"
                raise ConfirmationRequired(f"Commit configuration with automatic rollback in {minutes:g} {unit}?", details={"confirm_minutes": minutes})

            before = self.running
            intended = self.view(session)
            access.protect_login(before, intended)
            effective = self.schema.defaults(intended)
            mutations = list(session.mutations)
            # Explicit changes select owners; effective snapshots also expose default
            # changes to their lifecycle and dependency reapplication checks.
            prior = self.schema.ownership.snapshot(before)
            current = self.schema.ownership.snapshot(intended)
            affected = prior.changed(current)
            requires = self.schema.ownership.required_parents(prior, current)
            snapshots = (self.schema.ownership.snapshot(effective),
                         self.schema.ownership.snapshot(self.schema.defaults(before)))
            reapplies = reapply.plan(self.dependencies, snapshots[1].configuration, effective)
            affected.update(reapplies.paths)
            ordered = reapplies.order(affected, self.schema, requires)
            for consumer, providers in reapplies.requires.items():
                requires.setdefault(consumer, set()).update(providers)

            if intended == before:
                session.mutations.clear()
                session.commit_id = self.commit_id

                return {"commit_id": self.commit_id, "results": {}, "changed": False}

            # Persist the recovery target before any script can alter live state.
            self.store.write("transaction.json", {"before": before, "id": self.commit_id, "owners": sorted(affected)})

            if minutes is not None:
                pending = {"before": before, "owner": session.id, "deadline": self.clock() + minutes * 60}

                try:
                    self.store.write("confirmed.json", pending)
                except Exception:
                    # No lifecycle has started, so there is no uncertain live apply.
                    self.store.delete("transaction.json")
                    raise

                self.pending = pending

            self._start_activity('commit', session, started=started)

        # Scripts run outside the mutex so status requests remain responsive.
        # The activity flag continues to exclude competing commits and updates.
        results, succeeded, messages = {}, set(), []

        def report(message):
            if progress:
                progress('report', owner, message)
            else:
                messages.append(message)

        try:
            for owner in ordered:
                self._activity_owner(owner)
                if progress:
                    progress('start', owner, None)

                try:
                    blocked = (requires.get(owner, set()) & affected) - succeeded
                    if blocked:
                        raise ValidationError('Required configuration operation failed: ' + ', '.join(sorted(blocked)))

                    self._lifecycle(owner, effective, before, report=report, snapshots=snapshots,
                                    reapply_paths=reapplies.paths.get(owner, ()))
                    succeeded.add(owner)
                    results[owner] = {"success": True}
                except RecoveryError:
                    # A backend could not compensate a partial live apply. Keep the
                    # durable before-image for restart recovery instead of publishing.
                    raise
                except RouterError as error:
                    results[owner] = {"success": False, "error": str(error)}
                except Exception:
                    log.exception("Unexpected failure in %s lifecycle", owner)
                    results[owner] = {"success": False, "error": "Unable to apply this configuration. Its changes remain pending; check the system logs for details."}

                if progress:
                    progress('finish', owner, results[owner])

            failed = self.schema.ownership.retained_owners(prior, current, affected - succeeded)
            while True:
                retained = self.schema.ownership.retained_owners(prior, current, reapplies.retain(failed))
                if retained == failed:
                    break
                failed = retained
            # Restore successful related owners when a dependent operation failed,
            # before publishing independent partial successes.
            restored = failed & succeeded
            if restored:
                restored_tree = self.schema.ownership.publish(before, intended, failed)
                self._run_recovery(restored_tree, intended, restored)
                for name in restored:
                    results[name] = {'success': False, 'error': 'Restored because a dependent configuration operation failed.'}
                    succeeded.remove(name)
                    if progress:
                        progress('finish', name, results[name])

            with self.mutex:
                self.running = self.schema.ownership.publish(before, intended, failed)
                changed = self.running != before
                if changed:
                    self.commit_id += 1
                    self._persist("commit-confirm" if minutes is not None else "commit", session.user, comment=comment)

                    if self.pending:
                        self.pending["deadline"] = self.clock() + minutes * 60
                        self.store.write("confirmed.json", self.pending)

                # Rebase pending intent onto the published partial success, rather
                # than replaying changes that were already applied successfully.
                if session.alive:
                    session.mutations = self._remaining_mutations(self.running, intended, mutations, affected - succeeded)
                    session.dependency_cache = None

                session.commit_id = self.commit_id

                if not changed and self.pending:
                    self.store.delete("confirmed.json")
                    self.pending = None

                self.store.delete("transaction.json")

                return {"commit_id": self.commit_id, "results": results, "changed": changed, "messages": messages,
                        "elapsed": max(0, self.session_clock() - started),
                        "deadline": self.pending['deadline'] if self.pending else None}
        except Exception:
            self.unhealthy = True  # Durable journal is retained for startup reconciliation.
            log.exception("Commit publication failed; recovery required")
            raise
        finally:
            self._finish_activity()

    def confirm(self, session):
        """Confirm the running revision independently of the originating connection."""
        with self.mutex:
            self._idle(session)

            if session.draft:
                raise LockError("Draft sessions cannot confirm running configuration. Use 'configure' for a normal configuration session.")

            if not self.pending:
                raise ValidationError("No confirmation is pending")

            if self.clock() >= self.pending["deadline"]:
                raise LockError("The commit-confirm timer has expired. Wait for automatic rollback to finish before committing again.")

            self.store.delete("confirmed.json")
            self.pending = None
            self._live_lock()
            log.info("Commit %s confirmed by %s on %s (session %s)",
                     self.commit_id, session.user, session.vty, session.id)

    def scheduled_status(self):
        """Expose metadata without disclosing the frozen configuration."""
        if not self.scheduled or self.scheduled['when'] is None:
            return None

        job = self.scheduled
        return {'when': job['when'], 'remaining': max(0, job['when'] - self.clock()),
                'session': job['session'].identity(), 'confirm_minutes': job['minutes']}

    def schedule_commit(self, session, delay, *, minutes=None, confirmed_minutes=None,
                        expected_id=None, comment=None, report=None):
        """Verify and reserve a frozen candidate; the timer owns subsequent execution."""
        with self.mutex:
            self._idle(session)
            self._holder(session)
            if self.pending or self.scheduled:
                raise LockError('Complete the pending confirmation or scheduled commit first')
            if type(delay) not in (int, float) or not math.isfinite(delay) or not 0 < delay <= 1440:
                raise ValidationError('Commit delay must be greater than zero and at most 1440 minutes')
            if minutes is not None and (type(minutes) not in (int, float) or
                                       not math.isfinite(minutes) or not 0 < minutes <= 1440):
                raise ValidationError('Rollback timeout must be greater than zero and at most 1440 minutes')
            if comment is not None and (not isinstance(comment, str) or not validators.text(comment)):
                raise ValidationError('Commit comment must be nonempty single-line text without control characters')
            if session.commit_id != self.commit_id and expected_id != self.commit_id:
                raise ConfirmationRequired('Running configuration changed. Schedule this candidate against the current configuration?',
                                           details={'commit_id': self.commit_id})
            if minutes is not None and confirmed_minutes != minutes:
                raise ConfirmationRequired(f'Schedule commit in {delay:g} minutes with automatic rollback {minutes:g} minutes after completion?',
                                           details={'confirm_minutes': minutes})
            if self.view(session) == self.running:
                return None

            frozen = Session(session.id, session.user, session.vty, False, self.commit_id,
                             mutations=MutationJournal(deepcopy(list(session.mutations))))
            job = {'session': frozen, 'when': None, 'minutes': minutes, 'comment': comment,
                   'executing': False, 'principal': access.principal.get(), 'role': access.role.get()}
            self.scheduled = job

        try:
            checked = self.check(frozen, report=report)
            failures = [f'{name}: {result["error"]}' for name, result in checked['results'].items()
                        if not result['success']]
            if failures:
                raise ValidationError('Scheduled commit verification failed: ' + '; '.join(failures))

            with self.mutex:
                if self.scheduled is not job:
                    raise LockError('Scheduled commit was cancelled')
                when = self.clock() + delay * 60
                self.store.write('scheduled.json', {'user': session.user, 'when': when})
                job['when'] = when
                log.info('Commit scheduled by %s for %s', session.user, when)
                return self.scheduled_status()
        except Exception:
            with self.mutex:
                if self.scheduled is job:
                    self.scheduled = None
                    self._live_lock()
            raise

    def cancel_commit(self, session):
        with self.mutex:
            self._idle(session)
            if session.draft:
                raise LockError('Use a normal configuration session to cancel a scheduled commit')
            if not self.scheduled:
                raise ValidationError('No commit is scheduled')
            if self.scheduled['executing']:
                raise BusyError('The scheduled commit has already started')

            self.store.delete('scheduled.json')
            self.scheduled = None
            self._live_lock()
            log.info('Scheduled commit cancelled by %s on %s', session.user, session.vty)

    def _execute_scheduled(self, job):
        """Run with the original caller's authorization and the normal recovery journal."""
        from nvyr.helpers.config_feedback import commit_summary

        frozen = job['session']
        principal_token = access.principal.set(job['principal'])
        role_token = access.role.set(job['role'])
        try:
            # Recheck all owners before applying any: runtime prerequisites may have changed.
            checked = self.check(frozen)
            failures = [f'{name}: {result["error"]}' for name, result in checked['results'].items()
                        if not result['success']]
            if failures:
                raise ValidationError('; '.join(failures))
            result = self.commit(frozen, minutes=job['minutes'], confirmed_minutes=job['minutes'],
                                 comment=job['comment'])
            message = 'Scheduled ' + commit_summary(self.schema, result).lstrip()
            for report in checked['messages'] + result.get('messages', []):
                message += str(report).rstrip('\n') + '\n'
            for owner, outcome in result['results'].items():
                if not outcome['success']:
                    message += f"{owner}: {outcome['error']}\n"

            with self.mutex:
                owner = self.sessions.get(frozen.id)
                if owner and owner.alive:
                    # Remove already-applied intents while retaining edits made after scheduling.
                    intended = overlay(self.running, owner.mutations)
                    remaining = MutationJournal()
                    for path, old, new in changes(self.running, intended):
                        cursor = self.schema.resolve(path, validate=False)
                        remaining.append(Mutation('delete' if new is MISSING else 'set', path,
                                                  None if new is MISSING else new, cursor.owner or ''))
                    owner.mutations = remaining
                    owner.dependency_cache = None
                    owner.commit_id = self.commit_id
        except Exception as error:
            message = f'Scheduled commit failed: {error}'
            log.exception('Scheduled commit by %s failed', frozen.user)
        finally:
            access.principal.reset(principal_token)
            access.role.reset(role_token)
            with self.mutex:
                try:
                    self.store.delete('scheduled.json')
                except Exception:
                    # Never retry an executed job because removing its restart marker failed.
                    self.unhealthy = True
                    raise
                finally:
                    self.scheduled = None
                    self._finish_activity()
                    self._live_lock()

        with self.mutex:
            self.event_id += 1
            self.events.append({'id': self.event_id, 'type': 'scheduled-commit', 'owner': frozen.id,
                                'commit_id': self.commit_id, 'message': message})
        log.info('%s', message.rstrip())

    def _remaining_mutations(self, running, intended, mutations, failed):
        """Keep original intents; split only operations spanning successful owners."""
        remaining = MutationJournal()
        if not failed:
            return remaining

        split = set()
        for mutation in mutations:
            owners = self.schema.ownership.owners_at(mutation.path)
            if not owners.intersection(failed):
                continue

            if owners <= failed:
                remaining.append(mutation)
            else:
                split.add(mutation.path)

        # Whole-object copy/delete can cross ownership boundaries. Keep only
        # its unpublished difference, without replaying successful siblings.
        previous = None
        for path in sorted(split):
            if previous is not None and path[:len(previous)] == previous:
                continue

            previous = path
            for location, old, new in changes(lookup(running, path), lookup(intended, path), path):
                cursor = self.schema.resolve(location, validate=False)
                kind = 'delete' if new is MISSING else 'set'
                remaining.append(Mutation(kind, location, None if new is MISSING else new, cursor.owner or ''))

        return remaining

    def _run_recovery(self, target, before, owners, *, startup=False):
        """Replay a target through normal lifecycles without publishing it here.

        Attempt all ordered owners and aggregate failures, so one broken section
        does not prevent independent recovery attempts. The caller owns journal
        cleanup and publication after this method succeeds.
        """
        effective = self.schema.defaults(target)
        snapshots = (self.schema.ownership.snapshot(effective),
                     self.schema.ownership.snapshot(self.schema.defaults(before)))
        reapplies = reapply.plan(self.dependencies, snapshots[1].configuration, effective)
        ordered = reapplies.order(owners, self.schema)
        failures = []

        for owner in ordered:
            self._activity_owner(owner)
            try:
                self._lifecycle(owner, effective, before, recovery=True, snapshots=snapshots, startup=startup,
                                reapply_paths=reapplies.paths.get(owner, ()))
            except Exception:
                log.exception("Recovery failed for %s", owner)
                failures.append(owner)

        if failures:
            raise RouterError("Recovery failed for " + ", ".join(failures) + ". Check the system logs before making further changes.")

    def _restore(self, target, *, reason, force=False):
        self.schema.validate_configuration(target)
        owners = (set(self.schema.owners) if force else
                  self.schema.ownership.snapshot(self.running).changed(self.schema.ownership.snapshot(target)))
        self._run_recovery(target, self.running, owners, startup=force)

        with self.mutex:
            if self.running != target:
                self.running = target
                self.commit_id += 1

            self._persist(reason, "configd")

    def tick(self):
        with self.mutex:
            job = self.scheduled
            if job is not None:
                self._expire_sessions()
                if self.busy or job['executing'] or job['when'] is None or self.clock() < job['when']:
                    return
                job['executing'] = True
                self._start_activity('scheduled-commit', job['session'])

        if job is not None:
            self._execute_scheduled(job)
            return

        with self.mutex:
            self._expire_sessions()

            if not self.pending or self.busy or self.clock() < self.pending["deadline"]:
                return

            self._start_activity('rollback')

        try:
            self._restore(self.pending["before"], reason="confirmation-expired")

            with self.mutex:
                self.store.delete("confirmed.json")
                owner_id = self.pending["owner"]
                owner = self.sessions.get(owner_id)
                if owner and owner.alive:
                    owner.commit_id = self.commit_id

                self.pending = None
                self._live_lock()
                self.event_id += 1
                self.events.append({"id": self.event_id, "type": "confirmed-rollback",
                                    "owner": owner_id, "commit_id": self.commit_id,
                                    "message": "Commit-confirm timer expired. Configuration has been rolled back."})
        finally:
            self._finish_activity()

    def status(self, session=None, *, after=0):
        """Small status/events response; retained events allow acknowledgement after display."""
        with self.mutex:
            self._expire_sessions()

            if not isinstance(after, int) or after < 0:
                raise ValidationError("Cannot retrieve notifications. Reconnect to the router and try again.")

            return {"events": [event for event in self.events if event["id"] > after],
                    "event_id": self.event_id, "commit_id": self.commit_id,
                    "session_commit_id": session.commit_id if session else None,
                    "session": session.id if session else None,
                    "session_expired": bool(session and session.expired),
                    "edit": list(self.schema.command_path(session.edit)) if session else []}
