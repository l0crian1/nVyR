"""Shared FRR CLI reconciliation, with feature-owned portions of a full snapshot.

Adapters select and replace their configuration in integrated FRR text. The
manager owns subprocesses, serialization, durable claims, and failure recovery.
No feature may feed a partial configuration directly to frr-reload.py.
"""

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from nvyr.errors import RecoveryError, RouterError
from nvyr.storage import atomic_json


def run(argv, timeout=300):
    """Bound the entire reload process tree, including its vtysh children."""
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, start_new_session=True) as process:
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise RouterError('FRR reload command timed out') from error

        if process.returncode:
            raise RouterError(f'FRR command failed ({process.returncode}): {output.strip()}')
        return output


class MgmtdCandidate:
    """CLI reload still stages converted commands in FRR's global candidate.

    These commands only inspect/discard native staging; desired configuration
    always goes through frr-reload.py. Never discard foreign work on entry.
    """
    def check(self, runner):
        running = json.loads(runner(['vtysh', '-c', 'show mgmt datastore-contents running json']))
        candidate = json.loads(runner(['vtysh', '-c', 'show mgmt datastore-contents candidate json']))
        if candidate != running:
            raise RouterError('FRR has uncommitted candidate changes; commit or abort them before retrying')

    def abort(self, runner):
        runner(['vtysh', '-c', 'configure terminal file-lock', '-c', 'mgmt commit abort'])
        self.check(runner)


class Manager:
    def __init__(self, *, runner=run, directory='/run/nvyr-frr',
                 executable='/usr/lib/frr/frr-reload.py', candidates=(MgmtdCandidate(),)):
        self.run = runner
        self.directory = Path(directory)
        self.executable = executable
        self.candidates = candidates

    def snapshot(self):
        return self.run(['vtysh', '-c', 'show running-config no-header'])

    def reload(self, target):
        # Matching confdir/frr.conf prevents frr-reload's implicit "write".
        # All scratch files live in configd's writable runtime directory.
        with tempfile.TemporaryDirectory(prefix='reload-', dir=self.directory) as staging:
            path = Path(staging) / 'frr.conf'
            path.write_text(target, encoding='utf-8')
            self.run([self.executable, '--reload', '--confdir', staging,
                      '--rundir', staging, '--logfile', str(Path(staging) / 'reload.log'),
                      '--stdout', str(path)])

    def check_daemons(self, daemons):
        for daemon in daemons:
            self.run(['vtysh', '-d', daemon, '-c', 'show version'])

    def check_candidates(self):
        for candidate in self.candidates:
            candidate.check(self.run)

    def abort_candidates(self):
        for candidate in self.candidates:
            candidate.abort(self.run)

    def reconcile(self, desired, adapter, scopes, daemons):
        current = self.snapshot()
        if adapter.select(current, scopes) == desired:
            return

        target = adapter.replace(current, desired)
        self.reload(target)
        self.check_daemons(daemons)
        self.check_candidates()
        if adapter.select(self.snapshot(), scopes) != desired:
            raise RouterError('FRR running configuration does not match the requested configuration')

    def apply(self, owner, desired, state_directory, *, adapter, daemons=(), recovery=False):
        """Apply one owner's complete state while retaining every other section.

        Configd serializes owners. The file lock also serializes all reload users.
        Persist scopes before execution so recovery can remove newly added state
        even when it is absent from the engine's authoritative before-image.
        """
        if not re.fullmatch(r'[a-z][a-z0-9-]*', owner):
            raise ValueError('Invalid FRR configuration owner')

        self.directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        if self.directory.is_symlink():
            raise RouterError('Refusing a symlink for the FRR staging directory')

        record_path = Path(state_directory) / 'frr-reload' / f'{owner}.json'
        try:
            with (self.directory / 'reload.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                record = json.loads(record_path.read_text()) if record_path.exists() else {'scopes': []}
                scopes = sorted(set(record['scopes']) | set(desired))
                desired = {scope: desired.get(scope, []) for scope in scopes}
                self.check_daemons(daemons)
                if recovery and record.get('pending'):
                    self.abort_candidates()
                else:
                    self.check_candidates()
                before = adapter.select(self.snapshot(), scopes)
                clean = {'scopes': scopes}
                atomic_json(record_path, clean | {'pending': {'before': before, 'target': desired}})

                try:
                    self.reconcile(desired, adapter, scopes, daemons)
                    atomic_json(record_path, clean)
                except Exception as error:
                    if recovery:
                        raise RecoveryError(f'FRR {owner} recovery failed: {error}') from error

                    try:
                        self.abort_candidates()
                        self.reconcile(before, adapter, scopes, daemons)
                        atomic_json(record_path, clean)
                    except Exception as restore_error:
                        raise RecoveryError(f'FRR {owner} reload failed ({error}); restoration could not be '
                                            f'confirmed ({restore_error}). Restart configd to recover.') from restore_error
                    raise RouterError(f'FRR {owner} reload failed; previous configuration restored: {error}') from error
        except RecoveryError:
            raise
        except Exception as error:
            if recovery:
                raise RecoveryError(f'FRR {owner} recovery failed: {error}') from error
            if isinstance(error, RouterError):
                raise
            raise RouterError(f'FRR {owner} reload failed: {error}') from error


manager = Manager()
