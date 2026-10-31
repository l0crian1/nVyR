"""Atomic durable records. A transaction journal guards the external apply boundary."""

import json
import os
from pathlib import Path
import tempfile
import time
import logging
from contextlib import contextmanager
from nvyr.errors import PersistenceError

log = logging.getLogger(__name__)


def saved_document(configuration, *, metadata=None):
    """Reserved file metadata is separate from the configuration tree."""
    return dict(configuration, _nvyr={'factory': False, **(metadata or {})})


def unpack_saved(document):
    """Separate saved-file directives from the configuration tree."""
    if not isinstance(document, dict):
        raise ValueError('Saved configuration must be an object')

    configuration = dict(document)
    metadata = configuration.pop('_nvyr', None)
    if not isinstance(metadata, dict) or type(metadata.get('factory')) is not bool:
        raise ValueError('Invalid saved configuration metadata')

    return configuration, metadata


def read_saved(path):
    return unpack_saved(json.loads(Path(path).read_text(encoding='utf-8')))


def has_saved_configuration(path):
    """Only offer retention for a real saved configuration, not a factory seed."""
    path = Path(path)
    return path.is_file() and not read_saved(path)[1]['factory']


def record_description(name):
    return {"boot.json": "saved boot configuration", "state.json": "running configuration",
            "transaction.json": "commit recovery information", "confirmed.json": "automatic rollback information",
            "scheduled.json": "scheduled commit information"}.get(name, "configuration history")


def atomic_json(path, value, *, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".nvyr-", dir=path.parent)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.chmod(temporary, mode)
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)

        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class Store:
    def __init__(self, directory, *, saved_path=None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.saved_path = Path(saved_path) if saved_path is not None else self.directory / 'boot.json'

        if self.saved_path.is_symlink():
            raise PersistenceError('The saved configuration must not be a symbolic link')

        if self.saved_path != self.directory / 'boot.json' and self.saved_path.exists():
            # Enforce saved-file ownership and permissions on startup.
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                os.chown(self.saved_path, 0, 0)

            self.saved_path.chmod(0o644)

    def path(self, name):
        return self.saved_path if name == 'boot.json' else self.directory / name

    @contextmanager
    def snapshot_lock(self):
        """Image migration copies configd's journal at a durable write boundary."""
        with (self.directory / 'snapshot.lock').open('a') as stream:
            if os.name != 'nt':
                import fcntl

                fcntl.flock(stream, fcntl.LOCK_EX)

            yield

    def read(self, name, default=None):
        path = self.path(name)
        if not path.exists():
            return default

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            return unpack_saved(document)[0] if name == 'boot.json' else document
        except (OSError, ValueError) as error:
            log.exception("Cannot read persistent record %s", path)
            raise PersistenceError(f"Cannot read the {record_description(name)}. Check persistent storage and the system logs before proceeding.") from error

    def write(self, name, value, *, metadata=None):
        try:
            with self.snapshot_lock():
                if name == 'boot.json':
                    value = saved_document(value, metadata=metadata)

                atomic_json(self.path(name), value, mode=0o644 if name == 'boot.json' and self.saved_path != self.directory/'boot.json' else 0o600)
        except OSError as error:
            log.exception("Cannot persist %s", self.directory / name)
            raise PersistenceError(f"Cannot save the {record_description(name)}. Check available storage space, permissions and the system logs.") from error

    def delete(self, name):
        with self.snapshot_lock():
            path = self.path(name)
            path.unlink(missing_ok=True)
            sync_directory(path.parent)

    def record(self, commit_id, configuration, *, reason, user, comment=None):
        name = f"history/{commit_id:020d}.json"
        existing = self.read(name)
        if existing is not None:
            if existing["configuration"] != configuration:
                log.error("Historical commit %s conflicts with the proposed record", commit_id)
                raise PersistenceError("Configuration history is inconsistent. No history was overwritten; check the system logs before proceeding.")

            return

        self.write(name, {"id": commit_id, "configuration": configuration,
                          "reason": reason, "user": user, "comment": comment,
                          "timestamp": time.time(), "format": 1})

    def latest_id(self):
        ids = self.history_ids()
        return ids[-1] if ids else 0

    def history_ids(self):
        return sorted(int(path.stem) for path in (self.directory / "history").glob("*.json")
                      if len(path.stem) == 20 and path.stem.isdecimal())

    def historical(self, commit_id, ago):
        if not isinstance(ago, int) or ago < 0:
            raise PersistenceError("Enter a whole number of commits ago, zero or greater. Use compare ? to see available history.")

        record = self.read(f"history/{commit_id - ago:020d}.json")
        if record is None:
            raise PersistenceError(f"Configuration from {ago} commits ago is not retained. Use compare ? to see available history.")

        return record["configuration"]

    def history_metadata(self, commit_id):
        """Read metadata from retained snapshots; no second history index."""
        for retained_id in reversed(self.history_ids()):
            if retained_id <= commit_id:
                record = self.read(f"history/{retained_id:020d}.json")
                if record is not None:
                    yield {key: value for key, value in record.items() if key != "configuration"}

    def prune(self, retention):
        with self.snapshot_lock():
            for commit_id in self.history_ids()[:-retention]:
                (self.directory / 'history' / f'{commit_id:020d}.json').unlink()
