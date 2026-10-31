"""Navigation-only history. Prediction code must never import or consult this module."""

import os
from pathlib import Path
from prompt_toolkit.history import History, FileHistory, InMemoryHistory


class NavigationHistory(History):
    """Prompt buffers navigate this history; the dispatcher records each submitted line.

    Disabling automatic buffer appends keeps pasted blocks that switch modes from
    leaking configuration commands into operational history (or vice versa).
    """

    def __init__(self, backend):
        super().__init__()
        self.backend = backend

    def load_history_strings(self):
        previous = None
        for string in self.backend.load_history_strings():
            if string != previous:
                yield string
            previous = string

    def store_string(self, string):
        self.backend.store_string(string)

    def append_string(self, string):
        pass  # Whole prompt buffers are not the unit of history; see record().

    def record(self, string):
        if not string.strip():
            return

        # Consult saved history even if the first prompt has not loaded it yet.
        if not self._loaded:
            self._loaded_strings = list(self.load_history_strings())
            self._loaded = True

        if self._loaded_strings and self._loaded_strings[0] == string:
            return

        super().append_string(string)


def navigation_histories(directory=None, *, persistent=False):
    result = {}

    if persistent:
        directory = Path(directory) if directory is not None else Path(
            os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "nvyr/history"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    for mode in ("operational", "configuration"):
        backend = InMemoryHistory()

        if persistent:
            path = directory / mode
            descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            os.close(descriptor)
            path.chmod(0o600)
            backend = FileHistory(str(path))

        result[mode] = NavigationHistory(backend)

    return result
