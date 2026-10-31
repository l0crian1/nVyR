"""Local automation sessions backed exclusively by configd's Unix socket API."""

import json

from nvyr.errors import RouterError, ValidationError
from nvyr.lexer import split_pipeline
from nvyr.protocol import Client


class CommitError(RouterError):
    """One or more commit units failed; result records partial successes too."""

    def __init__(self, result):
        self.result = result
        failures = [f"{name}: {unit['error']}" for name, unit in result['results'].items() if not unit['success']]
        super().__init__('Commit failed for ' + '; '.join(failures), details=result)


class ConfigurationSession:
    """Open a configuration session; timeout is total lifetime, in seconds.

    set() and delete() take full CLI commands. commit(n) requests an n-second
    rollback deadline; it does not save or confirm automatically. Context exit
    discards uncommitted work and closes the session, without cancelling rollback.
    """

    def __init__(self, *, timeout=300, socket_path='/run/nvyr/configd.sock'):
        self._client = Client(socket_path)

        try:
            self.identity = self._client.request('open', timeout=timeout)
        except BaseException:
            self._client.close()
            self._client = None
            raise

    def _request(self, operation, **arguments):
        if self._client is None:
            raise RouterError('Configuration session is closed')

        return self._client.request(operation, **arguments)

    def _change(self, verb, command):
        if not isinstance(command, str):
            raise ValidationError(f'{verb}() requires a full {verb} command string')

        stages = split_pipeline(command)
        if len(stages) != 1 or stages[0][0].value != verb:
            raise ValidationError(f'{verb}() requires a full {verb} command without pipes')

        return self._request('execute', text=command)

    def set(self, command):
        return self._change('set', command)

    def delete(self, command):
        return self._change('delete', command)

    def get_config(self, source='running'):
        """Return a role-visible running/candidate snapshot, without defaults."""
        return self._request('get_config', source=source)['configuration']

    def load(self, configuration, *, replace=True):
        """Stage a configuration dict; commit() is required to apply it."""
        if not isinstance(configuration, dict):
            raise ValidationError('load() requires a configuration dict')

        try:
            content = json.dumps(configuration, allow_nan=False)
        except (TypeError, ValueError):
            raise ValidationError('load() requires a JSON-serializable configuration dict') from None

        return self._request('load', content=content, replace=replace)

    def commit(self, n=None, *, comment=None):
        result = self._request('commit', n=n, comment=comment)
        if any(not unit['success'] for unit in result['results'].values()):
            raise CommitError(result)

        return result

    def request_lock(self, force=False):
        """Acquire the commit lock; force permits a confirmed takeover."""
        try:
            return self._request('execute', text='request-session-lock')
        except RouterError as error:
            if not force or error.code != 'confirmation_required':
                raise

            owner = error.details['session']

        # Confirm only the observed owner. A changed owner or new commit blocks
        # this request normally; never loop and take an unobserved session's lock.
        return self._request('execute', text='request-session-lock', confirmation={'session': owner})

    def confirm(self):
        """Confirm the pending running revision, including after reconnecting."""
        return self._request('execute', text='confirm')

    def discard(self):
        return self._request('execute', text='discard')

    def save(self):
        return self._request('execute', text='save')

    def exit(self):
        if self._client is not None:
            try:
                self._client.request('close')
            finally:
                self._client.close()
                self._client = None

    def __enter__(self):
        if self._client is None:
            raise RouterError('Configuration session is closed')

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()
