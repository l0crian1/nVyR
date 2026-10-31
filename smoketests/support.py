"""Snapshot restoration and bounded observations shared by live smoketests."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import tempfile
import time

from nvyr.config_session import ConfigurationSession


@contextmanager
def defer_interrupt():
    """Finish a configd request or cleanup before delivering Ctrl+C."""
    interrupted = False

    def interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    previous = signal.signal(signal.SIGINT, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)

    if interrupted and callable(previous):
        previous(signal.SIGINT, None)


class SmokeSession(ConfigurationSession):
    """Use the normal API, keeping its RPC connection usable after Ctrl+C."""

    def _request(self, operation, **arguments):
        with defer_interrupt():
            return super()._request(operation, **arguments)


@contextmanager
def preserved_configuration(session, *, directory=None, report=print):
    """Snapshot once; replace and verify running configuration on every exit."""
    session.request_lock(force=True)
    original = session.get_config()

    descriptor, filename = tempfile.mkstemp(prefix='nvyr-smoketest-', suffix='.json', dir=directory)
    snapshot = Path(filename)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        json.dump(original, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())

    try:
        report(f'\nOriginal configuration snapshot: {snapshot}\n')
        yield session
    finally:
        # Never interrupt restoration halfway through or leave an unread RPC reply.
        with defer_interrupt():
            try:
                session.discard()
                session.load(original, replace=True)
                session.commit()
                if session.get_config() != original:
                    raise RuntimeError('Running configuration differs from the original snapshot')
            except BaseException:
                report(f'CONFIGURATION RESTORATION FAILED. Recovery snapshot retained: {snapshot}')
                raise
            else:
                snapshot.unlink()
                report('\nOriginal running configuration restored. Saved configuration was not changed.')


@contextmanager
def prepared_test(session, standup, cleanup, *, stop):
    """Run local setup/cleanup for each function, including setup failures."""
    try:
        standup(session)
        yield
    finally:
        try:
            with defer_interrupt():
                cleanup(session)
        except BaseException:
            stop('Smoketest cleanup failed; stopping tests and restoring the original configuration.')
            raise


@contextmanager
def configuration_case(session, request, baseline):
    """Reset a case in one commit, retaining unchanged suite-owned native objects."""
    try:
        yield
    finally:
        try:
            with defer_interrupt():
                session.discard()
                if session.get_config() != baseline:
                    session.load(baseline, replace=True)
                    session.commit()
        except BaseException:
            request.session.shouldstop = 'Configuration reset failed; stopping tests and restoring the original configuration.'
            raise


def wait_for(read, matches, *, description, timeout=10, interval=0.1):
    """Poll observable host state; report the last observation on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if matches(value):
            return value

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f'Timed out waiting for {description}. Last observation:\n{value}')

        time.sleep(min(interval, remaining))
