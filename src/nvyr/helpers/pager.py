"""Client-side paging of completed output using the invoking user's terminal."""

import os
import sys

from nvyr.errors import RouterError
from nvyr.helpers.process import call


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'


def show(path, *, length=None):
    # Do not allow user settings to enable shell escapes, external preprocessors,
    # file browsing or persistent search history in restricted CLI sessions.
    env = {key: value for key, value in os.environ.items() if not key.startswith('LESS')}
    env.update(LESSSECURE='1', LESSHISTFILE='-')

    if length is not None:
        # less reserves one screen row for its prompt.
        env['LESS_LINES'] = str(length + 1)

    # Exit on reaching the final page, leaving the displayed output on screen.
    status = call(['less', '-E', '-F', '-X', '-K', '-P', r'Space\: next page  /\: search  n\: next match  q\: quit',
                   '--', str(path)], env=env)

    # less -K uses 2 for a keyboard interrupt; the process helper uses 130.
    if status not in {0, 2, 130}:
        raise RouterError('Unable to display paged output. Use | no-more to print it directly.')
