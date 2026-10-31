"""Consecutive repeats occupy one navigation entry without removing older occurrences."""

import asyncio

from prompt_toolkit.buffer import Buffer
from prompt_toolkit.history import FileHistory, InMemoryHistory

from nvyr.history import NavigationHistory, navigation_histories


def load(history):
    """Exercise prompt-toolkit's lazy loading and cache used by new prompts."""
    async def entries():
        return [entry async for entry in history.load()]

    return asyncio.run(entries())


def test_repeated_commands_take_one_up_arrow_entry():
    history = NavigationHistory(InMemoryHistory())
    history.record('show version')
    for _ in range(30):
        history.record('show interfaces')

    assert load(history) == ['show interfaces', 'show version']
    buffer = Buffer(history=history)
    # Buffer loading is asynchronous; use the normal load task before navigating.
    async def navigate():
        buffer.load_history_if_not_yet_loaded()
        await buffer._load_history_task
        buffer.history_backward()
        assert buffer.text == 'show interfaces'
        buffer.history_backward()
        assert buffer.text == 'show version'

    asyncio.run(navigate())


def test_intervening_command_preserves_another_occurrence():
    history = NavigationHistory(InMemoryHistory())
    history.record('show interfaces')
    history.record('show version')
    history.record('show interfaces')
    history.record('show interfaces')

    assert history.get_strings() == ['show interfaces', 'show version', 'show interfaces']


def test_existing_file_duplicates_collapse_without_rewriting(tmp_path):
    path = tmp_path / 'operational'
    backend = FileHistory(str(path))
    for command in ('show interfaces', 'show interfaces', 'show version',
                    'show interfaces', 'show interfaces'):
        backend.store_string(command)
    original = path.read_bytes()

    history = NavigationHistory(FileHistory(str(path)))
    assert load(history) == ['show interfaces', 'show version', 'show interfaces']
    history.record('show interfaces')
    assert path.read_bytes() == original

    history.record('show vrf')
    history.record('show vrf')
    reopened = NavigationHistory(FileHistory(str(path)))
    assert load(reopened) == ['show vrf', 'show interfaces', 'show version', 'show interfaces']


def test_first_record_checks_saved_tail_and_keeps_modes_separate(tmp_path):
    histories = navigation_histories(tmp_path, persistent=True)
    histories['operational'].record('show interfaces')
    original = (tmp_path / 'operational').read_bytes()

    reopened = navigation_histories(tmp_path, persistent=True)
    reopened['operational'].record('show interfaces')
    reopened['operational'].record('   ')
    assert (tmp_path / 'operational').read_bytes() == original

    reopened['configuration'].record('show interfaces')
    assert load(reopened['operational']) == ['show interfaces']
    assert load(reopened['configuration']) == ['show interfaces']
