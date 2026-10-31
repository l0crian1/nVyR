"""Reboot and poweroff command mappings. These tests never invoke shutdown."""

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.op_scripts import shutdown


SCHEDULED = "Reboot scheduled for Fri 2026-10-16 10:22:48 UTC, use 'shutdown -c' to cancel.\n"
VISIBLE = "Reboot scheduled for Fri 2026-10-16 10:22:48 UTC\n"

COMMANDS = {
    'reboot': ['shutdown.nvyr.op', 'reboot'],
    'reboot now': ['shutdown.nvyr.op', 'reboot', 'now'],
    'reboot in 15': ['shutdown.nvyr.op', 'reboot', '15'],
    'reboot at 14:30': ['shutdown.nvyr.op', 'reboot', '14:30'],
    'reboot at 6:05': ['shutdown.nvyr.op', 'reboot', '6:05'],
    'reboot cancel': ['shutdown.nvyr.op', 'cancel'],
    'poweroff': ['shutdown.nvyr.op', 'poweroff'],
    'poweroff now': ['shutdown.nvyr.op', 'poweroff', 'now'],
    'poweroff in 15': ['shutdown.nvyr.op', 'poweroff', '15'],
    'poweroff at 06:05': ['shutdown.nvyr.op', 'poweroff', '06:05'],
    'poweroff cancel': ['shutdown.nvyr.op', 'cancel'],
    'show reboot': ['shutdown.nvyr.op', 'show'],
    'show poweroff': ['shutdown.nvyr.op', 'show'],
}


@pytest.fixture
def captured(monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd',
                        lambda argv, **kwargs: calls.append(argv) or 'scheduled\n')

    return calls


@pytest.mark.parametrize('line,argv', COMMANDS.items())
@pytest.mark.parametrize('role', ['sys-admin', 'net-admin'])
def test_commands_map_to_the_shutdown_wrapper(controller, session, captured, line, argv, role):
    token = access.role.set(role)

    try:
        for command, context in ((line, None), ('run ' + line, session)):
            result = controller.execute(command, context)
            if argv[1] in {'reboot', 'poweroff'}:
                assert result['event'] == 'command' and result['argv'] == argv
                assert not captured  # The existing terminal runner owns the prompt.
            else:
                assert result['text'] == 'scheduled\n' and captured == [argv]

            captured.clear()
    finally:
        access.role.reset(token)


@pytest.mark.parametrize('line', [
    'reboot in 0', 'reboot in -5', 'reboot in 15 extra', 'reboot at 24:00',
    'reboot at 12:60', 'reboot at noon', 'reboot at 14:30:00', 'poweroff in',
    'poweroff at', 'reboot cancel now',
])
def test_invalid_shutdown_commands_do_not_run(controller, captured, line):
    with pytest.raises(RouterError):
        controller.execute(line)

    assert captured == []


def test_help_offers_delay_time_and_cancel(controller):
    names = dict(controller.completion('reboot ', explicit=True)['candidates'])

    assert set(names) == {'<Enter>', 'at', 'cancel', 'in', 'now'}
    assert 'minutes' in dict(controller.completion('reboot in ', explicit=True)['hints'])
    assert 'HH:MM' in dict(controller.completion('poweroff at ', explicit=True)['hints'])
    assert {'reboot', 'poweroff'} <= set(dict(controller.completion('show ', explicit=True)['candidates']))


def test_operator_cannot_reboot_or_poweroff(controller, session, captured):
    token = access.role.set('read-only')

    try:
        for line in ('reboot', 'poweroff in 5', 'reboot at 01:00', 'poweroff cancel', 'reboot now', 'poweroff now'):
            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute(line)

            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute('run ' + line, session)

        names = dict(controller.completion('', explicit=True)['candidates'])

        assert 'reboot' not in names and 'poweroff' not in names
        assert controller.execute('show reboot')['text'] == 'scheduled\n'
        assert controller.execute('show poweroff')['text'] == 'scheduled\n'
    finally:
        access.role.reset(token)

    assert captured == [['shutdown.nvyr.op', 'show'], ['shutdown.nvyr.op', 'show']]


def test_wrapper_runs_shutdown_and_drops_the_cancel_hint(monkeypatch):
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        return SCHEDULED

    monkeypatch.setattr(shutdown, 'cmd', fake)
    monkeypatch.setattr(shutdown, 'rc_cmd', lambda argv: (0, fake(argv)))
    monkeypatch.setattr('builtins.input', lambda prompt: 'yes')

    assert shutdown.reboot() == VISIBLE
    assert shutdown.poweroff() == VISIBLE
    assert shutdown.reboot('now') == VISIBLE
    assert shutdown.reboot('1') == VISIBLE
    assert shutdown.poweroff('12:00') == VISIBLE
    assert shutdown.cancel() == SCHEDULED
    assert shutdown.show() == SCHEDULED
    assert calls == [
        ['shutdown', '-r'],
        ['shutdown', '-P'],
        ['shutdown', '-r', 'now'],
        ['shutdown', '-r', '1'],
        ['shutdown', '-P', '12:00'],
        ['shutdown', '-c'],
        ['shutdown', '--show'],
    ]


@pytest.mark.parametrize('function', [shutdown.reboot, shutdown.poweroff])
@pytest.mark.parametrize('when', [None, 'now', '15', '06:05'])
@pytest.mark.parametrize('answer', ['', 'n', 'no', 'anything else'])
def test_confirmation_defaults_to_no(monkeypatch, function, when, answer):
    prompts = []
    monkeypatch.setattr('builtins.input', lambda text: prompts.append(text) or answer)
    monkeypatch.setattr(shutdown, 'cmd', lambda *args: pytest.fail('Declined shutdown must not run'))

    assert function(when) == 'Command cancelled.\n'
    assert len(prompts) == 1 and prompts[0].endswith('[y/N] ')


@pytest.mark.parametrize('exception', [EOFError, KeyboardInterrupt])
def test_interrupted_prompt_cancels_without_shutdown(monkeypatch, exception, capsys):
    from nvyr import opmode

    def interrupted(prompt):
        raise exception

    monkeypatch.setattr('builtins.input', interrupted)
    monkeypatch.setattr(shutdown, 'cmd', lambda *args: pytest.fail('Cancelled shutdown must not run'))
    with pytest.raises(SystemExit) as error:
        opmode.run(['reboot'], namespace=vars(shutdown))

    assert error.value.code == 130
    assert capsys.readouterr().err == '\nCommand cancelled.\n'


def test_unscheduled_shutdown_returns_native_message_without_wrappers(tmp_path, monkeypatch, controller, caplog):
    import os
    import shutil
    import sys
    from build_tools.op_scripts import install_scripts

    source, bindir = tmp_path/'scripts', tmp_path/'bin'
    source.mkdir()
    shutil.copyfile(shutdown.__file__, source/'shutdown.py')
    install_scripts(source, bindir)
    executable = bindir/'shutdown'
    executable.write_text('#!' + sys.executable + '\nimport sys\n'
                          'assert sys.argv[1:] == ["--show"]\n'
                          'print("No scheduled shutdown.", file=sys.stderr)\nraise SystemExit(1)\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ['PATH'])

    assert shutdown.show() == 'No scheduled shutdown.\n'

    for line in ('show reboot', 'show poweroff'):
        assert controller.execute(line)['text'] == 'No scheduled shutdown.\n'

    assert not caplog.records
