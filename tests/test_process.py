"""Real subprocesses and PTYs test output delivery, terminal ownership and signals."""

import os
import pty
import select
import signal
import sys
import time

import pytest

from nvyr.helpers.process import cmd, run, call, rc_cmd, CommandError
from nvyr.errors import RouterError


def test_captured_helpers_return_their_documented_types(tmp_path):
    argv = [sys.executable, '-c', 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(3)']

    assert rc_cmd(argv) == (3, 'out\nerr\n')

    with pytest.raises(CommandError, match='out\nerr') as error:
        cmd(argv)

    assert error.value.details['returncode'] == 3
    assert run(argv) == 3
    assert cmd([sys.executable, '-c', 'import os; print(os.getcwd()); print(os.environ["EXAMPLE"])'],
               cwd=tmp_path, env=dict(os.environ, EXAMPLE='value')) == str(tmp_path) + '\nvalue\n'

    with pytest.raises(CommandError, match='command not found'):
        run(['/no-such-nvyr-command'])

    with pytest.raises(CommandError, match='did not finish'):
        run([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)


def test_streaming_is_incremental_and_does_not_duplicate_output(capfd):
    assert cmd([sys.executable, '-c', 'print("visible")'], stream=True) == ''
    assert capfd.readouterr().out == 'visible\n'
    assert rc_cmd([sys.executable, '-c', 'print("failure"); raise SystemExit(7)'], stream=True) == (7, '')
    assert capfd.readouterr().out == 'failure\n'


def test_cmd_returns_command_data_as_text():
    import json

    output = cmd([sys.executable, '-c', 'print(\'{"interfaces": []}\')'])

    assert json.loads(output) == {'interfaces': []}


def test_streamed_cancellation_does_not_log_command_as_failure(caplog):
    assert run([sys.executable, '-c', 'raise SystemExit(130)'], stream=True) == 130
    assert not caplog.records


def test_ssh_default_runner_still_reads_exit_status(tmp_path, monkeypatch):
    from nvyr.helpers.ssh import Manager

    executable = tmp_path / 'systemctl'
    executable.write_text('#!' + sys.executable + '\nimport sys\nraise SystemExit(0 if sys.argv[-1] == "active" else 3)\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path))
    manager = Manager(tmp_path)

    assert manager._active('active') is True
    assert manager._active('inactive') is False


def test_account_default_runner_still_checks_revocation_status(tmp_path, monkeypatch):
    from nvyr.helpers.accounts import Manager

    for name in ('loginctl', 'pkill'):
        executable = tmp_path / name
        executable.write_text('#!' + sys.executable + '\nimport sys\nraise SystemExit(1 if sys.argv[-1] == "424242" else 2)\n')
        executable.chmod(0o755)

    # Only these test executables can be found; no host session is touched.
    monkeypatch.setenv('PATH', str(tmp_path))
    manager = Manager()
    manager._terminate(424242)

    with pytest.raises(RouterError, match='terminate sessions'):
        manager._terminate(424243)


def read_until(fd, marker, timeout=5):
    data = b''
    deadline = time.monotonic() + timeout

    while marker not in data and time.monotonic() < deadline:
        if select.select([fd], [], [], .05)[0]:
            try:
                data += os.read(fd, 65536)
            except OSError:
                break

    assert marker in data, data.decode(errors='replace')

    return data


def spawn_terminal(source):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, '-c', source])

    return pid, descriptor


def cleanup(pid, descriptor):
    os.close(descriptor)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    os.waitpid(pid, 0)


def test_terminal_streams_before_exit_and_ctrl_c_restores_terminal():
    child = ('import os,time,signal; '
             'signal.signal(signal.SIGINT, lambda *a: exit(130)); '
             'print("TTY", os.isatty(0), os.isatty(1), flush=True); '
             'print("FIRST", flush=True); time.sleep(20); print("LATE")')
    source = ('import sys,os; from nvyr.helpers.process import call; '
              f'rc=call([sys.executable,"-c",{child!r}]); '
              'print("RETURNED",rc,os.tcgetpgrp(0)==os.getpgrp(),flush=True); '
              'print("INPUT",input(),flush=True)')
    pid, descriptor = spawn_terminal(source)

    try:
        output = read_until(descriptor, b'FIRST')

        assert b'TTY True True' in output and b'LATE' not in output and b'RETURNED' not in output

        os.write(descriptor, b'\x03')
        output = read_until(descriptor, b'RETURNED 130 True')

        assert b'Traceback' not in output

        os.write(descriptor, b'after-interrupt\n')
        read_until(descriptor, b'INPUT after-interrupt')
    finally:
        cleanup(pid, descriptor)


def test_terminal_input_and_nonzero_status():
    child = 'import sys; print("READY",flush=True); print("GOT",input(),flush=True); sys.exit(7)'
    pid, descriptor = spawn_terminal('import sys; from nvyr.helpers.process import run; '
        f'rc=run([sys.executable,"-c",{child!r}],stream=True,timeout=5); print("RETURNED",rc,flush=True)')

    try:
        read_until(descriptor, b'READY')
        os.write(descriptor, b'terminal input\n')

        assert b'GOT terminal input' in read_until(descriptor, b'RETURNED 7')
    finally:
        cleanup(pid, descriptor)


def test_streaming_timeout_kills_command_and_restores_foreground(tmp_path):
    marker = tmp_path / 'child.pid'
    child = f'import os,time; open({str(marker)!r},"w").write(str(os.getpid())); time.sleep(20)'
    source = ('import sys,os; from nvyr.helpers.process import run,CommandError\n'
              f'try: run([sys.executable,"-c",{child!r}],stream=True,timeout=.5)\n'
              'except CommandError: print("TIMED_OUT",os.tcgetpgrp(0)==os.getpgrp(),flush=True)\n')
    pid, descriptor = spawn_terminal(source)

    try:
        read_until(descriptor, b'TIMED_OUT True')

        with pytest.raises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)
    finally:
        cleanup(pid, descriptor)


def test_nested_streaming_wrapper_shares_cli_group_for_cancellation():
    utility = 'import time,signal; signal.signal(signal.SIGINT, lambda *a: exit(130)); print("READY",flush=True); time.sleep(20)'
    wrapper = ('import sys; from nvyr.helpers.process import run; '
               f'raise SystemExit(run([sys.executable,"-c",{utility!r}],stream=True,timeout=None,new_process_group=False))')
    parent = ('import sys,os; from nvyr.helpers.process import run; '
              f'rc=run([sys.executable,"-c",{wrapper!r}],stream=True,timeout=None); '
              'print("RETURNED",rc,os.tcgetpgrp(0)==os.getpgrp(),flush=True)')
    pid, descriptor = spawn_terminal(parent)

    try:
        read_until(descriptor, b'READY')
        os.write(descriptor, b'\x03')
        output = read_until(descriptor, b'RETURNED 130 True')

        assert b'Traceback' not in output
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('status', [0, 1, 2, 130])
def test_cmd_captures_native_messages_without_printing_or_logging(status, capfd, caplog):
    program = 'import sys; print("Device does not exist.", file=sys.stderr); sys.exit(' + str(status) + ')'
    argv = [sys.executable, '-c', program]

    if status:
        with pytest.raises(CommandError, match='Device does not exist.') as error:
            cmd(argv)

        assert error.value.details['returncode'] == status
        assert capfd.readouterr() == ('', '')
        assert not caplog.records

        return

    cmd(argv)  # Ignoring successful output must stay silent too.
    text = cmd(argv)

    assert text == 'Device does not exist.\n'
    assert capfd.readouterr() == ('', '')
    assert not caplog.records

    print(text, end='')

    assert capfd.readouterr() == ('Device does not exist.\n', '')


def test_cmd_streamed_failure_raises_without_printing_or_logging(capfd, caplog):
    with pytest.raises(CommandError, match='exit status 130') as error:
        cmd([sys.executable, '-c', 'raise SystemExit(130)'], stream=True)

    assert error.value.details['returncode'] == 130
    assert capfd.readouterr() == ('', '')
    assert not caplog.records


@pytest.mark.parametrize('status', [0, 1, 2, 7, 130])
def test_run_returns_only_program_status_without_output_or_logging(status, capfd, caplog):
    assert run([sys.executable, '-c',
                    f'import sys; print("output"); print("diagnostic", file=sys.stderr); sys.exit({status})']) == status
    assert capfd.readouterr() == ('', '')
    assert not caplog.records


def test_account_creation_handles_unsuccessful_exit_before_password_changes(tmp_path, monkeypatch):
    from nvyr.helpers import accounts

    calls = []
    manager = accounts.Manager(run=lambda argv: calls.append(argv) or 9)
    monkeypatch.setattr(manager, 'verify', lambda *args: None)
    monkeypatch.setattr(manager, 'account', lambda name: None)
    monkeypatch.setattr(manager, 'ledger', lambda directory: (tmp_path/'accounts.json', {'admin': {'uid': 424242}}))

    def missing(uid):
        raise KeyError(uid)

    monkeypatch.setattr(accounts.pwd, 'getpwuid', missing)

    with pytest.raises(RouterError, match='Could not create user admin'):
        manager._install({'admin': {'role': 'sys-admin'}}, tmp_path)

    assert [argv[0] for argv in calls] == ['useradd']


def test_failed_mount_never_enters_installation_body(tmp_path, monkeypatch):
    from tempfile import TemporaryDirectory
    from nvyr.helpers import installation

    calls = []
    monkeypatch.setattr(installation, 'run', lambda argv, **options: calls.append(argv) or 32)

    # Only the mount failure is under test; no privileged /run directory is needed.
    monkeypatch.setattr(installation.tempfile, 'TemporaryDirectory',
                        lambda **options: TemporaryDirectory(prefix=options['prefix'], dir=tmp_path))

    with pytest.raises(RouterError, match='Could not mount'):
        with installation.mounted('/nonexistent-nvyr-test-device'):
            pytest.fail('A failed mount must not be treated as an installation target')

    assert [argv[0] for argv in calls] == ['mount']


def test_failed_persistent_copy_is_reported_by_the_caller(tmp_path, monkeypatch):
    from nvyr.helpers import image_migration

    monkeypatch.setattr(image_migration, 'run', lambda *args, **options: 23)

    with pytest.raises(RouterError, match='Could not copy persistent files'):
        image_migration.copy_directory(tmp_path/'source', tmp_path/'destination')


@pytest.mark.parametrize('status', [0, 7, 130])
def test_call_displays_native_output_and_returns_status(status, capfd, caplog):
    argv = [sys.executable, '-c',
            f'import sys; print("output"); print("diagnostic", file=sys.stderr); sys.exit({status})']

    assert call(argv) == status
    assert capfd.readouterr() == ('output\n', 'diagnostic\n')
    assert not caplog.records


def test_operational_failure_reports_native_diagnostic_once(controller, capfd, caplog):
    command = [sys.executable, '-c',
               'import sys; print("Native diagnostic.", file=sys.stderr); sys.exit(1)']
    controller.operational.root['children']['show']['children']['version']['command'] = {'argv': command}

    with pytest.raises(CommandError) as error:
        controller.execute('show version')

    assert str(error.value) == 'Native diagnostic.'
    assert error.value.details['returncode'] == 1
    assert capfd.readouterr() == ('', '')
    assert not caplog.records
