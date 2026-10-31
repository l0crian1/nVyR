"""One safe subprocess boundary for trusted operational command definitions."""

from dataclasses import dataclass
import logging
import os
import signal
import subprocess
import re
import sys

from nvyr.errors import RouterError, ParseError
from nvyr.lexer import lex

log = logging.getLogger(__name__)


def operational_argv(command, tokens, line, *, omitted_positions=()):
    """Expand whole argv entries, never shell text or recursively expanded values."""
    template = command['argv']

    if any(argument == '@line' or argument.startswith('@line-') for argument in template):
        pipe = next((token for token in lex(line) if token.pipe), None)
        if pipe is not None:
            line = line[:pipe.start].rstrip()

    if omitted_positions:
        # The parser knows whether the optional value was consumed. A child
        # keyword in that token slot must not accidentally become its value.
        omitted = set()
        placeholders = {f'@{position}' for position in omitted_positions}

        for index, argument in enumerate(template):
            if argument in placeholders:
                omitted.add(index)

                if index > 1 and re.fullmatch(r'--?[a-zA-Z][a-zA-Z0-9_-]*', template[index - 1]):
                    omitted.add(index - 1)

        template = [arg for index, arg in enumerate(template) if index not in omitted]

    argv = []

    for argument in template:
        if argument == '@line':
            argv.append(line)
        elif argument.startswith('@@'):
            argv.append(argument[1:])
        elif exclusion := re.fullmatch(r'@line-([1-9][0-9]*)(?:-([1-9][0-9]*))?', argument):
            first, last = exclusion[1], exclusion[2] or exclusion[1]

            for number in (first, last):
                if len(number) > len(str(len(tokens))) or int(number) > len(tokens):
                    raise ParseError(f'Operational command requires input token {number}, but it was not supplied')

            first, last = int(first), int(last)
            if first > last:
                raise ParseError(f'Invalid operational exclusion {argument!r}; range must be ascending')

            # Source spans preserve quoting and all text outside the excluded
            # range, including a configuration-mode run prefix.
            argv.append(line[:tokens[first - 1].start] + line[tokens[last - 1].end:])
        elif re.fullmatch(r'@[1-9][0-9]*', argument):
            number = argument[1:]
            if len(number) > len(str(len(tokens))) or int(number) > len(tokens):
                raise ParseError(f'Operational command requires input token {number}, but it was not supplied')

            argv.append(tokens[int(number) - 1].value)
        elif argument.startswith('@'):
            raise ParseError(f'Invalid operational placeholder {argument!r}; use @1, @2, ... , @line, @line-N or @line-N-M')
        else:
            argv.append(argument)

    if template[0].startswith('@') and not template[0].startswith('@@'):
        raise ParseError('An operational executable or function name must be fixed in the schema')

    return argv


class CommandError(RouterError):
    code = "command"


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


def _foreground(group, descriptor):
    # A parent outside the foreground group must not stop itself on tcsetpgrp.
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU})

    try:
        os.tcsetpgrp(descriptor, group)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


def _terminal(argv, *, timeout, cwd, env, new_process_group):
    """Inherit the terminal; isolate the command's process group for cancellation."""
    descriptor, foreground = None, None

    if os.name == 'posix' and new_process_group:
        try:
            descriptor = sys.stdin.fileno()
            if os.isatty(descriptor) and os.tcgetpgrp(descriptor) == os.getpgrp():
                foreground = os.getpgrp()
        except (OSError, ValueError, AttributeError):
            descriptor = None

    child = subprocess.Popen(argv, cwd=cwd, env=env, shell=False,
                             **({'process_group': 0} if os.name == 'posix' and new_process_group else {}))

    def send(sig):
        try:
            if os.name == 'posix' and new_process_group:
                os.killpg(child.pid, sig)
            else:
                child.send_signal(sig)
        except ProcessLookupError:
            pass

    try:
        if foreground is not None:
            _foreground(child.pid, descriptor)

            # A command reading stdin before the handoff may have received SIGTTIN.
            send(signal.SIGCONT)

        try:
            returncode = child.wait(timeout=timeout)
        except KeyboardInterrupt:
            send(signal.SIGINT)

            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

            # Also clean up descendants if the script exited before its child.
            send(signal.SIGKILL)
            child.wait()
            returncode = 130

        return CommandResult('', '', 128 - returncode if returncode < 0 else returncode)
    except BaseException:
        send(signal.SIGKILL)
        child.wait()
        raise
    finally:
        if foreground is not None:
            _foreground(foreground, descriptor)


def cli_cmd(argv, *, timeout=15, stream=False, cwd=None, env=None, new_process_group=True):
    """Shared subprocess implementation used by the public execution helpers.

    Captured mode has no stdin. Streaming inherits stdin/stdout/stderr and returns
    empty output fields: the terminal, not a pipe/tee, owns those bytes. None disables
    the timeout. No shell expansion is performed.
    """
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(arg, str) for arg in argv):
        raise ValueError("command requires a nonempty argument list")

    try:
        if stream:
            result = _terminal(argv, timeout=timeout, cwd=cwd, env=env, new_process_group=new_process_group)
        else:
            options = {}

            if cwd is not None:
                options['cwd'] = cwd

            if env is not None:
                options['env'] = env

            if os.name == 'posix' and new_process_group:
                options['process_group'] = 0

            with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, errors="replace",
                                  shell=False, **options) as process:
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except BaseException:
                    # A captured operational script can wrap a streaming utility.
                    # Stop its descendants too, so a timeout cannot leave ping running.
                    try:
                        if os.name == 'posix' and new_process_group:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except ProcessLookupError:
                        pass

                    process.communicate()
                    raise

                result = CommandResult(stdout, stderr,
                                       128 - process.returncode if process.returncode < 0 else process.returncode)
    except FileNotFoundError as error:
        raise CommandError(f"Cannot run {argv[0]!r}: command not found. Install the required software to use this command.") from error
    except subprocess.TimeoutExpired as error:
        log.warning("Operational command timed out: %r", argv)
        raise CommandError(f"{argv[0]!r} did not finish within {timeout:g} seconds. Try again or check the service.") from error
    except OSError as error:
        log.exception("Cannot execute operational command %r", argv)
        raise CommandError(f"Cannot run {argv[0]!r}: {error.strerror or 'execution unavailable'}.") from error

    return result


def cmd(argv, **options):
    """Return captured output on success; raise CommandError on a nonzero exit.

    Use print(cmd(...)) or return its text from an operational command to display it.
    Streaming explicitly sends output to the terminal and returns ''; use
    run() or rc_cmd() when the caller needs to handle the exit status itself.
    """
    result = cli_cmd(argv, **options)
    output = result.stdout + result.stderr

    if result.returncode:
        raise CommandError(output.strip() or f'{argv[0]!r} failed (exit status {result.returncode}).',
                           details={'returncode': result.returncode})

    return output


def run(argv, **options):
    """Return the exit status (including 128+signal); optionally inherit the terminal."""
    return cli_cmd(argv, **options).returncode


def call(argv, *, timeout=None, **options):
    """Run in the terminal with live output and return the program's exit code."""
    return cli_cmd(argv, stream=True, timeout=timeout, **options).returncode


def rc_cmd(argv, **options):
    """Return (exit status, output). Streaming output is displayed, not retained."""
    result = cli_cmd(argv, **options)
    return result.returncode, result.stdout + result.stderr


def interactive_shell():
    """Run in the CLI user's terminal, after prompt_toolkit has released it."""
    from nvyr.login import local_role

    if local_role() != 'dev-admin':
        raise RouterError('Linux shell access requires dev-admin access')

    shell = '/bin/bash'

    try:
        # Start with normal signal handling, then let the foreground child handle
        # Ctrl-C while its parent waits. No pipes, timeout, new session or privilege change.
        child = subprocess.Popen([shell, "-i"])
    except OSError as error:
        raise CommandError(f"Cannot start host shell {shell!r}: {error.strerror or 'execution unavailable'}.") from error

    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        return child.wait()
    finally:
        signal.signal(signal.SIGINT, previous)
