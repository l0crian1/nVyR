"""prompt_toolkit view/controller. All configuration and predictions stay in configd."""

import argparse
import asyncio
from contextlib import contextmanager
import getpass
import os
from pathlib import Path
import signal
import socket
import tempfile

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.application import run_in_terminal, get_app
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from tabulate import tabulate

from nvyr.errors import RouterError, SessionExpiredError
from nvyr.lexer import lex, split_pipeline, load_arguments, quote
from nvyr.protocol import Client
from nvyr.schema import Schema, completion_sort_key, resolve_word
from nvyr.history import navigation_histories
from nvyr.helpers.process import interactive_shell
from nvyr.helpers.passwords import sensitive_line
from nvyr.helpers import pager


def error_text(error, line, number=None):
    if isinstance(error, SessionExpiredError):
        return str(error)

    if sensitive_line(line):
        return 'Credential command failed; check the path, role and password format (input omitted)'

    if number is None:
        return str(error)

    start = error.start
    if start is None and error.token:
        start = line.find(error.token)

    pointer = "" if start is None or start < 0 else "\n  " + " " * start + "^" * max(1, len(error.token or ""))

    return f"Line {number}: {error}\n  {line}{pointer}"


def file_error(error):
    path = repr(error.filename) if error.filename else "the requested file"

    if isinstance(error, FileNotFoundError):
        return f"Cannot open {path}: it does not exist. Check the file path and try again."

    if isinstance(error, PermissionError):
        return f"Access denied for {path}. Choose a location your account can read or write."

    return f"Cannot read or write {path}: {error.strerror or 'file access failed'}."


def completion_rows(result):
    """Order help for display without changing completion candidates or hints."""
    candidates = result.get('candidates', [])
    suggested = set(result.get('suggested', []))
    enter = [row for row in candidates if row[0] == '<Enter>']
    schema = [(name, description) for name, description in candidates
              if name != '<Enter>' and name not in suggested]
    discovered = [row for row in candidates if row[0] != '<Enter>' and row[0] in suggested]

    # Keep value hints above choices and suggestions, sorting their original labels.
    hints = sorted(result.get('hints', []), key=lambda row: completion_sort_key(row[0]))
    rows = [(f'<{name}>', description) for name, description in hints]

    rows += sorted(schema, key=lambda row: completion_sort_key(row[0]))
    rows += sorted(discovered, key=lambda row: completion_sort_key(row[0]))

    if not result.get('groups'):
        return enter + rows

    grouped = list(enter)
    # Print outer scopes first so the closest context stays beside the prompt.
    for group in reversed(result['groups']):
        names = set(group['candidates'])
        title = (f"Current context: {group['name']}" if group['current'] else
                 f"Other {group['name']} parameters:")
        if grouped:
            grouped.append(('', ''))

        grouped.append((title, ''))
        grouped.extend(row for row in rows if row[0] in names or (
            group['current'] and row[0].startswith('<')))

    return grouped


class TreeSuggestion(AutoSuggest):
    def __init__(self, cli):
        self.cli = cli

    def get_suggestion(self, buffer, document):
        if not document.is_cursor_at_the_end:
            return None

        try:
            result = self.cli.client.request("complete", text=document.text_before_cursor)
            suffix = result.get("extension", "")

            return Suggestion(suffix) if suffix else None
        except (RouterError, OSError, EOFError):
            return None


class CLI:
    def __init__(self, client, *, ask=None, emit=print):
        self.client, self.ask, self.emit = client, ask or self._ask, emit
        self.mode, self.edit, self.done = None, [], False
        self.histories = navigation_histories()
        self.session_id, self.commit_id, self.event_cursor = None, None, None
        self.session_expired = False
        self.hostname = None
        self.returncode = 0
        self.terminal_length = None
        self.control_schema = Schema.bundled('control')
        self._insertion_interrupted = False

    @contextmanager
    def _request_interrupts(self, tokens):
        """Finish an in-flight configuration RPC without abandoning its frame."""
        command = None
        insertion = False

        if self.mode and tokens:
            children = self.control_schema.root['children']

            try:
                node = children[resolve_word(tokens[0].value, children)]
                command = node.get('command')
                insertion = node.get('path') in {'configuration', 'rename', 'copy', 'load'} or command == 'rollback'

                if command == 'commit':
                    command = self.control_schema.resolve(tokens).node.get('command')
            except RouterError:
                # The daemon remains responsible for reporting invalid commands.
                command = None

        committing = command in {'commit', 'commit-confirm'}
        if not committing and not insertion:
            yield
            return

        def interrupt(signum, frame):
            if committing:
                self.emit('Commit in progress')
            else:
                self._insertion_interrupted = True

        previous = signal.signal(signal.SIGINT, interrupt)
        try:
            yield
        finally:
            signal.signal(signal.SIGINT, previous)

    @staticmethod
    def _ask(message):
        return input(message + " [y/N] ").strip().lower() in {"y", "yes"}

    def prompt(self):
        prefix = f"{getpass.getuser()}@{self.hostname or socket.gethostname()}"
        return prefix + ("(draft)# " if self.mode == "draft" else "# " if self.mode else ":~$ ")

    def execute_line(self, line, number=None):
        try:
            if not line.strip():
                return

            try:
                if not sensitive_line(line):
                    self.histories["configuration" if self.mode else "operational"].record(line)
            except OSError:
                self.emit("Command history could not be saved. This command will still be processed.")

            stages = split_pipeline(line)
            tokens = stages[0]
            if self.mode and "load".startswith(tokens[0].value):
                path, replace, set_format = load_arguments([t.value for t in tokens[1:]])

                if len(stages) != 1:
                    raise RouterError("Expected load [replace] [set] <file>")

                content = Path(path).read_text(encoding="utf-8")

                with self._request_interrupts(tokens):
                    result = self.client.request("load", content=content, set_format=set_format, replace=replace)

                for error in result["errors"]:
                    self.emit(error_text(RouterError(error["message"], token=error["token"], start=error["start"]), error["command"], error["line"]))

                return

            # Stream output into a client-local temporary file when exporting. No
            # client snapshot, and no privileged daemon file access on behalf of users.
            export = None

            if len(stages) > 1 and "export".startswith(stages[-1][0].value):
                if len(stages[-1]) == 2:
                    export = Path(stages[-1][1].value)

            stream, temporary, page = None, None, None

            try:
                if export:
                    descriptor, temporary = tempfile.mkstemp(prefix=".nvyr-export-", dir=export.parent)
                    stream = os.fdopen(descriptor, "w", encoding="utf-8")

                display_command = not self.mode or resolve_word(tokens[0].value, self.control_schema.root['children']) in {'show', 'compare', 'run'}
                if not export and display_command and self.emit is print and pager.interactive():
                    page = tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', prefix='nvyr-output-')

                def direct_output(chunk):
                    if self.emit is print:
                        print(chunk, end="", flush=True)
                    else:
                        self.emit(chunk)

                def output(chunk):
                    if stream:
                        stream.write(chunk)
                    elif page:
                        page.write(chunk)
                    else:
                        direct_output(chunk)

                confirmation = None

                while True:
                    try:
                        with self._request_interrupts(tokens):
                            result = self.client.request("execute", text=line, confirmation=confirmation,
                                                         on_text=output, on_terminal=direct_output)

                        break
                    except RouterError as error:
                        if error.code != "confirmation_required":
                            raise

                        if not self.ask(str(error)):
                            return

                        confirmation = (confirmation or {}) | error.details

                if page and page.tell():
                    page.flush()
                    paging = result.get('paging')
                    if paging is False or (self.terminal_length == 0 and paging is not True):
                        page.seek(0)
                        while chunk := page.read(32768):
                            direct_output(chunk)
                    else:
                        # Consume the complete RPC response before opening the
                        # pager, so quitting cannot leave unread frames.
                        pager.show(page.name, length=self.terminal_length or None)

                if stream:
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.close()
                    os.replace(temporary, export)
                    temporary = None

                event = result.get("event")
                if event in {"configure", "configure-draft"}:
                    opened = self.client.request("open", draft=event == "configure-draft")
                    self.session_id, self.commit_id = opened["session"], opened["commit_id"]
                    self.session_expired = False
                    self.mode = "draft" if event == "configure-draft" else "normal"
                elif event == "leave":
                    self.mode = None
                    self.session_id = None
                elif event == "exit":
                    self.done = True
                elif event == "shell":
                    interactive_shell()
                    self.receive_status(self.client.request("status", after=self.event_cursor))
                elif event == 'terminal-length':
                    self.terminal_length = result['length']
                elif event == "command":
                    # Execution and terminal relay completed inside the RPC request.
                    self.returncode = result['returncode']
                elif "commit_id" in result:
                    self.commit_id = result["commit_id"]

                self.edit = result.get("edit", [])
            finally:
                if page:
                    page.close()

                if stream and not stream.closed:
                    stream.close()

                if temporary:
                    os.unlink(temporary)
        except (ConnectionError, EOFError) as error:
            self.done = True
            self.emit(error_text(RouterError("Connection to the router was lost. Reconnect and check running configuration before retrying this command."), line, number))
        except (RouterError, OSError, UnicodeError) as error:
            if isinstance(error, OSError):
                error = RouterError(file_error(error))
            elif isinstance(error, UnicodeError):
                error = RouterError("This file is not valid UTF-8 text. Save it as UTF-8 and load it again.")

            self.emit(error_text(error, line, number))
        finally:
            if self.mode and self.edit:
                self.emit(self.edit_context())

    def edit_context(self):
        return "[edit " + " ".join(map(quote, self.edit)) + "]"

    def receive_status(self, status):
        """Acknowledge only after display, so prompt cancellation cannot lose an event."""
        # The session's UTS namespace keeps its launch-time hostname. Configd
        # supplies the live host name so commits also update isolated prompts.
        hostname = status.get('hostname', self.hostname)
        if hostname != self.hostname:
            self.hostname = hostname
            get_app().invalidate()

        for event in status["events"]:
            if self.event_cursor is None or event["id"] > self.event_cursor:
                self.emit(event["message"])
                self.event_cursor = event["id"]

        self.event_cursor = status["event_id"]

        if status["session"] == self.session_id:
            if status.get('session_expired') and not self.session_expired:
                self.emit('Configuration session expired. Exit configuration mode and open a new session.')
                self.session_expired = True

            self.commit_id = status["session_commit_id"]
            self.edit = status["edit"]

    async def watch_notifications(self, interval=0.5):
        while True:
            try:
                status = await asyncio.to_thread(self.client.request, "status", after=self.event_cursor)
                if status["events"] or (status.get('session_expired') and not self.session_expired):
                    await run_in_terminal(lambda: self.receive_status(status))
                else:
                    self.receive_status(status)
            except (OSError, EOFError, RouterError):
                await run_in_terminal(lambda: self.emit("Connection to the router's configuration service was lost. Reconnect to continue."))
                self.done = True

                if get_app().is_running:
                    get_app().exit(result="")

                return

            await asyncio.sleep(interval)

    def submit(self, text):
        lines = text.splitlines() or [""]
        self._insertion_interrupted = False

        try:
            for number, line in enumerate(lines, 1):
                self.execute_line(line, number if len(lines) > 1 else None)

                if self.done or self._insertion_interrupted:
                    break
        except KeyboardInterrupt:
            if not self.mode or len(lines) == 1:
                raise

            self._insertion_interrupted = True

        if self._insertion_interrupted:
            self.emit('Command insertion interrupted. Changes already accepted remain in the candidate.\n\n'
                      'Use compare to review them before committing.')

    def bindings(self):
        bindings = KeyBindings()

        def complete(buffer, **options):
            text = buffer.document.text_before_cursor

            try:
                return self.client.request("complete", text=text, **options)
            except RouterError as error:
                message = error_text(error, text)
                run_in_terminal(lambda: self.emit(message))
                return None

        def possible(buffer, result=None):
            if result is None:
                result = complete(buffer, explicit=True)

            if result is None:
                return

            rows = result.get("candidates", [])
            suffix = f"\nShowing {len(rows)} of {result['total']} matches; type a longer prefix." if result.get("total", 0) > len(rows) else ""
            rows = completion_rows(result)

            # Capture the input now: terminal output is deferred while editing continues.
            context = self.prompt() + buffer.document.text
            output = context + "\n\nPossible completions:\n" + tabulate(rows, tablefmt="plain") + suffix + "\n"
            run_in_terminal(lambda: print_formatted_text(output))

        @bindings.add("?")
        def question(event):
            # A question mark inside a quoted value is ordinary text.
            try:
                lex(event.current_buffer.document.text_before_cursor)
            except RouterError:
                event.current_buffer.insert_text("?")
                return

            possible(event.current_buffer)

        @bindings.add("tab")
        def tab(event):
            buffer = event.current_buffer
            result = complete(buffer, tab=True)

            if result is None:
                return

            line = buffer.document.current_line_before_cursor

            if result.get("display"):
                possible(buffer, result)
            elif result.get("unique") and result.get("replacement") is not None:
                buffer.delete_before_cursor(len(line) - result["start"])
                buffer.insert_text(result["replacement"] + " ")
            elif result.get("extension"):
                buffer.insert_text(result["extension"])
            else:
                possible(buffer)

        @bindings.add(" ")
        def space(event):
            buffer = event.current_buffer

            try:
                lex(buffer.document.text_before_cursor)
                result = self.client.request("complete", text=buffer.document.text_before_cursor, space=True)
                if result.get("replacement") is not None:
                    line = buffer.document.current_line_before_cursor
                    buffer.delete_before_cursor(len(line) - result["start"])
                    buffer.insert_text(result["replacement"])
            except RouterError:
                pass

            buffer.insert_text(" ")

        @bindings.add(Keys.BracketedPaste)
        def paste(event):
            event.current_buffer.insert_text(event.data.replace("\r\n", "\n").replace("\r", "\n"))

        @bindings.add("enter")
        def enter(event):
            event.current_buffer.validate_and_handle()

        return bindings

    def make_prompts(self, **options):
        return {mode: PromptSession(history=history, auto_suggest=TreeSuggestion(self),
                                    key_bindings=self.bindings(), multiline=True,
                                    complete_while_typing=False, enable_history_search=False,
                                    enable_system_prompt=False, enable_open_in_editor=False,
                                    **options)
                for mode, history in self.histories.items()}

    def interact(self, history_directory=None):
        try:
            self.histories = navigation_histories(history_directory, persistent=True)
        except OSError:
            self.emit("Persistent command history is unavailable; navigation will use this connection's history.")

        prompts = self.make_prompts()

        while not self.done:
            try:
                prompt = prompts["configuration" if self.mode else "operational"]
                text = prompt.prompt(self.prompt(),
                                     pre_run=lambda: prompt.app.create_background_task(self.watch_notifications()))
                self.submit(text)
            except KeyboardInterrupt:
                continue
            except EOFError:
                if self.mode:
                    self.execute_line("exit")
                else:
                    break


def main():
    parser = argparse.ArgumentParser(description="nVyR router CLI")
    parser.add_argument("--socket", default="/run/nvyr/configd.sock")
    parser.add_argument("--history-directory", help="Directory for separate operational and configuration histories")
    args = parser.parse_args()

    try:
        client = Client(args.socket)
    except OSError:
        parser.exit(1, f"Cannot connect to the router at {args.socket}. Check that the configuration service is running and that your account has access to its socket.\n")

    try:
        CLI(client).interact(args.history_directory)
    finally:
        client.close()


if __name__ == "__main__":
    main()
