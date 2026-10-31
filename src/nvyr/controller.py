"""One command dispatcher used by one-line, pasted and loaded set commands."""

import json
from copy import deepcopy
from nvyr.engine import Session
from nvyr.errors import ConfirmationRequired, ParseError, RouterError, SessionExpiredError
from nvyr.lexer import lex, quote, split_pipeline, load_arguments
from nvyr.pipeline import Output, Pipelines
from nvyr.render import json_text, marked_json, yaml_diff, candidate_json
from nvyr.schema import Cursor, Schema, completion_extension, completion_sort_key, resolve_word
from nvyr.helpers.suggestors import Context, registry as suggestor_registry
from nvyr.helpers.process import cmd, operational_argv
from nvyr.helpers import build_metadata, access, passwords
from nvyr.helpers import config_feedback
from nvyr.helpers.strip_private import ConfigurationMasker
from nvyr.tree import MISSING, Mutation, lookup, projected_value


class Controller:
    def __init__(self, engine):
        self.engine = engine
        self.operational = Schema.bundled("operational")
        self.control = Schema.bundled("control", suggestors=suggestor_registry(self._suggestion_context))
        self.pipelines = Pipelines(engine.schema)
        self.operations = {}

    def _suggestion_context(self):
        with self.engine.mutex:
            return Context(self.engine.store, self.engine.commit_id)

    def register_operation(self, name, handler):
        """Register trusted output handlers taking a resolved Cursor."""
        self.operations[name] = handler

    @staticmethod
    def terminal(cursor):
        return "command" in cursor.node and (cursor.expect not in {"value", "tag"} or cursor.node.get("optional_value"))

    def check_operational_access(self, cursor, schema=None):
        schema = self.operational if schema is None else schema

        for required in (schema.minimum_access(cursor.node), *cursor.required_access):
            access.require_role(required)

    def authorize_terminal(self, text, session):
        # Recheck the authenticated principal after terminal attachment, not a
        # client-supplied role or the root identity of the eventual child process.
        if session:
            self.engine.check_session(session)
            access.require('configure')
        else:
            access.current_role()

        tokens = split_pipeline(text)[0]
        wrapped = session and resolve_word(tokens[0].value, self.control.root['children']) == 'run'
        self.check_operational_access(self.operational.operational(tokens[1:] if wrapped else tokens))

    def execute(self, text, session=None, *, confirmation=None, on_text=None):
        try:
            return self._execute(text, session, confirmation=confirmation, on_text=on_text)
        except SessionExpiredError:
            raise  # This error contains no command values, including credentials.
        except RouterError:
            if passwords.sensitive_line(text):
                raise RouterError('Credential command failed; check the path, role and password format (input omitted)') from None

            raise

    def _execute(self, text, session=None, *, confirmation=None, on_text=None):
        if session:
            access.require('configure')

        stages = split_pipeline(text)
        parsed_pipeline = self.pipelines.parse(stages[1:])  # Validate sinks before effects.
        privacy_modes = [value or 'all' for name, value in parsed_pipeline if name == 'strip-private']
        if len(set(privacy_modes)) > 1:
            raise ParseError('Use one strip-private mode per command.')

        strip_private = privacy_modes[0] if privacy_modes else None
        parsed_pipeline = [(name, value) for name, value in parsed_pipeline if name != 'strip-private']
        masker = ConfigurationMasker(self.engine.schema, strip_private) if strip_private else None

        tokens = stages[0]
        schema = self.control if session else self.operational
        verb = resolve_word(tokens[0].value, schema.root["children"])
        if session and verb != 'exit':
            self.engine.check_session(session)

        if stages[1:] and (session and verb not in {"show", "compare", "run", "shellcmd"} or
                           not session and verb in {"configure", "exit", "shell"}):
            raise ParseError("Use output modifiers with show, compare or run; configuration-changing commands cannot be piped.")

        args = tokens[1:]

        # `run` is a configuration-mode wrapper, not part of the operational
        # command's positional arguments. Keep @line as the original raw input.
        op_tokens = args if session and verb == 'run' else tokens
        output, event = Output(), {}
        feedback = []
        emit = on_text if on_text is not None else feedback.append

        def operational_output(cursor):
            nonlocal event
            self.check_operational_access(cursor)
            command = cursor.node['command']
            if command == 'terminal-length':
                if stages[1:]:
                    raise ParseError('Terminal settings cannot be piped.')

                event = {'event': 'terminal-length', 'length': int(cursor.value)}
                return Output()

            if isinstance(command, dict) and command.get('stream') and stages[1:]:
                raise ParseError('Output modifiers are not supported on streaming commands. Run this command without pipes.')

            if strip_private and isinstance(command, dict):
                if not command['argv'][0].endswith('.nvyr.op'):
                    raise ParseError('strip-private requires an operational script that supports masking')

                # Prepend the function option before user values (including --).
                # The script signature, not an output text filter, owns masking.
                command = dict(command)
                command['argv'] = command['argv'][:2] + ['--strip-private', strip_private] + command['argv'][2:]

            if isinstance(command, dict) and command.get('stream'):
                event = {'event': 'command',
                         'argv': operational_argv(command, op_tokens, text,
                                                  omitted_positions=cursor.omitted_positions),
                         'timeout': command.get('timeout')}
                return Output()

            return self._operational_output(command, cursor, tokens=op_tokens, line=text, masker=masker)

        if session and verb in {"set", "delete", "edit"}:
            messages = self.engine.mutate(session, verb, args)
            if messages:
                output = Output(''.join(messages))
        elif session and verb in {'rename', 'copy'}:
            split = []

            for i, token in enumerate(args):
                if token.value != "to":
                    continue

                try:
                    source = self.engine.schema.resolve(list(session.edit) + args[:i], validate=False)
                    destination = self.engine.schema.resolve(list(session.edit) + args[i+1:], validate=False)
                    if source.node is destination.node and source.node["kind"] == "tag_node" and source.expect == destination.expect == "child":
                        split.append(i)
                except RouterError:
                    continue

            if len(split) != 1:
                raise ParseError(f"Expected {verb} <source tag-instance path> to <destination path under the same tag node>")

            i = split[0]
            transfer = self.engine.rename if verb == 'rename' else self.engine.copy
            transfer(session, [t.value for t in args[:i]], [t.value for t in args[i+1:]])
        elif session and verb in {"run", "shellcmd"}:
            if self._operational_show(op_tokens) is not None:
                command, path_tokens, defaults = self._show_target(op_tokens[2:], None, command='running')
                output = self._show_configuration(command, path_tokens, None, defaults=defaults, masker=masker)
            else:
                op = self.operational.operational(op_tokens)
                if not self.terminal(op) or (isinstance(op.node["command"], str) and op.node["command"] in {"configure", "configure-draft", "exit"}):
                    if verb == 'shellcmd':
                        raise ParseError('shellcmd requires a system command')

                    raise ParseError("run requires an operational display command")

                output = operational_output(op)
        elif session and verb == "load":
            raise ParseError("Use load [replace] [set] <file> from the interactive CLI to read a configuration file.")
        elif session and verb == "show":
            command, path_tokens, defaults = self._show_target(args, session)
            if command == 'references':
                if masker:
                    raise ParseError('strip-private is not supported by show references')

                paths = self.engine.references(session, path_tokens)
                output = Output('Referenced by:\n' + ''.join('  ' + ' '.join(map(quote, path)) + '\n' for path in paths)
                                if paths else 'No references found.\n')
            elif command == 'config-status':
                if path_tokens:
                    raise ParseError('show config-status takes no arguments')

                if masker:
                    raise ParseError('strip-private is not supported by show config-status')

                output = Output(config_feedback.configuration_status(
                    self.engine.schema, self.engine.configuration_status(session)))
            elif command == 'config-sessions':
                if path_tokens:
                    raise ParseError('show config-sessions takes no arguments')

                if masker:
                    raise ParseError('strip-private is not supported by show config-sessions')

                with self.engine.mutex:
                    self.engine.check_session(session)
                    output = Output(json_text({
                        'sessions': [s.identity() | {'draft': s.draft, 'current': s.id == session.id}
                                     for s in self.engine.sessions.values()],
                        'lock': self.engine.lock_owner,
                    }))
            elif command == 'commit-history':
                if path_tokens:
                    raise ParseError('show commit-history takes no arguments')

                if masker:
                    raise ParseError('strip-private is not supported by show commit-history')

                with self.engine.mutex:
                    self.engine.check_session(session)
                    commit_id = self.engine.commit_id
                    records = list(self.engine.store.history_metadata(commit_id))

                output = Output(config_feedback.commit_history(commit_id, records))
            else:
                output = self._show_configuration(command, path_tokens, session, defaults=defaults, masker=masker)
        elif not session and self._operational_show(tokens) is not None:
            command, path_tokens, defaults = self._show_target(args[1:], None, command='running')
            output = self._show_configuration(command, path_tokens, None, defaults=defaults, masker=masker)
        else:
            cursor = schema.resolve(tokens) if session else schema.operational(tokens)
            if not self.terminal(cursor):
                message = f"Expected a value after {cursor.path[-1]!r}." if cursor.expect in {"value", "tag"} and cursor.path else "Use ? to see the available commands."
                raise ParseError("Command is incomplete. " + message)

            command = cursor.node["command"]
            self.check_operational_access(cursor, schema)

            if command == "shell":
                access.require('use a Linux shell')
                event = {"event": "shell"}
            elif not session:
                if isinstance(command, str) and command in {"configure", "configure-draft", "exit"}:
                    if command != 'exit':
                        access.require('configure')

                    event = {"event": command}
                else:
                    output = operational_output(cursor)
            elif command in {"show", "running", "candidate", "compare"}:
                output = self._configuration_output(command, cursor.value, session, session.edit, masker=masker)
            elif command == 'commit-check':
                result = self.engine.check(session, report=lambda message: emit(config_feedback.report_text(message)))
                failures = [f"{owner}: {row['error']}\n" for owner, row in result['results'].items() if not row['success']]
                summary = ('Configuration check failed. Candidate configuration is unchanged.\n' if failures else
                           'Configuration check passed.\n' if result['results'] else
                           'No configuration changes to check.\n')
                output = Output(''.join(failures) + summary)
            elif command in {"commit", "commit-confirm"}:
                try:
                    minutes = float(cursor.path[1]) if command == "commit-confirm" else None
                except (ValueError, TypeError):
                    raise ParseError("commit-confirm requires a number of minutes") from None

                comment = cursor.value if cursor.path[-1] == 'comment' else None
                delay_index = 2 if command == 'commit-confirm' else 1
                if cursor.path[delay_index:delay_index + 1] == ('delay',):
                    try:
                        delay = float(cursor.path[delay_index + 1])
                    except (ValueError, TypeError):
                        raise ParseError('commit delay requires a number of minutes') from None

                    scheduled = self.engine.schedule_commit(session, delay, minutes=minutes, comment=comment,
                        expected_id=(confirmation or {}).get('commit_id'),
                        confirmed_minutes=(confirmation or {}).get('confirm_minutes'),
                        report=lambda message: emit(config_feedback.report_text(message)))
                    output = Output(config_feedback.scheduled_commit(scheduled))
                else:
                    result = self.engine.commit(session, expected_id=(confirmation or {}).get("commit_id"), minutes=minutes, comment=comment,
                                            confirmed_minutes=(confirmation or {}).get("confirm_minutes"),
                                            progress=lambda *args: emit(config_feedback.commit_progress(self.engine.schema, *args)))
                    output = Output(config_feedback.commit_summary(self.engine.schema, result))
            elif command == 'cancel':
                self.engine.cancel_commit(session)
                output = Output('Scheduled commit cancelled. Candidate configuration is unchanged.\n')
            elif command == "lock":
                output = Output(json_text(self.engine.request_lock(session, (confirmation or {}).get("session"))))
            elif command == 'release-lock':
                self.engine.release_lock(session)
                output = Output('Commit lock released. Candidate configuration is unchanged.\n')
            elif command == "exit":
                if session.mutations and not (confirmation or {}).get("discard"):
                    raise ConfirmationRequired("Discard this session's pending changes and exit?", details={"discard": True})

                event = {"event": "leave"}
            elif command == "rollback":
                self.engine.rollback(session, int(cursor.value))
            elif command == "top":
                session.edit = ()
            elif command == "up":
                self.engine.up(session)
            else:
                getattr(self.engine, command)(session)

                if command == "confirm":
                    output = Output("Commit confirmed. Automatic rollback has been cancelled.\n")

        output.text = ''.join(feedback) + output.text
        output = self.pipelines.execute(output, parsed_pipeline)

        return {"text": output.text, "export": output.export, "paging": output.paging, **event,
                "edit": list(self.engine.schema.command_path(session.edit)) if session else [],
                "commit_id": session.commit_id if session else self.engine.commit_id}

    def _operational_output(self, command, cursor=None, *, tokens=(), line='', masker=None):
        if isinstance(command, dict):
            argv = operational_argv(command, tokens, line,
                                    omitted_positions=cursor.omitted_positions if cursor is not None else ())
            return Output(cmd(argv, timeout=command.get("timeout", 15), env=access.command_environment()))

        if command in self.operations and not masker:
            return self.operations[command](cursor)

        if masker:
            raise ParseError('strip-private is not supported by this operational command')

        if command == "version":
            return Output(build_metadata.format_version(build_metadata.read()))

        if command == 'license':
            return Output(build_metadata.read_license())

        raise ParseError("This command is not supported by this router build.")

    def _operational_show(self, tokens):
        """Identify the operational running view before resolving its config path."""
        if len(tokens) < 2 or resolve_word(tokens[0].value, self.operational.root['children']) != 'show':
            return None

        cursor = self.operational.resolve(tokens[:2])
        if cursor.node.get('command') == 'running':
            self.check_operational_access(cursor)
            return cursor

        return None

    def _show_target(self, args, session, *, command='show'):
        """Select a display or relative schema path with the usual exact/prefix rules."""
        selectors = self.control.root["children"]["show"]["children"]
        children = self.engine.schema.resolve(session.edit if session else ()).node.get('children', {})
        defaults = False

        if args and command == 'show':
            name = resolve_word(args[0].value, children | selectors)
            if name in selectors:
                command, args = selectors[name]['command'], args[1:]
                defaults = name == 'all'

        if args and not defaults and command in {'show', 'running', 'candidate'}:
            name = resolve_word(args[0].value, children | {'all': selectors['all']})
            if name == 'all':
                defaults, args = True, args[1:]

        return command, args, defaults

    def _show_configuration(self, command, tokens, session, *, defaults=False, masker=None):
        path = session.edit if session else ()
        if tokens:
            cursor = self.engine.schema.resolve(list(path) + list(tokens))
            if cursor.node['kind'] == 'leaf_node' and cursor.expect == 'done' and not cursor.node.get('valueless'):
                raise ParseError('Show expects a configuration path, without a setting value.')

            path = cursor.path

        return self._configuration_output(command, None, session, path, defaults=defaults, masker=masker)

    def _configuration_output(self, command, value, session, path=(), *, defaults=False, masker=None):
        """Render running, aggregate, candidate or historical configuration views.

        Candidate-with-defaults is scoped to changed top-level sections, whereas
        ordinary show includes unchanged configuration. Output retains the source
        trees and absolute scope so pipes such as commands can render the same
        selection without parsing display text. Apply visibility/masking first.
        """
        running = self.engine.running
        view = self.engine.view(session) if session else running
        candidate_sections = defaults and command == 'candidate'

        if candidate_sections:
            running, view = self._candidate_sections(running, view)
        elif defaults:
            running = self.engine.schema.defaults(running)
            view = self.engine.schema.defaults(view) if session else running

        running, view = access.visible(running), access.visible(view)

        if masker:
            running, view = masker.tree(running), masker.tree(view)
            path = masker.path(path)

        before, after = running, view

        if candidate_sections:
            before, after = lookup(running, path), lookup(view, path)
            if before is MISSING and after is MISSING:
                text = json_text({})
            elif before is MISSING or (before == {} and after is not MISSING):
                text = json_text(after)
            else:
                text = marked_json(before, after)

            return Output(text, before=running, after=view, scope=path)

        if path and command in {"running", "show", "candidate"}:
            before, after = lookup(running, path), lookup(view, path)
            source = before if command == "running" else after
            if source is MISSING and (defaults or command == "running" or before is MISSING):
                raise ParseError(f"Configuration path {' '.join(map(quote, path))!r} is not configured.")

        if command == "running":
            return Output(json_text(before), after=running, scope=path)

        if defaults:
            return Output(json_text(after), after=view, scope=path)

        if command == "show":
            return Output(marked_json(before, after), before=running, after=view,
                          scope=path, include_unchanged=True)

        if command == "candidate":
            return Output(candidate_json(before, after), before=running, after=view, scope=path)

        if value is None:
            before, after = running, view
        elif value == "saved":
            before, after = access.visible(self.engine.store.read("boot.json", {})), running

            if masker:
                before = masker.tree(before)
        else:
            try:
                ago = int(value)
            except ValueError:
                raise ParseError("Use compare saved or compare <number of commits ago>. The number must be zero or greater; use ? to see retained history.") from None

            before, after = access.visible(self.engine.store.historical(self.engine.commit_id, ago)), running

            if masker:
                before = masker.tree(before)

        rendered = yaml_diff(lookup(before, path), lookup(after, path))
        if not rendered:
            comparison = "running and candidate" if value is None else "running and saved" if value == "saved" else f"running and the configuration from {value} commits ago"
            rendered = f"No differences between {comparison} configuration.\n" if value in {None, "saved"} else f"No differences between {comparison}.\n"

        return Output(rendered, before=before, after=after, scope=path)

    def _candidate_sections(self, running, view):
        """Effective changed top-level sections, retaining whole-section deletions."""
        running, view = access.visible(running), access.visible(view)
        names = {name for name in running.keys() | view.keys()
                 if running.get(name, MISSING) != view.get(name, MISSING)}
        previous = self.engine.schema.defaults(running)
        proposed = self.engine.schema.defaults(view)

        return (access.visible({name: previous[name] for name in names if name not in view}),
                access.visible({name: proposed[name] for name in names if name in view}))

    def get_config(self, session, source='running'):
        """Capture structured configuration without display markers or defaults."""
        with self.engine.mutex:
            self.engine.check_session(session)
            access.require('configure')

            if source not in ('running', 'candidate'):
                raise ParseError('Configuration source must be running or candidate')

            configuration = self.engine.running if source == 'running' else self.engine.view(session)
            return deepcopy(access.visible(configuration))

    def load(self, session, content, *, set_format=False, replace=False):
        self.engine.check_session(session)
        access.require('configure')

        if not set_format:
            try:
                from nvyr.storage import unpack_saved

                configuration = json.loads(content)
                if isinstance(configuration, dict) and '_nvyr' in configuration:
                    configuration, _ = unpack_saved(configuration)
            except ValueError as error:
                raise ParseError('Invalid configuration JSON') from None

            self.engine.stage_configuration(session, configuration, replace=replace)

            return []

        target = session

        if replace:
            target = Session("load", session.user, session.vty, session.draft, session.commit_id)

            # A replacement file builds a fresh tree, even when values in it
            # happen to match running configuration.
            target.mutations.append(Mutation('delete', ()))

        errors = []

        for number, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue

            try:
                stages = split_pipeline(line)
                tokens = stages[0]
                if len(stages) != 1 or resolve_word(tokens[0].value, self.control.root["children"]) != "set":
                    raise ParseError("load set accepts only set commands")

                # Load paths are always absolute, independent of interactive edit root.
                messages = self.engine.mutate(target, "set", tokens[1:], absolute=True)

                for message in messages:
                    errors.append({"line": number, "command": '[credential command omitted]' if passwords.sensitive_line(line) else line,
                                   **RouterError(message.rstrip()).as_dict()})
            except RouterError as error:
                if passwords.sensitive_line(line):
                    error = RouterError('Credential command failed (input omitted)')
                    line = '[credential command omitted]'

                errors.append({"line": number, "command": line, **error.as_dict()})

        if replace:
            from nvyr.tree import overlay

            self.engine.stage_configuration(session, overlay({}, target.mutations), replace=True)

        return errors

    def completion(self, text, session=None, *, explicit=False, space=False, tab=False):
        """The only prediction entry point. No command history is accepted here."""
        if session:
            self.engine.check_session(session)

        line = text.rsplit("\n", 1)[-1]
        tokens = lex(line, partial=True)

        # Whitespace within an unfinished quoted token is not a delimiter.
        trailing = bool(line and line[-1].isspace() and (not tokens or tokens[-1].end < len(line)))
        prefix = "" if trailing or not tokens else tokens[-1].value
        completed = tokens if trailing else tokens[:-1]
        active = None if trailing or not tokens else tokens[-1]
        schema = self.control if session else self.operational

        # Candidate journals contain only mutations. Completion projects the requested
        # branch instead of allocating a full merged view on every keystroke.
        with self.engine.mutex:
            running = access.visible(self.engine.running)
            mutations = tuple(session.mutations) if session else ()

        tree = lambda path: projected_value(running, mutations, path) if session else lookup(running, path)

        cursor = Cursor(schema.root)
        config_verb = None
        op_offset = 0
        transfer_source = None
        set_state = None
        consumed = set()
        tag_values = []
        show_request = None

        try:
            pipe_indices = [i for i, t in enumerate(tokens) if t.pipe]
            if pipe_indices:
                index = pipe_indices[-1]

                # Suppress continuations after a completed sink.
                prior = split_pipeline(line[:tokens[index].start])
                parsed = self.pipelines.parse(prior[1:])
                if any(self.pipelines.schema.root["children"][name].get("sink") for name, _ in parsed):
                    return {"candidates": [], "extension": "", "replacement": None}

                schema = self.pipelines.schema
                cursor = Cursor(schema.root)
                completed = [t for t in completed if t.start > tokens[index].start]

                if active and active.pipe:
                    active, prefix, completed = None, "", []
            elif completed and session:
                verb = resolve_word(completed[0].value, self.control.root["children"])
                if verb in {"set", "delete", "edit"}:
                    config_verb = verb
                    schema = self.engine.schema
                    cursor = schema.resolve(session.edit)

                    if verb == "set":
                        set_state = schema.set_cursor(session.edit)

                    completed = completed[1:]
                elif verb == "show":
                    show_request = (completed[1:], session, 'show')
                    completed = []
                elif verb in {"run", "shellcmd"}:
                    schema = self.operational
                    cursor = Cursor(schema.root)
                    op_offset = 1 if verb == 'run' else 0
                    completed = completed[op_offset:]
                elif verb in {'rename', 'copy'}:
                    schema = self.engine.schema
                    config_verb = verb
                    completed = completed[1:]
                    separators = []

                    for i, token in enumerate(completed):
                        if token.value == "to":
                            try:
                                source = schema.resolve(list(session.edit) + completed[:i], validate=False)
                                if source.node["kind"] == "tag_node" and source.expect == "child":
                                    separators.append(i)
                                    transfer_source = source.node
                            except RouterError:
                                continue

                    if separators:
                        completed = completed[separators[-1] + 1:]

                    cursor = schema.resolve(session.edit)
                elif verb == "load":
                    words = [t.value for t in completed[1:]]
                    options = ["replace", "set"] if not words else ["set"] if words == ["replace"] else []
                    candidates = [(value, "Load option") for value in options if value.startswith(prefix)]
                    extension = completion_extension(prefix, candidates)
                    replacement = candidates[0][0] if len(candidates) == 1 else None

                    if explicit:
                        try:
                            load_arguments([t.value for t in tokens[1:]])
                            candidates.append(("<Enter>", "Load the client-local file into the candidate"))
                        except RouterError:
                            candidates.append(("<file>", "Client-local configuration file"))

                    return {"candidates": candidates, "extension": extension, "replacement": replacement,
                            "unique": replacement is not None, "start": active.start if active else len(line)}

            if schema is self.operational and self._operational_show(completed) is not None:
                show_request = (completed[2:], None, 'running')

            if show_request is not None:
                arguments, context, source = show_request
                show_source, completed, defaults = self._show_target(arguments, context, command=source)
                if show_source in {'config-sessions', 'config-status', 'commit-history'}:
                    schema = self.control
                    cursor = schema.resolve(['show', show_source])
                else:
                    config_verb = 'references' if show_source == 'references' else 'show'
                    schema = self.engine.schema
                    cursor = schema.resolve(context.edit if context else ())
                    existing = running
                    proposed = None
                    if defaults:
                        if show_source == 'candidate':
                            existing, proposed = self._candidate_sections(self.engine.running, self.engine.view(context))
                        else:
                            existing = access.visible(schema.defaults(self.engine.running))
                            proposed = (access.visible(schema.defaults(self.engine.view(context)))
                                        if context else existing)

                    def show_tree(path):
                        old = lookup(existing, path)
                        if show_source == 'running':
                            return old

                        new = (lookup(proposed, path) if defaults else
                               projected_value(running, mutations, path))
                        if show_source == 'references':
                            return new

                        if defaults and show_source != 'candidate':
                            return new

                        # Removed objects remain discoverable in normal change views.
                        if new is MISSING:
                            return old

                        if isinstance(old, dict) and isinstance(new, dict):
                            return old | new

                        return new

                    tree = show_tree
                    if not completed and not defaults and show_source != 'references':
                        selectors = self.control.root['children']['show']['children']
                        options = selectors if source == 'show' and not arguments else {'all': selectors['all']}
                        cursor = Cursor({'kind': 'node', 'children': cursor.node.get('children', {}) | options}, cursor.path)

            if schema is self.operational:
                set_state = schema.set_cursor()

            advance_state = schema.advance_operational if schema is self.operational else schema.advance_set

            for token in completed:
                current = set_state.next if set_state is not None else cursor

                if schema is self.operational:
                    current = schema.operational_input(current, token)

                # A tag value identifies a path during discovery, even if submission
                # would reject it. Keep keyword resolution and leaf validation intact.
                is_tag = current.expect == 'tag'
                if is_tag and not (current.node.get('negatable') and token.value == 'not' and not token.quoted):
                    tag_values.append((current.node, token.value))

                if set_state is not None:
                    set_state = advance_state(set_state, token, validate=not is_tag)
                    if (set_state.anchor is not None and set_state.cursor.expect == 'done'
                            and set_state.cursor.node['kind'] == 'leaf_node'
                            and not set_state.cursor.node.get('multi')):
                        consumed.add(set_state.cursor.path)
                else:
                    cursor = schema.advance(cursor, token, validate=not is_tag)

            if set_state is not None:
                cursor = set_state.next if schema is self.operational else set_state.completion(prefix)

            # Runtime cleanup must suggest installed groups, never pending candidate edits.
            if schema is self.operational and cursor.path[:3] == ('clear', 'firewall', 'group'):
                tree = running

            # A positional value has the same completion/validation behavior as
            # a tag value, but its schema name is never typed by the operator.
            # An optional tag still offers both values and typed subcommands.
            # Converting it to a child cursor here falsely means its value was
            # already consumed and hides optional children such as ethernet.
            if schema is self.operational and active and not schema.optional_tag(cursor):
                cursor = schema.operational_input(cursor, active)

            current_role = access.current_role()

            def accessible(node):
                # A restricted parent can contain an explicitly public child.
                return access.allows(schema.minimum_access(node), current=current_role) or any(
                    accessible(child) for child in node.get('children', {}).values())

            if schema is self.operational and not accessible(cursor.node):
                return {"candidates": [], "extension": "", "replacement": None}

            candidates = None
            suggested = set()

            # Help may inspect an entered tag without a trailing space. Preserve
            # name-prefix discovery when the text still matches other candidates.
            if explicit and active and active.complete and cursor.expect == 'tag':
                candidates = schema.candidates(cursor, prefix, tree, suggested=suggested)
                if not candidates or prefix in dict(candidates):
                    if schema is not self.operational or schema.operational_input(cursor, active).expect == 'tag':
                        if not (cursor.node.get('negatable') and active.value == 'not' and not active.quoted):
                            tag_values.append((cursor.node, active.value))

                    if set_state is not None:
                        set_state = advance_state(set_state, active, validate=False)
                        cursor = set_state.next if schema is self.operational else set_state.completion()
                    else:
                        cursor = schema.advance(cursor, active, validate=False)

                    active, prefix = None, ''
                    candidates = None

            # Explicit help after an exact valued-leaf or tag keyword describes its input,
            # even when the operator has not yet entered a separating space.
            if explicit and active and cursor.expect == 'child' and config_verb != 'show':
                child = cursor.node.get('children', {}).get(prefix, {})
                if child.get('kind') in {'leaf_node', 'tag_node'} and not child.get('valueless'):
                    if set_state is not None:
                        set_state = advance_state(set_state, active)
                        cursor = set_state.next if schema is self.operational else set_state.completion()
                    else:
                        cursor = schema.advance(cursor, active)

                    active, prefix = None, ''

            if schema is self.operational and not accessible(cursor.node):
                return {"candidates": [], "extension": "", "replacement": None}

            display = tab and not prefix and cursor.expect in {"tag", "value"} and cursor.node.get("list_on_empty_tab", False)
            explicit = explicit or display

            if candidates is None:
                candidates = schema.candidates(cursor, prefix, tree, explicit=explicit, suggested=suggested)

            if set_state is not None and set_state.anchor is not None and cursor.expect == 'child':
                available = set_state.unused_children(cursor, consumed)
                candidates = [(name, detail) for name, detail in candidates if name in available]

            if (set_state is not None and set_state.cursor.joinable and cursor is not set_state.cursor
                    and 'and'.startswith(prefix)):
                candidates.append(('and', 'Join another value to this combination'))

            if schema is self.operational or schema is self.control:
                children = cursor.node.get('children', {})
                candidates = [(name, detail) for name, detail in candidates
                              if name not in children or accessible(children[name])]

            hints = list(cursor.node.get('hints', {}).items()) if (cursor.expect == 'tag' or
                    cursor.expect == 'value' and config_verb != 'show') else []

            positional = schema.positional_cursor(cursor) if schema is self.operational else None
            if positional is not None and accessible(positional.node):
                hints.extend(positional.node.get('hints', {}).items())
                positional_suggestions = set()
                values = schema.candidates(positional, prefix, tree, explicit=explicit,
                                           suggested=positional_suggestions)
                # A positional suggestion cannot expose a restricted keyword or
                # replace a named branch that the parser would choose first.
                keywords = {name for name, child in cursor.node.get('children', {}).items()
                            if not child.get('positional')}
                values = [(name, detail) for name, detail in values if name not in keywords]
                candidates = list((dict(values) | dict(candidates)).items())
                suggested.update(positional_suggestions)

            if config_verb == "show" and cursor.node["kind"] == "leaf_node":
                candidates = []  # A show scope ends at a leaf; it takes no value.

            if config_verb == 'references':
                if cursor.expect == 'child':
                    children = cursor.node.get('children', {})
                    candidates = [(name, detail) for name, detail in candidates
                                  if name in children and 'dependency' in self.engine.dependencies.branches[id(children[name])]]
                elif cursor.expect == 'tag':
                    names = tree(cursor.path)
                    candidates = [(name, detail) for name, detail in candidates
                                  if names is not MISSING and name in names]
                else:
                    candidates = []
                    hints = []

            if config_verb in {'rename', 'copy'} and transfer_source is None and cursor.node["kind"] == "tag_node" and cursor.expect == "child" and "to".startswith(prefix):
                candidates.append(("to", "Destination tag path"))

            if schema is self.operational and cursor.path[:3] == ('clear', 'firewall', 'group'):
                from nvyr.helpers.firewall_runtime import completion_candidates

                candidates = completion_candidates(cursor, set_state, candidates, running)

            for value in cursor.node.get("choices_hint", []):
                if value.startswith(prefix):
                    candidates.append((value, "Saved configuration" if value == "saved" else "Comparison target"))
                    suggested.discard(value)

            if explicit and cursor.expect in {"tag", "value"} and not candidates and not hints and config_verb not in {'show', 'references'}:
                candidates.append(("<value>", "Enter a value for this setting"))

            if explicit:
                try:
                    if schema is self.operational:
                        op_tokens = tokens[op_offset:]
                        terminal_cursor = schema.operational(op_tokens)
                        self.check_operational_access(terminal_cursor)
                    elif set_state is not None:
                        terminal_cursor = schema.advance_set(set_state, active).cursor if active else set_state.cursor
                    else:
                        terminal_cursor = schema.advance(cursor, active) if active else cursor

                    if schema is self.control:
                        self.check_operational_access(terminal_cursor, schema)

                    valid = self.terminal(terminal_cursor) if not config_verb else (
                        bool(terminal_cursor.path) and (
                            (config_verb == "delete" and terminal_cursor.join_value is None) or
                            (config_verb == 'references' and terminal_cursor.node['kind'] == 'tag_node'
                             and terminal_cursor.expect == 'child' and 'dependency' in terminal_cursor.node
                             and tree(terminal_cursor.path) is not MISSING) or
                            (config_verb == "show" and (terminal_cursor.expect != "done" or terminal_cursor.node.get("valueless"))) or
                            (config_verb in {'rename', 'copy'} and transfer_source is terminal_cursor.node and terminal_cursor.expect == "child") or
                            (config_verb == "edit" and schema.editable(terminal_cursor)) or
                            (config_verb == "set" and terminal_cursor.expect in {"done", "child", "tag"}
                             and not (terminal_cursor.expect == 'tag' and terminal_cursor.node.get('_negated')))))
                    if valid and schema is self.operational and terminal_cursor.path[:3] == ('clear', 'firewall', 'group'):
                        from nvyr.helpers.firewall_runtime import complete_request

                        valid = complete_request(schema, line, running)
                except RouterError:
                    valid = False

                if config_verb == "show" and not active and (cursor.expect != "done" or cursor.node.get("valueless")):
                    valid = True

                if active and not active.complete:
                    valid = False

                if valid:
                    try:
                        for node, value in tag_values:
                            schema.validate(node, value)
                    except RouterError:
                        valid = False

                if valid:
                    candidates.append(("<Enter>", "Execute the current command"))

            candidates.sort(key=lambda item: (item[0].startswith("<"), completion_sort_key(item[0])))
            extension = completion_extension(prefix, candidates)
            concrete = [v for v, _ in candidates if not v.startswith("<")]
            replacement = None

            if active and cursor.expect == "child" and space:
                choices = dict(candidates) if config_verb in {'rename', 'copy'} or schema in (self.operational, self.control) else cursor.node.get("children", {})
                if set_state is not None and set_state.anchor is not None:
                    choices = dict(candidates)

                if choices:
                    replacement = resolve_word(prefix, choices)
            elif active and space and schema is self.operational and schema.operational_input(cursor, active).expect == 'child':
                replacement = resolve_word(prefix, dict(candidates))
            elif len(concrete) == 1 and concrete[0].startswith(prefix):
                replacement = quote(concrete[0])

            # Never offer a suffix that would turn one value into multiple tokens.
            # Tab can replace the entire token with a correctly quoted value.
            if cursor.expect in {"tag", "value"} and active:
                raw = line[active.start:active.end]
                if raw.startswith(("'", '"')):
                    if len(concrete) == 1:
                        delimiter = raw[0]
                        escaped = concrete[0].replace("\\", "\\\\").replace('"', '\\"') if delimiter == '"' else concrete[0]
                        rendered = delimiter + escaped + delimiter
                        extension = rendered[len(raw):] if rendered.startswith(raw) and not (delimiter == "'" and "'" in concrete[0]) else ""
                    else:
                        extension = ""
                elif any(c.isspace() for c in prefix + extension) or any(c in prefix + extension for c in "'\"|\\"):
                    extension = ""

            visible = candidates[:256]

            # Keep execution help available even when discovered values fill the
            # display limit. Prefix/uniqueness calculations above still use all matches.
            for row in candidates[256:]:
                if row[0] == '<Enter>':
                    visible[-1] = row
                    break

            return {"candidates": visible, "hints": hints, "total": len(candidates), "extension": extension,
                    "groups": set_state.completion_groups(cursor, visible) if set_state is not None else [],
                    "suggested": [value for value, _ in visible if value in suggested],
                    "replacement": replacement, "start": active.start if active else len(line),
                    "unique": len(concrete) == 1, "display": bool(display)}
        except RouterError:
            return {"candidates": [], "extension": "", "replacement": None}
