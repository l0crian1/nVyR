"""Extensible typed output transformations; the lexer only knows about '|'."""

from dataclasses import dataclass, replace
import re
from nvyr.errors import ParseError
from nvyr.render import diff_commands, set_commands, scope_node
from nvyr.schema import Schema
from nvyr.tree import MISSING, lookup


@dataclass
class Output:
    text: str = ""
    before: dict | None = None
    after: dict | None = None
    export: str | None = None
    scope: tuple = ()
    paging: bool | None = None
    include_unchanged: bool = False


class Pipelines:
    def __init__(self, configuration_schema, schema=None):
        self.configuration_schema = configuration_schema
        self.schema = schema or Schema.bundled("pipelines")
        self.handlers = {"commands": self.commands, "match": self.match,
                         "except": self.except_lines, "count": self.count, "export": self.export,
                         "more": self.more, "no-more": self.no_more}

    def register(self, name, definition, handler):
        self.schema.root["children"][name] = definition
        self.handlers[name] = handler

    def parse(self, stages):
        parsed = []

        for index, tokens in enumerate(stages):
            cursor = self.schema.resolve(tokens)
            if (cursor.expect in {"value", "tag"} and not cursor.node.get('optional_value')
                    or "command" not in cursor.node):
                raise ParseError("The output modifier is incomplete. Use ? to see its required value.")

            if cursor.node.get("sink") and index != len(stages) - 1:
                raise ParseError(f"Nothing may follow {tokens[0].value!r}; place this output modifier last.")

            name, value = cursor.node['command'], cursor.value
            if name in {'match', 'except'}:
                try:
                    value = re.compile(value)
                except (re.error, OverflowError, RecursionError) as error:
                    raise ParseError(f'Invalid regular expression for {name}: {error}') from None

            parsed.append((name, value))

        return parsed

    def execute(self, output, parsed):
        for name, value in parsed:
            output = self.handlers[name](output, value)

        return output

    def commands(self, output, value):
        if output.after is None:
            raise ParseError("Use commands directly after a configuration display or comparison, before match, except or count.")

        schema = self.configuration_schema
        scope = output.scope
        node = scope_node(schema, scope)
        after = lookup(output.after, scope)
        before = lookup(output.before, scope) if output.before is not None else MISSING
        prefix = ()

        if scope and (node['kind'] == 'leaf_node' or after is MISSING or
                      (not after and (before is MISSING or before == after))):
            # A leaf or the selected object itself cannot be addressed from
            # inside itself. Retain its name relative to its editable parent.
            parent = scope[:-1]

            while not schema.editable(schema.resolve(parent, validate=False)):
                parent = parent[:-1]

            prefix = schema.command_path(scope)[len(schema.command_path(parent)):]

        if output.before is None:
            lines = set_commands(schema, after, prefix, node)
        else:
            lines = diff_commands(
                schema, output.before, output.after, scope, prefix=prefix,
                include_unchanged=output.include_unchanged,
            )

        return Output("".join(line + "\n" for line in lines))

    @staticmethod
    def match(output, value):
        return Output("".join(line for line in output.text.splitlines(keepends=True)
                              if re.search(value, line.rstrip('\r\n'))))

    @staticmethod
    def except_lines(output, value):
        return Output("".join(line for line in output.text.splitlines(keepends=True)
                              if not re.search(value, line.rstrip('\r\n'))))

    @staticmethod
    def count(output, value):
        return Output(str(len(output.text.splitlines())) + "\n")

    @staticmethod
    def export(output, value):
        return Output(output.text, export=value)

    @staticmethod
    def more(output, value):
        return replace(output, paging=True)

    @staticmethod
    def no_more(output, value):
        return replace(output, paging=False)
