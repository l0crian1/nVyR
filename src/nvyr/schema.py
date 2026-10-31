"""Shared resolution, validation, defaults and authoritative completion sources."""

import json
import math
from copy import deepcopy
from dataclasses import dataclass, replace
from importlib.resources import files
from os.path import commonprefix
from inspect import signature

from nvyr.errors import ParseError, ValidationError
from nvyr.lexer import Token
from nvyr.tree import MISSING, lookup, put
from nvyr.helpers.validators import REGISTRY as VALIDATORS, PREPARERS, ValidationFailure, failure_message
from nvyr.helpers.suggestors import registry as suggestor_registry, Suggestion, BoundSuggestor
from nvyr.helpers.strip_private import KINDS as STRIP_KINDS
from nvyr.helpers.access import ROLE_LEVELS
from nvyr.helpers.dependencies import validate_declarations
from nvyr.helpers.ownership import Ownership
from nvyr.helpers.reapply_schema import validate_reapply


def prefix_matches(prefix, values):
    return [value for value in values if value.startswith(prefix)]


def callback_reference(reference):
    """Runtime callback objects shared by validators and suggestors."""
    if (not isinstance(reference, dict) or set(reference) - {"name", "args"} or
            not isinstance(reference.get("name"), str) or not reference["name"] or
            not isinstance(reference.get("args", {}), dict) or
            not all(isinstance(key, str) for key in reference.get("args", {}))):
        raise ValueError("Callback must be an object with name and optional args object")

    return reference["name"], reference.get("args", {})


def check_callback(reference, registry, *required):
    name, arguments = callback_reference(reference)
    if name not in registry:
        raise ValueError(f"Unknown callback {name}")

    try:
        signature(registry[name]).bind(*required, **arguments)
    except TypeError as error:
        raise ValueError(f"Invalid arguments for {name}: {error}") from error

    return name, arguments


def validator_checks(validation):
    """Return the runtime validator checks in declaration order."""
    if not isinstance(validation, dict) or set(validation) - {'mode', 'checks'}:
        raise ValueError('Validators require an object with mode and checks')

    if validation.get('mode', 'AND') not in {'AND', 'OR'}:
        raise ValueError('Validator mode must be AND or OR')

    checks = validation.get('checks', {})
    if not isinstance(checks, dict) or not all(isinstance(key, str) and key for key in checks):
        raise ValueError('Validator checks require an object with nonempty string IDs')

    return checks.items()


def completion_sort_key(value):
    """Unsigned decimal values first, by magnitude; other tokens alphabetically.

    Compare significant digit lengths instead of int(), allowing arbitrarily long
    values and retaining deterministic ordering for equivalent spellings like 01/1.
    """
    if value.isascii() and value.isdecimal():
        digits = value.lstrip("0") or "0"
        return (0, len(digits), digits, len(value), value)

    return (1, value)


def resolve_word(word, values):
    # Full keywords need only one lookup, regardless of the number of siblings.
    if word in values:
        node = values[word] if isinstance(values, dict) else None
        if not isinstance(node, dict) or not node.get('_negation_branch'):
            return word

    if isinstance(values, dict):
        values = {name: node for name, node in values.items()
                  if not isinstance(node, dict) or not node.get('_negation_branch')}

    matches = prefix_matches(word, values)
    if len(matches) == 1:
        return matches[0]

    message = (f"Abbreviation {word!r} matches more than one command: {', '.join(matches)}. Type more characters."
               if matches else f"Unknown command or setting {word!r}. Use ? to see valid choices.")
    raise ParseError(message, token=word)


@dataclass
class Cursor:
    node: dict
    path: tuple = ()
    expect: str = "child"
    value: object = None
    owner: str | None = None
    omitted_positions: tuple = ()
    required_access: tuple = ()
    join_value: str | None = None
    join_negated: bool = False

    @property
    def joinable(self):
        return self.expect == 'done' and self.node.get('joinable', False)


@dataclass(frozen=True)
class SetCursor:
    """Transient grammar state; never stored in a configuration or mutation."""

    cursor: Cursor
    anchor: Cursor | None = None
    parent_anchors: tuple = ()

    @property
    def boundary(self):
        # Leaves and childless tags always return to the anchor. Tags with
        # children use the following keyword to select their continuation.
        return self.cursor.expect == 'done' or (
            self.cursor.node['kind'] == 'tag_node' and self.cursor.expect == 'child'
            and not self.cursor.node.get('children'))

    @property
    def next(self):
        return self.anchor if self.boundary and self.anchor is not None else self.cursor

    def completion(self, prefix=""):
        # Nested node anchors take precedence over outer configuration anchors.
        # Keep outer options available so a command can continue at either level.
        if (self.parent_anchors and self.next.expect == 'child'
                and (self.boundary or self.cursor is self.anchor or self.cursor.node['kind'] == 'tag_node')):
            local = self.next.node.get('children', {})
            if prefix and prefix_matches(prefix, local):
                return self.next

            children = {}
            for parent in self.parent_anchors:
                children.update(parent.node.get('children', {}))
            children.update(self.anchor.node.get('children', {}))
            children.update(local)
            cursor = self.next

        # A complete nested tag can take a child or start another anchor operation.
        elif (self.anchor is not None and self.cursor is not self.anchor
                and self.cursor.node['kind'] == 'tag_node' and self.cursor.expect == 'child'):
            local = self.cursor.node.get('children', {})
            if prefix and prefix_matches(prefix, local):
                return self.cursor

            children = self.anchor.node.get('children', {}) | local
            cursor = self.cursor
        else:
            return self.next

        # Local abbreviations take precedence during input. An ancestor name
        # that abbreviates a local child cannot be selected from this context.
        children = {name: node for name, node in children.items()
                    if name in local or not prefix_matches(name, local)}

        return replace(cursor, node=cursor.node | {'children': children})

    def completion_groups(self, cursor, candidates):
        """Describe the origins of merged help without changing the candidates."""
        joinable = self.cursor.joinable and any(name == 'and' for name, _ in candidates)
        if cursor.expect != 'child':
            return []
        if not joinable and (cursor is self.next or cursor is self.cursor):
            return []

        # A completed joinable leaf still owns its `and` continuation, even when
        # the next ordinary parameter would return to its enclosing anchor.
        current = self.cursor if joinable else self.next
        contexts = [current, self.next, self.anchor, *reversed(self.parent_anchors)]
        groups = {}
        for context in contexts:
            if context is None or context.path in groups:
                continue

            name_position = -2 if context.node['kind'] == 'tag_node' else -1
            groups[context.path] = {
                'name': context.path[name_position] if context.path else 'root',
                'current': context is current,
                'candidates': [],
            }

        for name, _ in candidates:
            if name == '<Enter>':
                continue

            parent = self.input(name)
            groups[parent.path]['candidates'].append(name)

        if not any(group['candidates'] and not group['current'] for group in groups.values()):
            return []

        return [group for group in groups.values() if group['candidates']]

    def input(self, token):
        word = token.value if isinstance(token, Token) else token
        cursor = self.completion(word)
        if self.cursor.joinable:
            choices = {'and': None} | cursor.node.get('children', {})
            if resolve_word(word, choices) == 'and':
                return self.cursor

        if cursor is self.cursor or cursor is self.next:
            return cursor

        name = resolve_word(word, cursor.node['children'])

        if self.next.expect == 'child' and name in self.next.node.get('children', {}):
            return self.next
        if name in self.anchor.node.get('children', {}):
            return self.anchor
        return next(parent for parent in reversed(self.parent_anchors)
                    if name in parent.node.get('children', {}))

    def unused_children(self, cursor, consumed):
        """Completion-only filtering; repeated input still uses the full grammar."""
        def available(node, path):
            if node['kind'] == 'leaf_node':
                negative_path = path[:-1] + ('not', path[-1])
                return node.get('multi', False) or path not in consumed or (
                    node.get('negatable') and negative_path not in consumed)

            if node['kind'] == 'tag_node' or not node.get('children'):
                return True

            return any(available(child, path + (name,))
                       for name, child in node['children'].items())

        children = cursor.node.get('children', {})
        result = set()

        for name, node in children.items():
            if node.get('_negation_branch'):
                continue
            # Nested-tag completion merges local and anchor children. Resolve
            # their actual parent paths rather than treating them as siblings.
            parent = cursor if cursor is self.cursor or cursor is self.next else self.input(name)
            if available(node, parent.path + (name,)):
                result.add(name)

        return result


class Schema:
    def __init__(self, root, validators=None, suggestors=None):
        self.root = deepcopy(root)
        self._negative_nodes = {}
        self._add_negation_nodes(self.root)
        self.validators = VALIDATORS | (validators or {})
        self.suggestors = suggestor_registry() | (suggestors or {})
        self._access = {}
        self._prepared_validators = {}
        self._default_children = {}
        self._check(self.root)
        self.ownership = Ownership(self.root)
        self.owners = self.ownership.owners
        validate_reapply(self.root)

    def _add_negation_nodes(self, node):
        """Derive negative storage branches from the existing value definitions."""
        children = node.get('children', {})
        negative = {}
        for name, child in list(children.items()):
            if child.get('negatable') is True:
                variant = deepcopy(child)
                variant.pop('negatable')
                variant.pop('default', None)
                variant['_negated'] = True
                self._add_negation_nodes(variant)
                negative[name] = variant
                self._negative_nodes[id(child)] = variant
            self._add_negation_nodes(child)

        if negative:
            if 'not' in children:
                raise ValueError('The not keyword is reserved beside negatable nodes')
            children['not'] = {'kind': 'node', '_negation_branch': True, 'children': negative}

    def command_path(self, path):
        """Translate storage paths into the public field-not-value grammar."""
        node = self.root
        words = []
        tag = False
        negative = False
        for word in path:
            optional_child = node.get('optional_value') and word in node.get('children', {})
            if tag and not optional_child:
                words.append(word)
                tag = False
                continue
            node = node['children'][word]
            if node.get('_negation_branch'):
                negative = True
                continue
            if not node.get('positional'):
                words.append(word)
            if negative:
                words.append('not')
                negative = False
            tag = node['kind'] == 'tag_node'
        return tuple(words)

    @classmethod
    def bundled(cls, name="configuration", **kwargs):
        return cls(json.loads(files("nvyr").joinpath(f"schemas/{name}.json").read_text()), **kwargs)

    def _check(self, node, path=(), inherited_access='read-only'):
        kind = node.get("kind")
        if kind not in {"node", "tag_node", "leaf_node"}:
            raise ValueError(f"Invalid node kind at {path}")

        validate_declarations(node, path)

        if 'negatable' in node and (type(node['negatable']) is not bool or
                kind not in {'leaf_node', 'tag_node'} or node.get('valueless') or node.get('rest')):
            raise ValueError(f'negatable requires a boolean on a valued leaf or tag at {path}')

        if 'rename' in node and (type(node['rename']) is not bool or kind != 'tag_node'):
            raise ValueError(f"{'/'.join(path) or '<root>'}: rename requires a boolean on a tag_node")

        minimum = node.get('access', inherited_access)
        if not isinstance(minimum, str) or minimum not in ROLE_LEVELS:
            raise ValueError(f"Invalid access {minimum!r} at {' '.join(path) or '<root>'}; expected read-only, net-admin, sys-admin or dev-admin")

        self._access[id(node)] = minimum

        if 'strip_kind' in node and (not isinstance(node['strip_kind'], str) or
                node['strip_kind'] not in STRIP_KINDS or
                kind not in {'leaf_node', 'tag_node'} or node.get('valueless')):
            raise ValueError(f'Invalid strip_kind on valued leaf or tag node at {path}')

        if 'anchor' in node and (type(node['anchor']) is not bool or
                kind not in ('node', 'tag_node')):
            raise ValueError(f"An anchor requires a node or tag node at {path}")

        join = node.get('joinable')
        valid_join = type(join) is bool or (
            isinstance(join, dict) and set(join) == {'negatable'} and type(join['negatable']) is bool)
        if 'joinable' in node and (not valid_join or
                kind != 'leaf_node' or node.get('valueless') or node.get('rest')):
            raise ValueError(f"joinable requires a boolean or {{negatable: boolean}} on a valued leaf at {path}")

        command = node.get("command")
        if 'positional' in node and (type(node['positional']) is not bool
                or kind != 'tag_node'
                or not (isinstance(command, dict) or 'command' not in node and node.get('children'))
                or any(node.get(option) for option in ('optional_value', 'anchor', 'negatable', 'rest'))):
            raise ValueError(f'positional requires an operational tag with a command or children at {path}')

        if sum(bool(child.get('positional')) for child in node.get('children', {}).values()) > 1:
            raise ValueError(f'Only one positional child is allowed at {path}')

        if 'rest' in node and (type(node['rest']) is not bool or
                kind != 'leaf_node' or not isinstance(command, dict) or
                node.get('valueless') or node.get('multi') or node.get('optional_value')):
            raise ValueError(f'rest requires a valued operational command leaf at {path}')

        if isinstance(command, dict):
            argv, timeout = command.get("argv"), command.get("timeout", 15)
            if (not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv)
                    or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
                raise ValueError(f"Invalid system-command definition at {path}")

            if set(command) - {'argv', 'timeout', 'stream'}:
                raise ValueError(f'Unknown system-command property at {path}')

            if 'stream' in command and type(command['stream']) is not bool:
                raise ValueError(f'Operational stream must be boolean at {path}')

            if not argv[0] or argv[0].startswith('@') and not argv[0].startswith('@@'):
                raise ValueError(f'Operational executable/function must be fixed at {path}')

        if node.get("multi") and node.get("valueless"):
            raise ValueError("A valueless leaf cannot be multi-valued")

        if (node.get("multi") or node.get("valueless")) and kind != "leaf_node":
            raise ValueError("Only leaves support multi and valueless")

        if kind == "leaf_node" and node.get("children"):
            raise ValueError("Leaves cannot have children")

        if "choices" in node:
            choices = node["choices"]
            if (not isinstance(choices, dict) or
                    not all(isinstance(value, str) for value in choices) or
                    not all(isinstance(label, str) and label for label in choices.values())):
                raise ValueError(f"Choices require a value-to-description object at {path}")

        if "hints" in node:
            hints = node["hints"]
            if (kind not in {"leaf_node", "tag_node"} or node.get("valueless") or not isinstance(hints, dict)
                    or not all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in hints.items())):
                raise ValueError(f"Hints require a value-to-description object on a valued leaf or tag node at {path}")

        validation = node.get("validators", {})

        for check_id, reference in validator_checks(validation):
            name, arguments = check_callback(reference, self.validators, "")
            if name in PREPARERS and self.validators[name] is VALIDATORS.get(name):
                self._prepared_validators[id(node), check_id] = PREPARERS[name](**arguments)

        for reference in node.get("suggestors", []):
            check_callback(reference, self.suggestors)

        if "default" in node:
            default = node["default"]
            if kind != "leaf_node" or default["mode"] not in {"direct", "always"}:
                raise ValueError("Invalid default")

            if node.get("valueless"):
                if "value" in default and default["value"] is not True:
                    raise ValueError("Valueless defaults represent true presence")
            else:
                if node.get("multi") and (not isinstance(default.get("value"), list) or not default["value"]):
                    raise ValueError("Multi defaults require a nonempty list")

                values = default["value"] if node.get("multi") else [default["value"]]

                for value in values:
                    self.validate(node, value)

                if node.get("multi") and len(set(values)) != len(values):
                    raise ValueError(f"Multi defaults require different values at {' '.join(path)}")

        for name, child in node.get("children", {}).items():
            if not name or any(c.isspace() for c in name) or "|" in name:
                raise ValueError(f"Invalid keyword {name!r}")

            self._check(child, path + (name,), minimum)

        # Default expansion only needs branches containing a default declaration.
        self._default_children[id(node)] = tuple(
            (name, child) for name, child in node.get('children', {}).items()
            if 'default' in child or self._default_children[id(child)]
        )

    def minimum_access(self, node):
        """Return the inherited policy without adding defaults to schema source."""
        return self._access[id(node)]

    def validate(self, node, value):
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValidationError("Enter a single-line value without control characters; enclose values containing spaces in quotes.", token=None if node.get('secret') else str(value))

        rule = node.get("validators", {})
        references = [(check_id, *callback_reference(ref)) for check_id, ref in validator_checks(rule)]
        names = [name for _, name, _ in references]
        results = []

        for check_id, name, arguments in references:
            prepared = self._prepared_validators.get((id(node), check_id))
            results.append(prepared(value) if prepared else self.validators[name](value, **arguments))

        if results and not (any(results) if rule.get("mode", "AND") == "OR" else all(results)):
            if node.get('secret'):
                raise ValidationError('Invalid credential value; check the expected format')

            failed = [name for name, passed in zip(names, results) if not passed]
            suggestions = []
            for result in results:
                if isinstance(result, ValidationFailure):
                    suggestions.extend(result.suggestions)
            raise ValidationError(failure_message(value, failed, rule.get("mode", "AND"), suggestions), token=value)

    def advance(self, cursor, token, *, validate=True, internal=False):
        """Consume one token and return the next immutable parser cursor.

        User input resolves abbreviations and expands not/and syntax. Internal
        paths already use stored names and must not reinterpret those keywords.
        Cursor state distinguishes a pending tag/value from children or a
        completed leaf; source positions are retained when reporting errors.
        """
        word = token.value if isinstance(token, Token) else token

        try:
            if cursor.expect in {"tag", "value"}:
                join = cursor.node.get('joinable')
                if not internal and isinstance(join, dict) and join.get('negatable'):
                    if word == 'not' and not cursor.join_negated:
                        return replace(cursor, join_negated=True)
                    if cursor.join_negated:
                        word = 'not ' + word

                if (not internal and cursor.node.get('negatable') and cursor.join_value is None and word == 'not'
                        and not (isinstance(token, Token) and token.quoted)):
                    return replace(cursor, node=self._negative_nodes[id(cursor.node)],
                                   path=cursor.path[:-1] + ('not', cursor.path[-1]))

                if cursor.join_value is not None:
                    # Join syntax is interactive only; validators and storage see
                    # the same comma-separated combination as programmatic input.
                    word = cursor.join_value + ',' + word

                if validate:
                    self.validate(cursor.node, word)

                return Cursor(cursor.node,
                              cursor.path + (word,) if cursor.expect == "tag" else cursor.path,
                              "child" if cursor.expect == "tag" else "done", word, cursor.owner)

            if cursor.expect == "done":
                if cursor.joinable:
                    resolve_word(word, ('and',))
                    return replace(cursor, expect='value', join_value=cursor.value)

                raise ParseError("Unexpected extra value; quote values containing spaces", token=word)

            children = cursor.node.get('children', {})
            name = word if internal and word in children else resolve_word(word, children)
            node = cursor.node["children"][name]
            expect = {"node": "child", "tag_node": "tag", "leaf_node": "value"}[node["kind"]]

            if node.get("valueless"):
                expect = "done"

            return Cursor(node, cursor.path + (name,), expect,
                          True if node.get("valueless") else None,
                          node.get("script", {}).get("name", cursor.owner))
        except (ParseError, ValidationError) as error:
            if isinstance(token, Token):
                error.start = token.start

            if cursor.path:
                error.args = (f"{error}\nAt configuration or command path: {' '.join(self.command_path(cursor.path))}",)

            raise

    def resolve(self, tokens, *, validate=True):
        cursor = Cursor(self.root)

        for token in tokens:
            cursor = self.advance(cursor, token, validate=validate, internal=not isinstance(token, Token))

        return cursor

    def operational(self, tokens, *, validate=True):
        """Resolve commands and record omitted optional values for placeholders."""
        state = self.set_cursor()
        omitted = []
        required_access = set()
        position = 0

        for position, token in enumerate(tokens, 1):
            if self.optional_tag(state.next) and self.operational_input(state.next, token) is not state.next:
                omitted.append(position)

            state = self.advance_operational(state, token, validate=validate)

            # Anchored options are executed together through the anchor's command.
            # Retain each completed option's policy when returning to that anchor.
            if state.anchor is not None and state.boundary:
                required_access.add(self.minimum_access(state.cursor.node))

        cursor = state.cursor
        if cursor.join_negated:
            raise ParseError(f"Expected a value after 'not' at {' '.join(cursor.path)}")
        if cursor.join_value is not None:
            raise ParseError(f"Expected a value after 'and' at {' '.join(cursor.path)}")

        if cursor.expect in {'tag', 'value'} and cursor.node.get('optional_value'):
            omitted.append(position + 1)

        if state.anchor is not None:
            if not isinstance(state.anchor.node.get('command'), dict):
                raise ParseError('An operational anchor requires an executable command')

            if state.cursor is not state.anchor and not state.boundary:
                raise ParseError(f"Operational command is incomplete at {' '.join(state.cursor.path)}")

            cursor = state.anchor

        return replace(cursor, omitted_positions=tuple(omitted), required_access=tuple(sorted(required_access)))

    @staticmethod
    def optional_tag(cursor):
        return (cursor.expect == 'tag' and cursor.node.get('optional_value')
                and isinstance(cursor.node.get('command'), dict))

    def operational_input(self, cursor, token):
        """Declared children take precedence over an optional command value."""
        word = token.value if isinstance(token, Token) else token
        if self.optional_tag(cursor) and prefix_matches(word, cursor.node.get('children', {})):
            return replace(cursor, expect='child')

        if cursor.expect == 'child':
            children = cursor.node.get('children', {})
            keywords = [name for name, child in children.items() if not child.get('positional')]
            positional = self.positional_cursor(cursor)
            if positional is not None and not prefix_matches(word, keywords):
                return positional

        return cursor

    def positional_cursor(self, cursor):
        """Enter a declared positional value without consuming a keyword."""
        if cursor.expect == 'child':
            for name, child in cursor.node.get('children', {}).items():
                if child.get('positional'):
                    return self.advance(cursor, name, internal=True)

        return None

    def advance_operational(self, state, token, *, validate=True):
        if state.cursor.node.get('rest') and state.cursor.expect == 'done':
            return state  # The remaining tokens are opaque arguments, preserved by @line.

        current = state.input(token) if state.cursor.joinable else state.next
        current = self.operational_input(current, token)
        cursor = self.advance(current, token, validate=validate)
        anchor = state.anchor

        if (current.expect == state.next.expect == 'child' and current.node.get('optional_value')
                and self.optional_tag(cursor)):
            raise ParseError('A subcommand must immediately follow its parent command, before a value')

        if anchor is None and cursor.node.get('anchor') and cursor.expect == 'child':
            anchor = cursor

        return SetCursor(cursor, anchor)

    def configuration_path(self, tokens, operation="set"):
        cursor = self.resolve(tokens)
        return self._configuration_cursor(cursor, operation)

    def _configuration_cursor(self, cursor, operation):
        if not cursor.path:
            raise ParseError("A configuration path is required")

        if cursor.join_negated:
            raise ParseError(f"Expected a value after 'not' at {' '.join(cursor.path)}")
        if cursor.join_value is not None:
            raise ParseError(f"Expected a value after 'and' at {' '.join(cursor.path)}")

        if operation == "edit":
            if not self.editable(cursor):
                raise ParseError("Choose a configuration section or a named object to edit; a setting value or an object type without a name cannot be an edit location.")
        elif operation == "set":
            if cursor.expect == "value" or (cursor.expect == 'tag' and cursor.node.get('_negated')):
                raise ParseError(f"Configuration path is incomplete. Expected a value after {cursor.path[-1]!r}.")

        return cursor

    def set_cursor(self, root=()):
        """Start at the edit root, never inheriting an anchor above that root."""
        cursor = self.resolve(root)
        anchor = cursor if (cursor.node.get('anchor') and cursor.expect == 'child') else None

        return SetCursor(cursor, anchor)

    def advance_set(self, state, token, *, validate=True):
        current = state.input(token)
        cursor = self.advance(current, token, validate=validate)
        anchors = list(state.parent_anchors)
        if state.anchor is not None:
            anchors.append(state.anchor)

        # Returning to an outer anchor leaves its nested anchors behind.
        while anchors and current.path[:len(anchors[-1].path)] != anchors[-1].path:
            anchors.pop()

        anchor = anchors.pop() if anchors else None
        # Explicit anchors introduce local scope, including nested tag instances
        # such as VLANs. Unanchored tags still return to the enclosing object.
        if cursor.node.get('anchor') and cursor.expect == 'child':
            if anchor is not None:
                anchors.append(anchor)
            anchor = cursor

        return SetCursor(cursor, anchor, tuple(anchors))

    def set_paths(self, tokens, *, root=()):
        """Expand a complete set command into ordinary validated path cursors.

        Joinable leaves join successive values before emitting a single operation.
        Nested node anchors take precedence, retaining outer anchors until a
        command returns to them. Nested tags can continue into their children or
        return to a named child of the active anchor.
        """
        state = self.set_cursor(root)
        operations = []

        for token in tokens:
            # Finish a value only when input leaves it, so joined prefixes never
            # become separate mutations or separate multi-leaf alternatives.
            # Leaving a bare nested anchor still configures that node (for example log or counter).
            if state.input(token) is not state.cursor:
                operations.append(state.cursor)

            state = self.advance_set(state, token)

        self._configuration_cursor(state.cursor, 'set')

        operations.append(state.cursor)

        return operations

    @staticmethod
    def editable(cursor):
        return (cursor.node["kind"] == "node" and not cursor.node.get('_negation_branch')) or (cursor.node["kind"] == "tag_node" and cursor.expect == "child")

    def candidates(self, cursor, prefix, tree, *, explicit=False, suggested=None):
        """Merge schema choices, configured values and live suggestions.

        Schema descriptions win for declared choices. ``tree`` may be a mapping
        or lazy path lookup; ``suggested`` optionally receives newly discovered
        names. Already selected join terms are omitted, including their opposite
        polarity, before prefix filtering and completion ordering.
        """
        if suggested is not None:
            suggested.clear()

        if cursor.node.get('secret') and cursor.expect in {'value', 'done'}:
            return []

        values = {}
        node = cursor.node

        if cursor.expect == "child":
            values = {k: v.get("description", "") for k, v in node.get("children", {}).items()
                      if not v.get('_negation_branch') and not v.get('positional')}
        elif cursor.joinable:
            values = {'and': 'Join another value to this combination'}
        elif cursor.expect in {"tag", "value"}:
            choices = node.get("choices", {})
            values.update(choices)
            configured = tree(cursor.path) if callable(tree) else lookup(tree, cursor.path)
            if configured is not MISSING:
                existing = configured.keys() if cursor.expect == "tag" else (
                    configured if isinstance(configured, list) else [configured])
                values.update({str(v): "" if cursor.expect == "tag" else "Configured value" for v in existing})

            declared = set(values) | set(node.get('children', {}))

            for reference in node.get("suggestors", []):
                name, arguments = callback_reference(reference)
                if name in self.suggestors:
                    callback = self.suggestors[name]
                    results = (callback.suggest(tree, **arguments) if isinstance(callback, BoundSuggestor)
                               else callback(**arguments))
                    for suggestion in results:
                        if isinstance(suggestion, Suggestion):
                            values[suggestion.value] = suggestion.description
                        else:
                            values[str(suggestion)] = "Suggested value"

            if suggested is not None:
                suggested.update(set(values) - declared)

            # A configured or discovered choice still deserves its schema help.
            values.update(choices)

            if self.optional_tag(cursor):
                values.update({k: v.get('description', '') for k, v in node.get('children', {}).items()})

            if cursor.join_value is not None:
                selected = set(cursor.join_value.split(','))
                values = {value: description for value, description in values.items()
                          if selected.isdisjoint(value.split(','))}

            join = node.get('joinable')
            if isinstance(join, dict) and join.get('negatable'):
                selected = {term.removeprefix('not ') for term in (cursor.join_value or '').split(',')}
                values = {value: description for value, description in values.items()
                          if selected.isdisjoint(term.removeprefix('not ') for term in value.split(','))}
                if cursor.join_negated:
                    values = {value: description for value, description in values.items()
                              if not value.startswith('not ')}
                else:
                    values['not'] = 'Require the following flag to be clear'

            if node.get('negatable') and cursor.join_value is None:
                values['not'] = 'Exclude the following value'

        if cursor.expect == 'child' and node.get('optional_value') and 'command' in node:
            # Optional typed subcommands precede the name; required nested tags
            # (such as a named firewall chain's rule number) follow it normally.
            values = {k: v for k, v in values.items()
                      if not (node['children'][k]['kind'] == 'tag_node'
                              and node['children'][k].get('optional_value')
                              and 'command' in node['children'][k])}

        return [(v, values[v]) for v in sorted(values, key=completion_sort_key) if v.startswith(prefix)]

    def defaults(self, explicit):
        """Always activates beneath a present top-level branch; never invent tags.

        Direct existence is tested against explicit input, never defaults added earlier.
        """
        effective = explicit

        def walk(node, path, branch_active=False):
            nonlocal effective
            kind = node["kind"]
            if kind == "leaf_node":
                default = node.get("default")
                if not default or lookup(explicit, path) is not MISSING:
                    return

                active = lookup(explicit, path[:-1]) is not MISSING if default["mode"] == "direct" else branch_active
                if active:
                    value = default.get("value", True)

                    # Effective views must not share mutable defaults with the
                    # schema or another retrieval/commit's effective tree.
                    effective = put(effective, path, list(value) if node.get("multi") else value)

                return

            children = self._default_children[id(node)]
            if not children:
                return

            if kind == "tag_node":
                for tag in lookup(explicit, path, {}):
                    for name, child in children:
                        walk(child, path + (tag, name), True)

                return

            for name, child in children:
                child_path = path + (name,)
                active = (child["kind"] == "leaf_node" or lookup(explicit, child_path) is not MISSING) if not path else branch_active
                walk(child, child_path, active)

        walk(self.root, ())

        return effective

    def validate_configuration(self, configuration):
        """Validate structure and leaf values; empty containers are valid intent."""

        def validate_at(node, value, path):
            try:
                self.validate(node, value)
            except ValidationError as error:
                error.args = (f"{error}\nAt configuration path: {' '.join(path)}",)
                raise

        def walk(node, value, path):
            if (node.get('_negation_branch') or node.get('_negated') and node['kind'] == 'tag_node') and value == {}:
                raise ValidationError(f"{' '.join(self.command_path(path))}: an exclusion requires a value")
            if node.get('input_only'):
                raise ValidationError('Plaintext passwords must be hashed before storing configuration')

            if node["kind"] == "leaf_node":
                if node.get("valueless"):
                    if value is not True:
                        raise ValidationError(f"{' '.join(path)!r} is an on/off setting. Use true to enable it, or remove the setting.")
                elif node.get("multi"):
                    if not isinstance(value, list) or not value or len(set(map(str, value))) != len(value):
                        raise ValidationError(f"{' '.join(path)!r} requires one or more different values in a JSON array.")

                    for item in value:
                        validate_at(node, item, path)
                else:
                    validate_at(node, value, path)

                return

            if not isinstance(value, dict):
                raise ValidationError(f"Expected named configuration settings under {' '.join(path) or 'the root'!r}, enclosed in JSON braces.")

            if node["kind"] == "tag_node":
                for tag, children in value.items():
                    validate_at(node, tag, path)
                    walk({"kind": "node", "children": node.get("children", {}), "tag_instance": True}, children, path + (tag,))
            else:
                for name, child in value.items():
                    if name not in node.get("children", {}):
                        raise ValidationError(f"Unknown configuration key {' '.join(path + (name,))}")

                    walk(node["children"][name], child, path + (name,))

        walk(self.root, configuration, ())


def completion_extension(prefix, candidates):
    values = [v for v, _ in candidates if not v.startswith("<")]
    return commonprefix(values)[len(prefix):] if values else ""
