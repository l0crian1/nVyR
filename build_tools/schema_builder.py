"""Expand YAML schema fragments into standalone runtime JSON."""

import argparse
import ast
import copy
from inspect import Parameter, Signature, signature
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import tempfile
import typing

import yaml


ROOT = Path(__file__).resolve().parents[1]

# Builds run before nVyR is installed. Load the dependency-free validator source
# from this checkout so signature checks never use a different installed version.
VALIDATORS = runpy.run_path(str(ROOT / 'src/nvyr/helpers/validators.py'))['REGISTRY']
OP_ARGUMENTS = runpy.run_path(str(ROOT / 'src/nvyr/opmode.py'))['_arguments']
SCRIPT_INDEX = runpy.run_path(str(ROOT / 'src/nvyr/helpers/script_schema.py'))['ScriptIndex']
VALIDATE_REAPPLY = runpy.run_path(str(ROOT / 'src/nvyr/helpers/reapply_schema.py'))['validate_reapply']


class SchemaBuildError(ValueError):
    """Invalid schema source or include operation."""


class SchemaLoader(yaml.SafeLoader):
    """Safe YAML with JSON scalar resolution, string keys and no silent overwrites."""

    # Do not mutate SafeLoader globally or inherit YAML 1.1's yes/on, octal,
    # sexagesimal and timestamp conversions. Quoted scalars remain strings.
    yaml_implicit_resolvers = {}

    def construct_mapping(self, node, deep=False):
        result = {}

        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise SchemaBuildError(f'YAML mapping keys must be strings at {key_node.start_mark}')

            if key in result:
                raise SchemaBuildError(f'Duplicate YAML key {key!r} at {key_node.start_mark}')

            if key == 'command' or key.endswith('/command'):
                if isinstance(value_node, yaml.SequenceNode):
                    for argument in value_node.value:
                        if (not isinstance(argument, yaml.ScalarNode)
                                or argument.tag != 'tag:yaml.org,2002:str'
                                or argument.style not in ("'", '"')):
                            raise SchemaBuildError(f'Command arguments must be explicitly quoted strings at {argument.start_mark}')

            if re.search(r'/command/(?:-|[0-9]+)$', key):
                if (not isinstance(value_node, yaml.ScalarNode)
                        or value_node.tag != 'tag:yaml.org,2002:str'
                        or value_node.style not in ("'", '"')):
                    raise SchemaBuildError(f'Command arguments must be explicitly quoted strings at {value_node.start_mark}')

            result[key] = self.construct_object(value_node, deep=deep)

        return result


for _tag, _pattern, _initial in (
    ('null', r'null', 'n'),
    ('bool', r'true|false', 'tf'),
    ('int', r'-?(?:0|[1-9][0-9]*)', '-0123456789'),
    ('float', r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)', '-0123456789'),
):
    SchemaLoader.add_implicit_resolver('tag:yaml.org,2002:' + _tag,
                                     re.compile(r'\A(?:' + _pattern + r')\Z'), list(_initial))


def _assert_json_values(value, ancestors=frozenset()):
    """Reject YAML-only values and recursive aliases before expanding includes."""
    if isinstance(value, (dict, list)):
        if id(value) in ancestors:
            raise SchemaBuildError('Recursive YAML aliases are not supported')

        ancestors = ancestors | {id(value)}

        for item in value.values() if isinstance(value, dict) else value:
            _assert_json_values(item, ancestors)
    elif value is not None and type(value) not in (str, bool, int, float):
        raise SchemaBuildError(f'Unsupported YAML value type: {type(value).__name__}; use JSON-compatible values')
    elif isinstance(value, float) and not math.isfinite(value):
        raise SchemaBuildError('Non-finite numbers are not supported in runtime JSON')


def _tokens(pointer):
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise SchemaBuildError(f'Expected a non-root JSON Pointer, got {pointer!r}')

    if re.search(r'~(?![01])', pointer):
        raise SchemaBuildError(f'Invalid JSON Pointer escape in {pointer!r}')

    return [part.replace('~1', '/').replace('~0', '~') for part in pointer[1:].split('/')]


def _key(container, token):
    if isinstance(container, dict):
        if token in container:
            return token
    elif isinstance(container, list) and re.fullmatch(r'0|[1-9][0-9]*', token):
        # Compare before conversion so arbitrarily long invalid indexes fail cleanly.
        if len(token) <= len(str(len(container))) and int(token) < len(container):
            return int(token)

    raise SchemaBuildError(f'Path component {token!r} does not exist')


def _modify(document, operation, pointer, value=None):
    """Apply one include edit in place using JSON Pointer addressing.

    Object additions require absent keys; list additions only append via /-.
    Replacement/addition values are copied so include consumers cannot share
    mutable edit values. Missing targets are errors rather than implicit creation.
    """
    try:
        tokens = _tokens(pointer)
        parent = document

        for token in tokens[:-1]:
            parent = parent[_key(parent, token)]

        token = tokens[-1]

        if operation == 'add':
            if isinstance(parent, dict):
                if token in parent:
                    raise SchemaBuildError('Target already exists; use replace')

                parent[token] = copy.deepcopy(value)
            elif isinstance(parent, list) and token == '-':
                parent.append(copy.deepcopy(value))
            else:
                raise SchemaBuildError('Add requires a missing object key or /- to append to a list')
        else:
            key = _key(parent, token)

            if operation == 'remove':
                del parent[key]
            else:
                parent[key] = copy.deepcopy(value)
    except SchemaBuildError as error:
        raise SchemaBuildError(f'{operation} {pointer!r}: {error}') from error


class SchemaBuilder:
    def __init__(self, includes):
        self.includes = Path(includes).resolve()

    def resolve_file(self, path, stack=()):
        path = Path(path).resolve()
        if path in stack:
            chain = ' -> '.join(str(item) for item in (*stack, path))
            raise SchemaBuildError(f'Include cycle: {chain}')

        try:
            document = yaml.load(path.read_text(encoding='utf-8'), Loader=SchemaLoader)
            if not isinstance(document, dict):
                raise SchemaBuildError('Schema files must contain a YAML mapping')

            _assert_json_values(document)

            return self._resolve(document, (*stack, path))
        except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
            raise SchemaBuildError(f'{path}: {error}') from error

    def _include_path(self, name):
        if not isinstance(name, str) or not name or '\\' in name or ':' in name or '\x00' in name:
            raise SchemaBuildError('Include file must be a relative POSIX path ending in .yaml.i')

        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or not name.endswith('.yaml.i'):
            raise SchemaBuildError(f'Invalid include file {name!r}; use a path under the include directory ending in .yaml.i')

        path = (self.includes / name).resolve()
        if not path.is_relative_to(self.includes):
            raise SchemaBuildError(f'Include file {name!r} escapes the include directory')

        return path

    def _resolve(self, value, stack):
        if isinstance(value, list):
            return [self._resolve(item, stack) for item in value]

        if not isinstance(value, dict):
            return value

        result = {}

        for key, item in value.items():
            if key == 'include_schema':
                if not isinstance(item, list):
                    raise SchemaBuildError('include_schema must be a list of file entries')

                for index, spec in enumerate(item):
                    try:
                        additions = self._include(spec, stack)
                        self._merge(result, additions)
                    except SchemaBuildError as error:
                        name = spec.get('file') if isinstance(spec, dict) else spec
                        raise SchemaBuildError(f'include_schema[{index}] ({name!r}): {error}') from error
            else:
                self._merge(result, {key: self._resolve(item, stack)})

        return result

    @staticmethod
    def _merge(result, additions):
        for key, item in additions.items():
            if key in result:
                raise SchemaBuildError(f'Included or local key {key!r} conflicts with existing content; '
                                       'use per-file edits or a distinct as name')

            result[key] = item

    def _include(self, spec, stack):
        """Expand one fragment, then apply remove/replace/add edits in that order.

        Edits address the included node's contents, not its wrapper name. ``as``
        renames that wrapper; ``as: null`` returns only its contents for merging.
        """
        if (not isinstance(spec, dict) or 'file' not in spec or
                set(spec) - {'file', 'as', 'remove', 'replace', 'add'}):
            raise SchemaBuildError('Each include_schema entry requires file and supports only as, remove, replace, add')

        document = self.resolve_file(self._include_path(spec['file']), stack)
        if len(document) != 1:
            raise SchemaBuildError('Include files must define exactly one named node')

        name, result = next(iter(document.items()))
        if not name or name == 'include_schema' or not isinstance(result, dict):
            raise SchemaBuildError('An included node must have a nonempty name and mapping contents')

        target = spec.get('as', name)
        if target is not None and (not isinstance(target, str) or not target or target == 'include_schema'):
            raise SchemaBuildError('as must be a nonempty node name or null to include node contents')

        # Nested includes are expanded before edits, including fragments used as edit values.
        for operation in ('remove', 'replace', 'add'):
            changes = spec.get(operation, [] if operation == 'remove' else {})

            if operation == 'remove':
                if not isinstance(changes, list) or not all(isinstance(p, str) for p in changes):
                    raise SchemaBuildError('remove must be a list of JSON Pointers')

                for pointer in changes:
                    _modify(result, operation, pointer)
            else:
                if not isinstance(changes, dict):
                    raise SchemaBuildError(f'{operation} must map JSON Pointers to values')

                for pointer, item in changes.items():
                    _modify(result, operation, pointer, self._resolve(item, stack))

        return result if target is None else {target: result}


def _assert_expanded(value):
    if isinstance(value, dict):
        if 'include_schema' in value:
            raise SchemaBuildError('An edit introduced unresolved include_schema; include it in an object value instead')

        for item in value.values():
            _assert_expanded(item)
    elif isinstance(value, list):
        for item in value:
            _assert_expanded(item)


def _prepare_firewall_failsafe(document):
    """The ephemeral firewall has local references, not dependency registrations."""
    node = document.get('children', {}).get('firewall', {}).get('children', {}).get('fail-safe')
    if node is None:
        return

    def visit(node):
        children = node.get('children', {})
        children.pop('source-domain-group', None)
        children.pop('destination-domain-group', None)

        for key in ('dependency', 'depends', 'reapply-on-change', 'dependency-format'):
            node.pop(key, None)

        suggestion = node.get('suggestors', {}).get('config-path')
        if suggestion and suggestion.get('path', '').startswith('firewall '):
            suggestion['path'] = suggestion['path'].replace('firewall ', 'firewall fail-safe ', 1)

        for child in node.get('children', {}).values():
            visit(child)

    visit(node)


def _describe_defaults(node):
    """Decorate the fully expanded configuration tree, never its source fragments."""
    default = node.get('default')
    if default is not None:
        value = default.get('value', True)
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        node['description'] = f"{node.get('description', '')} (default: {text})".lstrip()

    for child in node.get('children', {}).values():
        _describe_defaults(child)


def _normalize_callbacks(node, path=(), *, operational=False):
    """Validate node metadata and lower callback mappings after include edits.

    Mutates the expanded tree into runtime callback lists. Configuration and
    operational nodes share validation except for explicitly operational syntax.
    """
    if 'positional' in node and (type(node['positional']) is not bool
            or not operational or node.get('kind') != 'tag_node'
            or not (isinstance(node.get('command'), list) or 'command' not in node and node.get('children'))
            or any(node.get(option) for option in ('optional_value', 'anchor', 'negatable', 'rest'))):
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: positional requires an operational tag with a command or children")

    if sum(bool(child.get('positional')) for child in node.get('children', {}).values()) > 1:
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: only one positional child is allowed")

    if 'negatable' in node and (type(node['negatable']) is not bool or
            node.get('kind') not in {'leaf_node', 'tag_node'} or node.get('valueless') or node.get('rest')):
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: negatable requires a boolean on a valued leaf or tag")
    join = node.get('joinable')
    valid_join = type(join) is bool or (
        isinstance(join, dict) and set(join) == {'negatable'} and type(join['negatable']) is bool)
    if 'joinable' in node and (not valid_join or
            node.get('kind') != 'leaf_node' or node.get('valueless') or node.get('rest')):
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: joinable requires a boolean or {{negatable: boolean}} on a valued leaf")

    if 'rename' in node and (type(node['rename']) is not bool or node.get('kind') != 'tag_node'):
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: rename requires a boolean on a tag_node")

    if 'dependency-format' in node and (node.get('kind') != 'tag_node' or 'dependency' not in node
                                      or node['dependency-format'] != '{parent}.{value}'):
        raise SchemaBuildError('dependency-format requires {parent}.{value} on a dependency tag node')

    for key in ('dependency', 'depends'):
        if key in node:
            value = node[key]
            if (not isinstance(value, str) or not value or any(character.isspace() for character in value)
                    or node.get('kind') not in ('tag_node', 'leaf_node') or node.get('valueless')):
                raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: {key} requires a nonempty type name on a valued leaf or tag node")

    if 'access' in node and node['access'] not in ('read-only', 'net-admin', 'sys-admin', 'dev-admin'):
        raise SchemaBuildError(f"{'/'.join(path) or '<root>'}: invalid access {node['access']!r}; expected read-only, net-admin, sys-admin or dev-admin")

    if 'validators' in node:
        validators = node['validators']
        location = '/'.join((*path, 'validators'))

        if not isinstance(validators, dict) or validators.get('mode', 'AND') not in ('AND', 'OR'):
            raise SchemaBuildError(f'{location}: validators require a mapping with mode AND or OR')

        checks = {}

        for name, arguments in validators.items():
            if name == 'mode':
                continue

            if (name in {'checks', 'names'} or not name
                    or not isinstance(arguments, dict)):
                raise SchemaBuildError(f'{location}: use validator-name: {{arguments}}, or {{}} for no arguments; '
                                       'aliases, checks wrappers and lists are not supported in YAML sources')

            if name not in VALIDATORS:
                raise SchemaBuildError(f'{location}: unknown validator {name!r}')

            try:
                parameters = signature(VALIDATORS[name])

                # Report misspelled keywords before any missing required ones.
                parameters.bind_partial('', **arguments)
                parameters.bind('', **arguments)
            except TypeError as error:
                raise SchemaBuildError(f'{location}: invalid arguments for validator {name!r}: {error}') from error

            checks[name] = {'name': name}

            if arguments:
                checks[name]['args'] = arguments

        node['validators'] = {'mode': validators.get('mode', 'AND'), 'checks': checks}

    if 'suggestors' in node:
        suggestors = node['suggestors']
        location = '/'.join((*path, 'suggestors'))

        if not isinstance(suggestors, dict):
            raise SchemaBuildError(f'{location}: suggestors require a mapping of suggestor names to arguments')

        references = []

        for name, arguments in suggestors.items():
            if not name or not isinstance(arguments, dict):
                raise SchemaBuildError(f'{location}: use suggestor-name: {{arguments}}, or {{}} for no arguments')

            reference = {'name': name}

            if arguments:
                reference['args'] = arguments

            references.append(reference)

        node['suggestors'] = references

    for name, child in node.get('children', {}).items():
        _normalize_callbacks(child, (*path, name), operational=operational)


def _annotation(node):
    """Read the supported signature types without evaluating script code."""
    if node is None:
        return Parameter.empty

    if isinstance(node, ast.Constant):
        if node.value is None:
            return type(None)
        if isinstance(node.value, str):
            return _annotation(ast.parse(node.value, mode='eval').body)

    names = {'str': str, 'int': int, 'float': float, 'bool': bool, 'list': list,
             'Optional': typing.Optional, 'List': typing.List, 'Union': typing.Union}
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'typing' and node.attr in names:
        return names[node.attr]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation(node.left) | _annotation(node.right)
    if isinstance(node, ast.Subscript):
        element = (tuple(_annotation(item) for item in node.slice.elts)
                   if isinstance(node.slice, ast.Tuple) else _annotation(node.slice))
        return _annotation(node.value)[element]

    raise ValueError(f'Cannot statically check annotation {ast.unparse(node)!r}; use supported opmode types')


def _script_signatures(path):
    """Inspect public, explicitly registered functions; never import the script."""
    module = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    decorators = set()

    for node in module.body:
        if isinstance(node, ast.ImportFrom) and node.module == 'nvyr':
            decorators.update((item.asname or item.name) + '.command' for item in node.names if item.name == 'opmode')
        elif isinstance(node, ast.ImportFrom) and node.module == 'nvyr.opmode':
            decorators.update(item.asname or item.name for item in node.names if item.name == 'command')
        elif isinstance(node, ast.Import):
            decorators.update((item.asname or item.name) + '.command' for item in node.names if item.name == 'nvyr.opmode')

    functions = {}
    for node in module.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name.startswith('_'):
            continue
        if not any(ast.unparse(decorator) in decorators for decorator in node.decorator_list):
            continue
        if isinstance(node, ast.AsyncFunctionDef):
            raise ValueError(f'{node.name}: operational commands must be synchronous')

        parameters = []
        args = node.args
        ordinary = args.posonlyargs + args.args
        defaults = [None] * (len(ordinary) - len(args.defaults)) + args.defaults
        entries = [(arg, Parameter.POSITIONAL_ONLY if index < len(args.posonlyargs) else Parameter.POSITIONAL_OR_KEYWORD, default)
                   for index, (arg, default) in enumerate(zip(ordinary, defaults))]
        if args.vararg:
            entries.append((args.vararg, Parameter.VAR_POSITIONAL, None))
        entries.extend((arg, Parameter.KEYWORD_ONLY, default) for arg, default in zip(args.kwonlyargs, args.kw_defaults))
        if args.kwarg:
            entries.append((args.kwarg, Parameter.VAR_KEYWORD, None))

        for arg, kind, default in entries:
            parameters.append(Parameter(arg.arg, kind, annotation=_annotation(arg.annotation),
                                        default=Parameter.empty if default is None else ast.literal_eval(default)))

        functions[node.name] = Signature(parameters)

    return functions


class _RuntimeValue(str):
    """A placeholder whose contents cannot be type-checked until execution."""


class _HelpRequested(Exception):
    """argparse completed a help request without requiring function arguments."""


class _MappingParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)

    def print_help(self, file=None):
        pass  # Validate help mappings without printing usage during a build.

    def exit(self, status=0, message=None):
        if status == 0:
            raise _HelpRequested

        raise ValueError(message or 'Invalid operational arguments')

    def add_argument(self, *args, **kwargs):
        convert = kwargs.get('type')
        if convert:
            # Placeholder values arrive at runtime. Check their presence and
            # position now, and validate literal values using the actual type.
            kwargs['type'] = lambda value: value if isinstance(value, _RuntimeValue) else convert(value)

        return super().add_argument(*args, **kwargs)


def _check_script_command(arguments, directory, cache):
    """Check fixed op-script mappings against parsed public function signatures.

    Script source is inspected without executing it. Placeholder values stand in
    for runtime tokens while argparse checks the declared options and arguments.
    Native commands outside the .nvyr.op namespace are not introspected here.
    """
    executable = arguments[0]
    if not executable.endswith('.nvyr.op'):
        return

    name = executable.removesuffix('.nvyr.op')
    if not re.fullmatch(r'[a-z][a-z0-9_]*', name):
        raise ValueError(f'Invalid operational script executable {executable!r}')

    path = directory / f'{name}.py'
    if not path.is_file():
        raise ValueError(f'Operational script {executable!r} does not exist')
    if len(arguments) < 2 or arguments[1].startswith('@'):
        raise ValueError(f'{executable}: specify a fixed @opmode.command function')
    if name not in cache:
        cache[name] = _script_signatures(path)

    function = arguments[1]
    if function not in cache[name]:
        raise ValueError(f'{executable}: {function!r} is not a public @opmode.command function')

    parser = _MappingParser(prog=f'{executable} {function}', allow_abbrev=False)
    OP_ARGUMENTS(parser, cache[name][function], function)

    values = []
    for argument in arguments[2:]:
        if argument.startswith('@') and not argument.startswith('@@') and not re.fullmatch(r'@(?:[1-9][0-9]*|line(?:-[1-9][0-9]*(?:-[1-9][0-9]*)?)?)', argument):
            raise ValueError(f'{executable} {function}: invalid placeholder {argument!r}')

        values.append(argument[1:] if argument.startswith('@@') else
                      _RuntimeValue(argument) if argument.startswith('@') else argument)

    try:
        parser.parse_args(values)
    except _HelpRequested:
        return
    except ValueError as error:
        raise ValueError(f'{executable} {function}: {error}') from error


def _normalize_commands(node, path=(), *, scripts, cache):
    """Keep operational YAML as argv lists; preserve the existing runtime dispatch."""
    location = '/'.join(path) or 'root'

    if set(node) & {'script', 'argv', 'value_argv'}:
        raise SchemaBuildError(f'{location}: use command: [\'executable\', \'argument\']; script, argv and value_argv are not operational YAML syntax')

    if 'command' in node:
        arguments = node['command']
        if (not isinstance(arguments, list) or not arguments
                or not all(isinstance(arg, str) and '\x00' not in arg for arg in arguments)
                or not arguments[0] or arguments[0].startswith('@') and not arguments[0].startswith('@@')):
            raise SchemaBuildError(f'{location}: command requires a nonempty list of quoted strings with a fixed executable')

        # These are CLI/session actions, not external programs. Keep their existing
        # runtime handlers, including the access checks on configure and shell.
        builtins = {'configure', 'configure-draft', 'running', 'version', 'license', 'exit', 'shell', 'terminal-length'}
        if arguments[0] in builtins:
            if len(arguments) != 1 or 'timeout' in node or 'stream' in node:
                raise SchemaBuildError(f'{location}: built-in command {arguments[0]!r} does not take arguments, timeout or stream')

            node['command'] = arguments[0]
        else:
            try:
                _check_script_command(arguments, scripts, cache)
            except (ValueError, TypeError, OSError, SyntaxError, argparse.ArgumentError) as error:
                raise SchemaBuildError(f'{location}: {error}') from error

            command = {'argv': arguments}

            for option in ('timeout', 'stream'):
                if option in node:
                    command[option] = node.pop(option)

            node['command'] = command
    elif 'timeout' in node or 'stream' in node:
        raise SchemaBuildError(f'{location}: timeout and stream require a command')

    for name, child in node.get('children', {}).items():
        _normalize_commands(child, (*path, name), scripts=scripts, cache=cache)


def script_inventory(index):
    """Group explicit script declarations without expanding inherited ownership."""
    records = {}
    for path, name in index.patterns:
        node = index.root
        parts = []
        for part in path:
            if part is None:
                parts.append('<name>')
            else:
                node = node['children'][part]
                parts.append(part)

        if node['kind'] == 'tag_node':
            parts.append('<name>')

        record = records.setdefault(name, {
            'script': name, 'priority': index.owners[name][1], 'paths': [],
        })
        record['paths'].append(' '.join(parts) or '<root>')

    for record in records.values():
        record['paths'].sort()

    return sorted(records.values(), key=lambda record: (record['priority'], record['script']))


def build_schemas(source=ROOT / 'schemas', output=ROOT / 'src/nvyr/schemas', *, check=False,
                  op_scripts=ROOT / 'src/nvyr/op_scripts'):
    """Resolve every top-level .yaml; validate all inputs before writing any JSON."""
    source, output = Path(source), Path(output)
    paths = sorted(source.glob('*.yaml'))
    if not paths:
        raise SchemaBuildError(f'No schema sources found in {source}')

    if source.resolve() == output.resolve():
        raise SchemaBuildError('Schema source and output directories must differ')

    builder = SchemaBuilder(source / 'includes')
    rendered = {}

    for path in paths:
        document = builder.resolve_file(path)
        _assert_expanded(document)

        if path.stem == 'configuration':
            _prepare_firewall_failsafe(document)

        try:
            _normalize_callbacks(document, operational=path.stem == 'operational')

            if path.stem == 'operational':
                _normalize_commands(document, scripts=Path(op_scripts), cache={})
            VALIDATE_REAPPLY(document)
        except ValueError as error:
            raise SchemaBuildError(f'{path}: {error}') from error

        if path.stem == 'configuration':
            try:
                index = SCRIPT_INDEX(document)
            except ValueError as error:
                raise SchemaBuildError(f'{path}: {error}') from error

            _describe_defaults(document)
            inventory = script_inventory(index)
            rendered['script-priorities.json'] = (json.dumps(inventory, indent=2) + '\n').encode('utf-8')

        rendered[path.with_suffix('.json').name] = (json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')

    changed = [name for name, data in rendered.items()
               if not (output / name).is_file() or (output / name).read_bytes() != data]

    if check:
        if changed:
            raise SchemaBuildError('Generated schemas are missing or stale: ' + ', '.join(changed))

        return

    output.mkdir(parents=True, exist_ok=True)

    for name in changed:
        temporary = None

        try:
            with tempfile.NamedTemporaryFile(dir=output, prefix='.' + name, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(rendered[name])

            temporary.chmod(0o644)
            os.replace(temporary, output / name)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'schemas')
    parser.add_argument('--output', type=Path, default=ROOT / 'src/nvyr/schemas')
    parser.add_argument('--check', action='store_true', help='Fail if generated files are missing or stale')
    args = parser.parse_args()

    try:
        build_schemas(args.source, args.output, check=args.check)
    except (SchemaBuildError, OSError) as error:
        parser.exit(1, f'Schema build failed: {error}\n')


if __name__ == '__main__':
    main()
