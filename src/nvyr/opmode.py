"""Expose explicitly marked operational functions with signature-derived arguments."""

import argparse
import inspect
import sys
import types
import typing


def command(function):
    """Opt a locally defined function into run(); helpers remain private."""
    function.__nvyr_command__ = True
    return function


def _arguments(parser, signature, name):
    """Register a resolved signature; also used by the schema build checks."""
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            raise ValueError(f'{name}: variadic parameters are not supported')

        default = parameter.default
        required = default is parameter.empty
        value_type = parameter.annotation
        if value_type is parameter.empty:
            value_type = None
        if typing.get_origin(value_type) in (typing.Union, types.UnionType):
            members = typing.get_args(value_type)
            if len(members) == 2 and type(None) in members:
                value_type = next(member for member in members if member is not type(None))

        if value_type is None:
            value_type = str if required or default is None else type(default)

        multiple = typing.get_origin(value_type) is list
        if multiple:
            elements = typing.get_args(value_type)
            if len(elements) != 1 or elements[0] not in (str, int, float):
                raise ValueError(f'{name}.{parameter.name}: lists require str, int or float elements')

            value_type = elements[0]

        if value_type not in (str, int, float, bool):
            raise ValueError(f'{name}.{parameter.name}: use str, int, float, bool, list[str/int/float] or an optional annotation')

        positional = (parameter.kind == parameter.POSITIONAL_ONLY or
                      required and parameter.kind == parameter.POSITIONAL_OR_KEYWORD)
        names = [parameter.name] if positional else list(dict.fromkeys(
            ['--' + parameter.name.replace('_', '-'), '--' + parameter.name]))
        options = {}

        if not positional:
            options['dest'] = parameter.name

        if value_type is bool:
            if positional or required or not isinstance(default, bool):
                raise ValueError(f'{name}.{parameter.name}: boolean flags need a true/false default and cannot be positional-only')

            options.update(action=argparse.BooleanOptionalAction, default=default)
        else:
            options['type'] = value_type

            if multiple:
                if not required and default is not None and (
                        not isinstance(default, list) or any(type(value) is not value_type for value in default)):
                    raise ValueError(f'{name}.{parameter.name}: list defaults must be None or a list of the declared element type')

                options['default'] = argparse.SUPPRESS
                if positional:
                    options['nargs'] = '+' if required else '*'
                else:
                    options.update(action='append', required=required)
            elif not required:
                options['default'] = default

                if positional:
                    options['nargs'] = '?'
            elif not positional:
                options['required'] = True

        parser.add_argument(*names, **options)

    return signature


def command_arguments(line, mapping, *, schema=None):
    """Return (anchor path, option argv) using the operational tree's grammar.

    Mapping keys are child names, or tuples for paths through normal nodes.
    Values are one argv string, a list of argv strings, or a function receiving
    the validated leaf value (True for flags) and returning its complete argv.
    Each occurrence of a multi leaf repeats its mapping. The caller places
    positional/tag values.
    """
    from nvyr.errors import ParseError
    from nvyr.lexer import split_pipeline
    from nvyr.schema import Schema, resolve_word

    schema = schema or Schema.bundled('operational')
    tokens = split_pipeline(line)[0]
    if not tokens:
        raise ParseError('Expected an operational command')

    if resolve_word(tokens[0].value, [*schema.root['children'], 'run']) == 'run':
        tokens = tokens[1:]

    state = schema.set_cursor()
    for index, token in enumerate(tokens):
        state = schema.advance_set(state, token)
        if state.anchor is not None:
            break
    else:
        raise ParseError('Expected a complete operational command anchor')

    anchor = state.anchor.path
    arguments = []

    for cursor in schema.set_paths(tokens[index + 1:], root=anchor):
        relative = cursor.path[len(anchor):]
        if not relative:
            continue

        key = relative[0] if len(relative) == 1 else relative
        if cursor.node['kind'] != 'leaf_node' or key not in mapping:
            raise ParseError(f'No argument mapping for {" ".join(cursor.path)}')

        flags = mapping[key]
        if callable(flags):
            translated = flags(cursor.value)
            if not isinstance(translated, list) or any(
                    not isinstance(value, str) or '\x00' in value for value in translated):
                raise ValueError(f'Invalid argument mapping for {key!r}: function must return a list of strings')

            arguments.extend(translated)
            continue

        if isinstance(flags, str):
            flags = [flags]

        if not isinstance(flags, list) or not flags or any(not isinstance(flag, str) or not flag or '\x00' in flag for flag in flags):
            raise ValueError(f'Invalid argument mapping for {key!r}: expected a string or nonempty list of strings')

        arguments.extend(flags)
        if not cursor.node.get('valueless') and cursor.value is not None:
            arguments.append(cursor.value)

    return anchor, arguments


def run(argv=None, *, namespace=None):
    """Dispatch a public @command from __main__ (or an explicit module namespace).

    Required ordinary parameters are positional arguments; defaulted parameters
    and keyword-only parameters are named options. Boolean defaults produce flags
    with --no-* counterparts. List options repeat their flag; positional lists
    consume multiple arguments. Commands may print output or return a string.
    """
    from nvyr.errors import RouterError

    namespace = vars(sys.modules['__main__']) if namespace is None else namespace
    parser = argparse.ArgumentParser(description=namespace.get('__doc__'), allow_abbrev=False)
    subparsers = parser.add_subparsers(required=True)
    functions = {}

    try:
        for name, function in sorted(namespace.items()):
            if (name.startswith('_') or not inspect.isfunction(function) or
                    function.__module__ != namespace.get('__name__') or
                    not getattr(function, '__nvyr_command__', False)):
                continue

            if inspect.iscoroutinefunction(function) or inspect.isgeneratorfunction(function):
                raise ValueError(f'{name}: operational commands must be ordinary synchronous functions')

            help_text = inspect.getdoc(function)
            child = subparsers.add_parser(name, help=help_text, description=help_text, allow_abbrev=False)
            signature = inspect.signature(function)
            hints = typing.get_type_hints(function)
            signature = signature.replace(parameters=[
                parameter.replace(annotation=hints.get(parameter.name, parameter.annotation))
                for parameter in signature.parameters.values()])
            functions[name] = function, _arguments(child, signature, name)

        if not functions:
            raise ValueError('No public @opmode.command functions are defined in this script')
    except (ValueError, TypeError, NameError, argparse.ArgumentError) as error:
        parser.error(f'Invalid operational script: {error}')

    words = list(sys.argv[1:] if argv is None else argv)
    arguments = vars(parser.parse_args(words))
    function, signature = functions[words[0]]

    for parameter in signature.parameters.values():
        if parameter.name not in arguments:
            default = parameter.default
            arguments[parameter.name] = list(default) if isinstance(default, list) else default

    positional = [arguments.pop(parameter.name) for parameter in signature.parameters.values()
                  if parameter.kind == parameter.POSITIONAL_ONLY]

    try:
        result = function(*positional, **arguments)
    except (KeyboardInterrupt, EOFError):
        parser.exit(130, '\nCommand cancelled.\n')
    except RouterError as error:
        parser.exit(1, f'{error}\n')

    if result is not None:
        if not isinstance(result, str):
            raise TypeError('Operational commands must return text or None')

        print(result, end='' if not result or result.endswith('\n') else '\n')

