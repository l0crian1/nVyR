"""The readable command inventory follows the schemas and preserves tree layout."""

import pytest

from build_tools import command_tree
from build_tools.command_tree import OUTPUT, generate, render_tree


def test_inline_choices_wrap_with_aligned_connectors():
    root = {'children': {
        'protocol': {'kind': 'leaf_node', 'negatable': True,
                     'choices': {'alpha': '', 'bravo': '', 'charlie': '', 'delta': ''}},
        'zulu': {'kind': 'leaf_node', 'valueless': True},
    }}
    assert render_tree('rule <number>', root, width=34) == (
        'rule <number>\n'
        '├── protocol [not] <alpha|bravo|\n'
        '│                   charlie|delta>\n'
        '└── zulu'
    )


def test_nested_last_child_choices_hints_optional_and_joined_values():
    root = {'children': {
        'objects': {'kind': 'tag_node', 'optional_value': True, 'hints': {'name': ''},
                    'children': {'status': {'kind': 'leaf_node', 'joinable': True,
                                           'choices': {'confirmed': '', 'assured': ''}}}},
    }}
    text = render_tree('show', root, width=42)
    assert text == (
        'show\n'
        '└── objects [<name>]\n'
        '    └── status <confirmed|assured>\n'
        '                [and <value> ...]'
    )


def test_generated_command_tree_is_current():
    text = generate()
    assert OUTPUT.read_text(encoding='utf-8') == text
    assert '## Configuration paths' in text
    assert '## Configuration-mode commands' in text
    assert '## Operational commands' in text
    assert '## Pipe modifiers' in text
    assert 'protocol [not] <' in text
    assert 'source-address [not] <' in text
    assert 'load [replace] [set] <file>' in text
    assert '_negation_branch' not in text


def test_check_rejects_missing_and_stale_document(tmp_path, monkeypatch):
    output = tmp_path / 'command-tree.md'
    monkeypatch.setattr(command_tree, 'OUTPUT', output)
    monkeypatch.setattr(command_tree, 'generate', lambda: 'current tree\n')
    monkeypatch.setattr('sys.argv', ['command_tree', '--check'])

    with pytest.raises(SystemExit) as error:
        command_tree.main()

    assert error.value.code == 1

    output.write_text('old tree\n', encoding='utf-8')

    with pytest.raises(SystemExit) as error:
        command_tree.main()

    assert error.value.code == 1

    output.write_text('current tree\n', encoding='utf-8')
    command_tree.main()
