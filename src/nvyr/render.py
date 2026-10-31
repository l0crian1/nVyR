"""Daemon-side rendering and reversible CLI serialization."""

import json
from collections.abc import Mapping
from nvyr.lexer import Token, quote
from nvyr.tree import MISSING, changes, put, lookup


def json_text(tree):
    return json.dumps(tree, indent=2, ensure_ascii=False, sort_keys=True,
                      default=lambda value: dict(value) if isinstance(value, Mapping) else value) + "\n"


def leaf_value(node, value):
    """Serialize joined values using the same grammar as interactive input."""
    if node.get('negatable') and value == 'not':
        return "'not'"
    if node.get('joinable'):
        join = node['joinable']
        if isinstance(join, dict) and join.get('negatable'):
            return ' and '.join('not ' + quote(part[4:]) if part.startswith('not ') else quote(part)
                                for part in value.split(','))
        return ' and '.join(quote(part) for part in value.split(','))

    return quote(value)


def tag_token(node, value):
    """Keep a literal tag named not distinct from the exclusion keyword."""
    if node.get('negatable') and value == 'not':
        return Token(value, 0, 0, quoted=True)
    return value


def candidate_json(before, after):
    """Render changed branches only; minus/plus lines retain removed/replaced values."""
    if before is MISSING or after is MISSING:
        return marked_json(before, after)

    removed, added = {}, {}

    for path, old, new in changes(before, after):
        if old is not MISSING:
            removed = put(removed, path, old)

        if new is not MISSING:
            added = put(added, path, new)

    if removed == {}:
        return json_text(added)

    return marked_json(removed, added)


def set_commands(schema, tree, path=(), node=None):
    node = schema.root if node is None else node
    if node['kind'] != 'leaf_node' and not tree and path:
        yield "set " + " ".join(map(quote, path))
    elif node["kind"] == "leaf_node":
        prefix = "set " + " ".join(map(quote, path))

        if node.get("valueless"):
            yield prefix
        else:
            for value in tree if node.get("multi") else [tree]:
                yield prefix + " " + leaf_value(node, value)
    elif node["kind"] == "tag_node":
        for tag, value in sorted(tree.items()):
            token = tag_token(node, tag)
            if not value:
                yield "set " + " ".join(map(quote, path + (token,)))
            else:
                instance = {'kind': 'node', 'children': node.get('children', {}), 'tag_instance': True}
                yield from set_commands(schema, value, path + (token,), instance)
    elif node.get("tag_instance") and not tree:
        yield "set " + " ".join(map(quote, path))
    else:
        for key, child in sorted(tree.items()):
            if node['children'][key].get('_negation_branch'):
                for field, excluded in sorted(child.items()):
                    yield from set_commands(schema, excluded, path + (field, 'not'),
                                            node['children'][key]['children'][field])
                continue
            yield from set_commands(schema, child, path + (key,), node["children"][key])


def scope_node(schema, path):
    # Display paths may contain privacy aliases. Validation already happened
    # while selecting the original configuration scope.
    cursor = schema.resolve(path, validate=False)
    if cursor.node["kind"] == "tag_node" and cursor.expect == "child":
        return {"kind": "node", "children": cursor.node.get("children", {}), "tag_instance": True}

    return cursor.node


def diff_commands(schema, before, after, path=(), *, prefix=None, include_unchanged=False):
    """Serialize changes in scope, optionally including retained configuration."""

    def walk(node, old, new, path):
        if old is new or old == new:
            if include_unchanged and new is not MISSING:
                yield from set_commands(schema, new, path, node)

            return

        prefix = " ".join(map(quote, path))

        if new is MISSING:
            yield "delete " + prefix
            return

        if old is MISSING:
            if node.get("tag_instance") and not new:
                yield "set " + prefix
            else:
                yield from set_commands(schema, new, path, node)

            return

        if node["kind"] == "leaf_node":
            if node.get("multi"):
                for value in old:
                    if value not in new:
                        yield "delete " + prefix + " " + leaf_value(node, value)

                for value in new:
                    if include_unchanged or value not in old:
                        yield "set " + prefix + " " + leaf_value(node, value)
            else:
                yield from set_commands(schema, new, path, node)
        else:
            keys = sorted(old.keys() | new.keys())
            # Emit exclusions after ordinary fields: broad field deletions clear both.
            if node['kind'] != 'tag_node' and node.get('children', {}).get('not', {}).get('_negation_branch') and 'not' in keys:
                keys.remove('not')
                keys.append('not')

            for key in keys:
                child = {"kind": "node", "children": node.get("children", {}), "tag_instance": True} if node["kind"] == "tag_node" else node["children"][key]
                if child.get('_negation_branch'):
                    left, right = old.get(key, {}), new.get(key, {})
                    for field in sorted(left.keys() | right.keys()):
                        previous = left.get(field, MISSING)
                        # Deleting an entire field also removes its exclusions.
                        # Restore any retained exclusions after that broad deletion.
                        if field in old and field not in new:
                            previous = MISSING
                        yield from walk(child['children'][field], previous,
                                        right.get(field, MISSING), path + (field, 'not'))
                    continue
                token = tag_token(node, key) if node['kind'] == 'tag_node' else key
                yield from walk(child, old.get(key, MISSING), new.get(key, MISSING), path + (token,))

    yield from walk(scope_node(schema, path), lookup(before, path), lookup(after, path),
                    path if prefix is None else prefix)


def marked_json(before, after):
    """Match object keys, never similar text inside unrelated subtrees.

    Each side retains its own commas, so selecting context and minus/plus lines
    reconstructs the respective JSON tree. Lists and scalar replacements are atomic.
    """

    def block(value, depth, key, comma):
        lines = json_text(value).splitlines()
        label = "" if key is None else json.dumps(key, ensure_ascii=False) + ": "
        padding = "  " * depth
        lines[0] = label + lines[0]
        lines[-1] += comma

        return [padding + line for line in lines]

    def walk(old, new, depth=0, key=None, old_comma="", new_comma=""):
        if old is MISSING:
            yield from ("+ " + line for line in block(new, depth, key, new_comma))
        elif new is MISSING:
            yield from ("- " + line for line in block(old, depth, key, old_comma))
        elif old == new:
            left = block(old, depth, key, old_comma)
            right = block(new, depth, key, new_comma)

            for a, b in zip(left, right):
                if a == b:
                    yield "  " + a
                else:
                    yield "- " + a
                    yield "+ " + b
        elif isinstance(old, Mapping) and isinstance(new, Mapping) and old and new:
            padding = "  " * depth
            label = "" if key is None else json.dumps(key, ensure_ascii=False) + ": "
            yield "  " + padding + label + "{"
            old_last, new_last = max(old), max(new)

            for child in sorted(old.keys() | new.keys()):
                yield from walk(old.get(child, MISSING), new.get(child, MISSING), depth + 1, child,
                                "" if child == old_last else ",", "" if child == new_last else ",")

            if old_comma == new_comma:
                yield "  " + padding + "}" + old_comma
            else:
                yield "- " + padding + "}" + old_comma
                yield "+ " + padding + "}" + new_comma
        else:
            yield from ("- " + line for line in block(old, depth, key, old_comma))
            yield from ("+ " + line for line in block(new, depth, key, new_comma))

    return "\n".join(walk(before, after)) + "\n"


def yaml_diff(before, after):
    lines = []

    for path, old, new in changes(before, after):
        lines.append(" / ".join(map(quote, path)) + ":")

        if old is not MISSING:
            lines.extend("  - " + line for line in json_text(old).splitlines())

        if new is not MISSING:
            lines.extend("  + " + line for line in json_text(new).splitlines())

    return "\n".join(lines) + ("\n" if lines else "")
