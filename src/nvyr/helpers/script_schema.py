"""Dependency-free indexing and validation of YAML script declarations."""


class ScriptIndex:
    """Index explicit declarations and subtree ownership without runtime imports.

    Pattern paths use None for tag values. Owners retain their first declaration
    and shared priority; patterns retain every declaring path. Subtree flags let
    later projections skip branches with no script declarations.
    """
    def __init__(self, root):
        self.root = root
        self.owners = {}
        self.patterns = []
        self.watches = {}
        self.before_watches = {}
        self._contains = {}
        self._exclusive = {}
        self._index(root)

        for paths in (*self.watches.values(), *self.before_watches.values()):
            for path in paths:
                node = root
                for part in path:
                    if node.get('kind') == 'tag_node':
                        if part != '*':
                            raise ValueError('script watch must use * to cross tag instances; or watch the collection instead')
                        node = {'children': node.get('children', {})}
                        continue
                    node = node.get('children', {}).get(part, {})
                if not node:
                    raise ValueError(f"Unknown script watch path: {' '.join(path)}")

    def _index(self, node, path=(), tags=(), owner=None):
        """Validate one declaration and accumulate descendant ownership metadata."""
        script = node.get('script')
        here_tags = (*tags, path[-1]) if node['kind'] == 'tag_node' and path else tags
        if 'script' in node:
            location = ' '.join(part or '<tag>' for part in path) or '<root>'
            if (not isinstance(script, dict) or set(script) - {'name', 'priority', 'register', 'watch', 'watch-before'}
                    or not isinstance(script.get('name'), str) or not script['name']
                    or type(script.get('priority')) is not int):
                raise ValueError(f'{location}: scripts require a name, integer priority and optional register mapping')

            owner = script['name']
            for key, index in (('watch', self.watches), ('watch-before', self.before_watches)):
                watch = script.get(key, [])
                if (not isinstance(watch, list) or not all(isinstance(value, str) and value.split()
                        and value == ' '.join(value.split()) for value in watch)):
                    raise ValueError(f'{location}: script {key} requires a list of absolute configuration paths')
                index.setdefault(owner, set()).update(tuple(value.split()) for value in watch)
            previous = self.owners.get(owner)
            if previous and previous[1] != script['priority']:
                raise ValueError(f'{location}: conflicting priorities for script {owner}')

            self.owners.setdefault(owner, (path, script['priority']))
            self.patterns.append((path, owner))
            register = script.get('register', {})
            if not isinstance(register, dict):
                raise ValueError(f'{location}: script register must be a mapping')

            for key, value in register.items():
                if not isinstance(key, str) or not key:
                    raise ValueError(f'{location}: register keys must be nonempty strings')

                if isinstance(value, dict):
                    if (set(value) != {'tag'} or not isinstance(value['tag'], str)
                            or value['tag'] not in here_tags):
                        raise ValueError(f'{location}: register {key} must reference an enclosing tag node')
                elif not isinstance(value, str) or not value:
                    raise ValueError(f'{location}: register {key} requires a literal string or {{tag: name}}')

        child_path = (*path, None) if node['kind'] == 'tag_node' else path
        children = node.get('children', {})
        contains = bool(script)
        exclusive = node['kind'] in {'leaf_node', 'tag_node'} or not children
        for name, child in children.items():
            self._index(child, (*child_path, name), here_tags, owner)
            contains |= self._contains[id(child)]
            if child.get('script', {}).get('name', owner) == owner:
                exclusive |= self._exclusive[id(child)]

        self._contains[id(node)] = contains
        self._exclusive[id(node)] = exclusive

    def supports(self, path):
        return any(len(pattern) >= len(path) and all(a is None or a == b for a, b in zip(pattern, path))
                   for pattern, _ in self.patterns)

    def touches(self, path, owner):
        return any(name == owner and all(a is None or a == b for a, b in zip(pattern, path))
                   for pattern, name in self.patterns)

    def owners_at(self, path):
        """Nearest inherited owner plus declarations inside the selected subtree."""
        result = set()
        nearest = (-1, None)
        for pattern, name in self.patterns:
            if not all(a is None or a == b for a, b in zip(pattern, path)):
                continue

            if len(pattern) >= len(path):
                result.add(name)

            if nearest[0] < len(pattern) <= len(path):
                nearest = (len(pattern), name)

        if nearest[1] is not None:
            result.add(nearest[1])

        return result

