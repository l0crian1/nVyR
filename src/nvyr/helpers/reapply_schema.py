"""Build-time validation for declarative provider-field watches."""


def validate_reapply(root):
    providers = {}
    watches = []

    def walk(node, path, owner=None):
        owner = node.get('script', {}).get('name', owner)
        if 'dependency' in node:
            providers.setdefault(node['dependency'], []).append(node)

        if 'reapply-on-change' in node:
            fields = node['reapply-on-change']
            # Watches belong to valued references and contain relative field paths.
            if (not node.get('depends') or not owner or not isinstance(fields, list) or not fields
                    or not all(isinstance(value, str) and value.split() and value == ' '.join(value.split())
                               for value in fields) or len(fields) != len(set(fields))):
                raise ValueError(f"{' '.join(path)}: reapply-on-change requires a nonempty list of relative paths on an owned depends node")
            watches.append((node, path))

        for name, child in node.get('children', {}).items():
            walk(child, (*path, name), owner)

    walk(root, ())
    for node, path in watches:
        definitions = providers.get(node['depends'], [])
        # A misspelled dependency type cannot provide a watched field.
        if not definitions:
            raise ValueError(f"{' '.join(path)}: reapply-on-change has no provider for {node['depends']}")

        for field in node['reapply-on-change']:
            found = False
            for provider in definitions:
                current = provider
                for index, name in enumerate(field.split()):
                    # A watch can cover a tag collection, but cannot guess its instance keys.
                    if index and current.get('kind') == 'tag_node':
                        raise ValueError(f"{' '.join(path)}: reapply-on-change cannot cross tag instances in {field!r}; watch the collection instead")
                    current = current.get('children', {}).get(name, {})
                found |= bool(current)

            # Interface types have different capabilities (for example, lo has no VRF).
            # A field must exist on at least one provider; absent fields cannot change.
            if not found:
                raise ValueError(f"{' '.join(path)}: unknown reapply-on-change path {field!r} on {node['depends']} provider")
