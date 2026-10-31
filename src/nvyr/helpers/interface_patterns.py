"""Native nftables interface selectors: exact names or a trailing prefix wildcard."""


def matches(selector, name):
    """Match a concrete name without expanding selectors against host inventory."""
    if selector.endswith('*'):
        return name.startswith(selector[:-1])
    return selector == name


def overlaps(first, second):
    """Detect ambiguous ownership, including interfaces that do not exist yet."""
    return matches(first, second.rstrip('*')) or matches(second, first.rstrip('*'))


def normalize(selectors):
    """Remove redundant members covered by a broader prefix in the same object."""
    selectors = set(selectors)
    prefixes = [selector for selector in selectors if selector.endswith('*')]
    return sorted(selector for selector in selectors
                  if not any(prefix != selector and matches(prefix, selector.rstrip('*'))
                             for prefix in prefixes))
