"""Shared checks for relationships and completeness beyond scalar CLI validation."""

from nvyr.errors import ValidationError


def require_fields(section, keys, path):
    """Require child settings in a configuration section, reporting its CLI path."""
    # Incomplete sections must not reach native configuration generation.
    missing = set(keys) - section.keys()
    if missing:
        raise ValidationError(f'{path}: requires {", ".join(sorted(missing))}')
