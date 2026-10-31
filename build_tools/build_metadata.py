"""Resolve build versions and record ISO assembly identity."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def resolve_version(version=None, project=ROOT / 'pyproject.toml'):
    """Use one filename-safe Debian version for the package and ISO identity."""
    if version is None:
        version = tomllib.loads(Path(project).read_text(encoding='utf-8'))['project']['version']

    # Versions become both Debian control fields and artifact filenames.
    if not isinstance(version, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+~\-]*', version):
        raise ValueError('version must start with a digit and contain only letters, digits, ., +, ~ or -')
    # Debian interprets the final hyphen as a separator requiring a revision.
    if version.endswith('-'):
        raise ValueError('version must not end with an empty Debian revision')
    return version


def source_revision(repository):
    """Record source identity; archives without .git have unknown revision/state."""
    repository = Path(repository).resolve()
    if not (repository / '.git').exists():
        return {'git_commit': None, 'git_dirty': None}

    command = ['git', '-c', f'safe.directory={repository}', '-C', str(repository)]
    revision = subprocess.run(command + ['rev-parse', '--verify', 'HEAD'],
                              check=True, capture_output=True, text=True).stdout.strip()
    changes = subprocess.run(command + ['status', '--porcelain', '--untracked-files=normal'],
                             check=True, capture_output=True, text=True).stdout
    return {'git_commit': revision, 'git_dirty': bool(changes)}


def write_control(path, version):
    """Replace only the version field in a staged Debian control template."""
    path = Path(path)
    text, count = re.subn(r'^Version:.*$', f'Version: {resolve_version(version)}',
                         path.read_text(encoding='utf-8'), flags=re.MULTILINE)
    if count != 1:
        raise ValueError('Debian control template must contain exactly one Version field')
    path.write_text(text, encoding='utf-8')


def write_metadata(output, project=ROOT / 'pyproject.toml', *, built_at=None, built_by=None,
                   version=None):
    version = resolve_version(version, project)

    if built_by is not None and (
            not isinstance(built_by, str) or not built_by.strip() or not built_by.isprintable()):
        raise ValueError('built-by must be a nonempty printable string')

    instant = built_at if built_at is not None else datetime.now(timezone.utc)
    if instant.utcoffset() is None:
        raise ValueError('Build time must have an explicit timezone')

    document = {
        'version': version,
        'build_timestamp': instant.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'built_by': built_by,
        **source_revision(Path(project).parent),
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    output.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path, help='Write ISO build metadata')
    mode.add_argument('--print-version', action='store_true', help='Resolve and print the build version')
    mode.add_argument('--control', type=Path, help='Set the version in a staged Debian control file')
    parser.add_argument('--project', type=Path, default=ROOT / 'pyproject.toml')
    parser.add_argument('--version', help='Override the project version for this build')
    parser.add_argument('--built-by', help='Builder attribution displayed by show version')
    args = parser.parse_args()

    try:
        version = resolve_version(args.version, args.project)
        if args.print_version:
            print(version)
        elif args.control:
            write_control(args.control, version)
        else:
            write_metadata(args.output, args.project, built_by=args.built_by, version=version)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Build metadata generation failed: {error}\n')


if __name__ == '__main__':
    main()
