"""Install PATH symlinks for executable operational scripts (Debian or development)."""

import argparse
import os
from pathlib import Path
import re


def install_scripts(source, bin_directory):
    source, bin_directory = Path(source).resolve(), Path(bin_directory).resolve()
    scripts = sorted(p for p in source.glob('*.py') if not p.name.startswith('_'))

    # Validate before installing anything. Helpers belong in the helpers package
    # or private modules; each public script is a directly executable entry point.
    for path in scripts:
        if not re.fullmatch(r'[a-z][a-z0-9_]*', path.stem):
            raise ValueError(f'Invalid operational script name: {path.name}')

        with path.open('rb') as stream:
            first_line = stream.readline()

        if first_line != b'#!/usr/bin/env python3\n':
            raise ValueError(f'{path}: operational scripts require #!/usr/bin/env python3 with an LF line ending')

        link = bin_directory / f'{path.stem}.nvyr.op'
        if link.exists() and not link.is_symlink():
            raise ValueError(f'Refusing to replace existing executable: {link}')

    bin_directory.mkdir(parents=True, exist_ok=True)

    for path in scripts:
        path.chmod(0o755)
        link = bin_directory / f'{path.stem}.nvyr.op'
        target = os.path.relpath(path, bin_directory)

        if link.is_symlink():
            if os.readlink(link) == target:
                continue

            link.unlink()

        link.symlink_to(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--bin', type=Path, required=True)
    args = parser.parse_args()
    install_scripts(args.source, args.bin)


if __name__ == '__main__':
    main()
