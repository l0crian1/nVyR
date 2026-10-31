#!/usr/bin/env python3
"""Record the final boot payload after live-build creates its SquashFS/initrd."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))

from nvyr.helpers.build_metadata import read
from nvyr.helpers.images import manifest
from nvyr.storage import atomic_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    args = parser.parse_args()
    atomic_json(args.media/'nvyr/image.json', manifest(args.media, read(args.metadata)), mode=0o644)


if __name__ == '__main__':
    main()
