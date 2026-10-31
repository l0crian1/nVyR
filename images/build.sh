#!/bin/sh
# Keep the Docker entrypoint small; Python preserves build status while logging.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
exec python3 -m build_tools.image_build "$@"
