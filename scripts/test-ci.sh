#!/bin/sh
# The same checks run locally and in GitHub Actions; stop at the first failure.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"

printf '\nChecking generated schemas...\n'
python -m build_tools.schema_builder --check

# Dependencies are installed when the test image is built. Register this checkout
# without downloading a second build environment on every test run.
python -m pip install --no-deps --no-build-isolation -e .

printf '\nRunning regression tests...\n'
python -m pytest -q -n 2 --dist loadfile --durations=30 --junitxml=test-results/framework.xml

printf '\nBuilding Python distributions...\n'
python -m build --no-isolation

printf '\nBuilding Debian package...\n'
sh scripts/build-deb.sh

printf '\nAll CI checks passed. Reports: test-results/; packages: dist/\n'
