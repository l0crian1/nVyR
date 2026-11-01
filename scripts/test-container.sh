#!/bin/sh
# Use Linux filesystem semantics and speed even when the checkout is on Windows.
set -eu

checkout=$(mktemp -d /tmp/nvyr-ci.XXXXXX)
# Keep the copy owned by the container user so Git can inspect it when the
# mounted checkout belongs to a different UID (including GitHub's runner user).
rsync -a --no-owner --no-group \
    --exclude='/dist/' --exclude='/build/' --exclude='/experiments/' \
    --exclude='/acceptance-results/' --exclude='/test-results/' --exclude='/.venv/' \
    --exclude='__pycache__/' --exclude='.pytest_cache/' --exclude='*.egg-info/' \
    /workspace/ "$checkout/"

status=0
sh "$checkout/scripts/test-ci.sh" || status=$?

# Retain test evidence on failures too, without copying generated source changes
# or deleting artifacts from earlier local runs.
for directory in test-results dist; do
    if [ -d "$checkout/$directory" ]; then
        mkdir -p "/workspace/$directory"
        rsync -a "$checkout/$directory/" "/workspace/$directory/"
    fi
done

exit "$status"
