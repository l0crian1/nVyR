"""Exercise the publication gate without building or pushing a Docker image."""

import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/image-builder.yml'


def run_version_check(tmp_path, previous, current, event='push', new_branch=False):
    """Run the actual workflow step against a small repository and push baseline."""
    def git(*arguments):
        return subprocess.run(
            ['git', *arguments], cwd=tmp_path, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    git('init')
    git('config', 'user.name', 'Workflow test')
    git('config', 'user.email', 'test@example.invalid')

    dockerfile = tmp_path / 'images/Dockerfile'
    dockerfile.parent.mkdir()
    dockerfile.write_text(previous, encoding='utf-8')
    git('add', '.')
    git('commit', '-m', 'Previous builder')
    before = git('rev-parse', 'HEAD')

    # A push can contain unrelated commits after the previous Dockerfile change.
    (tmp_path / 'README.md').write_text('Unrelated change\n', encoding='utf-8')
    git('add', '.')
    git('commit', '-m', 'Unrelated change')
    dockerfile.write_text(current, encoding='utf-8')

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))
    steps = workflow['jobs']['publish']['steps']
    version_step = next(step for step in steps if step.get('id') == 'version')
    output = tmp_path / 'github-output'
    environment = dict(os.environ)
    environment.update(
        EVENT_NAME=event,
        BEFORE_SHA='0' * 40 if new_branch else before,
        GITHUB_OUTPUT=str(output),
    )

    result = subprocess.run(
        [sys.executable, '-c', version_step['run']], cwd=tmp_path,
        env=environment, capture_output=True, text=True,
    )
    outputs = output.read_text() if output.exists() else ''
    return result, outputs


@pytest.mark.parametrize(('previous', 'current', 'publish'), [
    ('FROM debian:trixie\n', '# builder-version: 0.1.0\nFROM debian:trixie\n', True),
    ('# builder-version: 0.1.0\n', '# builder-version: 0.1.1\n', True),
    ('# builder-version: 0.1.9\n', '# builder-version: 0.1.10\n', True),
    ('# builder-version: 0.1.0\nFROM debian:trixie\n',
     '# builder-version: 0.1.0\nFROM debian:trixie\nRUN echo changed\n', False),
])
def test_push_publishes_only_new_versions(tmp_path, previous, current, publish):
    result, outputs = run_version_check(tmp_path, previous, current)

    assert result.returncode == 0, result.stderr
    assert f'publish={str(publish).lower()}\n' in outputs
    assert f'version={current.splitlines()[0].split()[-1]}\n' in outputs


@pytest.mark.parametrize('current', [
    '# builder-version: 0.0.9\n',
    '# builder-version: latest\n',
    '# builder-version: 01.1.0\n',
    '# builder-version: 0.1.1 extra\n',
    'FROM debian:trixie\n',
])
def test_invalid_or_decreasing_version_cannot_publish(tmp_path, current):
    result, outputs = run_version_check(tmp_path, '# builder-version: 0.1.0\n', current)

    assert result.returncode != 0
    assert outputs == ''


def test_manual_retry_republishes_current_version(tmp_path):
    dockerfile = '# builder-version: 0.1.0\nFROM debian:trixie\n'
    result, outputs = run_version_check(tmp_path, dockerfile, dockerfile, 'workflow_dispatch')

    assert result.returncode == 0, result.stderr
    assert outputs == 'version=0.1.0\npublish=true\n'


def test_first_branch_push_has_no_previous_revision(tmp_path):
    dockerfile = '# builder-version: 0.1.0\nFROM debian:trixie\n'
    result, outputs = run_version_check(tmp_path, dockerfile, dockerfile, new_branch=True)

    assert result.returncode == 0, result.stderr
    assert outputs == 'version=0.1.0\npublish=true\n'
