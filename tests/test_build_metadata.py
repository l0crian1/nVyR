from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import pytest

from build_tools.build_metadata import ROOT, resolve_version, source_revision, write_control, write_metadata
from nvyr.errors import RouterError
from nvyr.helpers import build_metadata
from nvyr.helpers import access


def test_metadata_uses_project_version_and_normalizes_time_to_utc(tmp_path):
    project = tmp_path / 'pyproject.toml'
    project.write_text('[project]\nversion = "0.2.3"\n')
    output = tmp_path / 'image/usr/share/nvyr/build.json'
    write_metadata(output, project, built_at=datetime(2026, 10, 11, 19, 42, 18,
                                                     tzinfo=timezone(timedelta(hours=-4))))

    assert json.loads(output.read_text()) == {
        'version': '0.2.3', 'build_timestamp': '2026-10-11T23:42:18Z', 'built_by': None,
        'git_commit': None, 'git_dirty': None}
    assert build_metadata.format_version(build_metadata.read(output)) == (
        ' Version    | 0.2.3\n'
        ' Build date | 2026-10-11 23:42:18 UTC\n'
        ' Built by   | Not specified\n'
        ' Copyright  | Copyright (c) 2026 L0crian and nVyR contributors\n'
        ' Project    | https://github.com/l0crian1/nVyR\n')

    with pytest.raises(ValueError, match='explicit timezone'):
        write_metadata(output, project, built_at=datetime(2026, 10, 11))


def test_cli_captures_actual_generation_time_and_reading_never_restamps(tmp_path):
    output = tmp_path / 'build.json'
    start = datetime.now(timezone.utc).replace(microsecond=0)
    subprocess.run([sys.executable, str(ROOT / 'build_tools/build_metadata.py'),
                    '--output', str(output), '--built-by', 'L0crian and contributors'], cwd=tmp_path, check=True)
    end = datetime.now(timezone.utc)
    original = output.read_bytes()
    metadata = build_metadata.read(output)
    instant = datetime.fromisoformat(metadata['build_timestamp'])

    assert start <= instant <= end
    assert metadata['built_by'] == 'L0crian and contributors'

    # File timestamps (including a later boot/install) cannot change image identity.
    os.utime(output, (0, 0))

    assert build_metadata.read(output) == metadata
    assert output.read_bytes() == original


def test_show_version_uses_stored_metadata_in_both_modes(controller, session, tmp_path, monkeypatch):
    path = tmp_path / 'build.json'
    document = {'version': '0.1.0', 'build_timestamp': '2026-10-11T23:42:18Z',
                'built_by': 'Example Builder',
                'extension': {'reserved-for-future': True}}
    path.write_text(json.dumps(document))
    monkeypatch.setattr(build_metadata, 'METADATA_PATH', path)

    assert build_metadata.read() == document

    expected = build_metadata.format_version(document)

    assert controller.execute('show version')['text'] == expected
    assert controller.execute('run show version', session)['text'] == expected
    assert controller.execute('show version | match "Build date"')['text'] == expected.splitlines(True)[1]
    assert ' Built by   | Example Builder\n' in expected


def test_non_image_installation_does_not_invent_a_build_date(tmp_path, monkeypatch):
    monkeypatch.setattr(build_metadata, 'package_version', lambda name: '0.2.0')

    output = build_metadata.format_version(build_metadata.read(tmp_path / 'missing'))
    assert output.startswith(' Version    | 0.2.0\n Build date | unavailable\n')
    assert ' Built by   | Not specified\n' in output

    def missing(name):
        raise build_metadata.PackageNotFoundError(name)

    monkeypatch.setattr(build_metadata, 'package_version', missing)

    assert build_metadata.read(tmp_path / 'missing') == {
        'version': 'unknown', 'build_timestamp': None, 'built_by': None}


@pytest.mark.parametrize('document', [
    [], {}, {'version': '0.1.0'},
    {'version': False, 'build_timestamp': '2026-10-11T23:42:18Z'},
    {'version': 'bad\nversion', 'build_timestamp': '2026-10-11T23:42:18Z'},
    {'version': '0.1.0', 'build_timestamp': None},
    {'version': '0.1.0', 'build_timestamp': '2026-10-11T23:42:18'},
    {'version': '0.1.0', 'build_timestamp': '2026-10-11T23:42:18+03:00'},
    {'version': '0.1.0', 'build_timestamp': '2026-02-30T23:42:18Z'},
])
def test_invalid_stored_metadata_is_reported_instead_of_hidden(tmp_path, document):
    path = tmp_path / 'build.json'
    path.write_text(json.dumps(document))

    with pytest.raises(RouterError, match='Invalid build metadata'):
        build_metadata.read(path)


def test_unreadable_json_is_actionable(tmp_path):
    path = tmp_path / 'build.json'
    path.write_text('{broken')

    with pytest.raises(RouterError, match='Cannot read build metadata'):
        build_metadata.read(path)


@pytest.mark.parametrize('builder', ['', '   ', 'builder\nextra', 'builder\x1b[31m', 123, False])
def test_invalid_builder_attribution_is_rejected(tmp_path, builder):
    """Attribution is display text, never terminal controls or a different JSON type."""
    path = tmp_path / 'build.json'
    with pytest.raises(ValueError, match='built-by'):
        write_metadata(path, built_by=builder)
    assert not path.exists()

    path.write_text(json.dumps({'version': '0.1.0', 'build_timestamp': '2026-10-25T12:00:00Z',
                               'built_by': builder}))
    with pytest.raises(RouterError, match='built_by'):
        build_metadata.read(path)


def test_show_license_verbatim_in_both_modes_and_pipelines(controller, session, monkeypatch):
    """The installed license is ordinary paged output, available to every login role."""
    license_path = ROOT / 'LICENSE'
    monkeypatch.setattr(build_metadata, 'LICENSE_PATH', license_path)
    expected = license_path.read_text(encoding='utf-8')
    assert build_metadata.COPYRIGHT in expected.splitlines()

    for role in ('read-only', 'net-admin', 'sys-admin'):
        token = access.role.set(role)
        try:
            assert controller.execute('show license')['text'] == expected
            if role != 'read-only':
                assert controller.execute('run show license', session)['text'] == expected
            assert controller.execute('show license | match "Copyright"')['text'] == build_metadata.COPYRIGHT + '\n'
            result = controller.execute('show license | no-more')
            assert result['text'] == expected and result['paging'] is False
        finally:
            access.role.reset(token)

    assert 'license' in dict(controller.completion('show ', explicit=True)['candidates'])
    with pytest.raises(RouterError):
        controller.execute('show license extra')


def test_missing_license_reports_the_installed_path(controller, tmp_path, monkeypatch):
    """A packaging failure is actionable rather than silently displaying a substitute."""
    path = tmp_path / 'missing-license'
    monkeypatch.setattr(build_metadata, 'LICENSE_PATH', path)
    with pytest.raises(RouterError, match='Cannot read the nVyR license') as caught:
        controller.execute('show license')
    assert str(path) in str(caught.value)


@pytest.mark.skipif(sys.platform == 'win32', reason='ISO orchestration requires a POSIX shell')
@pytest.mark.parametrize('arguments', [
    ['--built-by'], ['--built-by', ''], ['--built-by='], ['--unknown'],
    ['--version'], ['--version='], ['--version', '../escape'], ['--version', '0.1\nBad: value'],
    ['--output-dir'], ['--output-dir='],
])
def test_iso_builder_rejects_invalid_arguments_before_starting_build(arguments):
    """Argument errors return before root checks, package builds or filesystem staging."""
    environment = os.environ | {'PATH': os.pathsep.join((os.path.dirname(sys.executable), os.environ['PATH']))}
    result = subprocess.run(['sh', str(ROOT / 'images/build.sh'), *arguments],
                            capture_output=True, text=True, env=environment)
    assert result.returncode != 0
    assert 'error:' in result.stderr or 'Cannot prepare ISO build' in result.stderr


@pytest.fixture
def iso_build(tmp_path):
    # Exercise the actual orchestration; replace only expensive external build steps.
    repository = tmp_path / 'repository'

    for directory in ['images', 'scripts', 'build_tools', 'dist']:
        (repository / directory).mkdir(parents=True)

    for relative in ['images/build.sh', 'images/assemble.sh', 'images/packages.lock', 'images/container-sources.lock',
                     'images/frr-sources.lock', 'images/kernel-sources.lock', 'images/router.list.chroot',
                     'images/0100-router.hook.chroot',
                     'build_tools/build_metadata.py', 'build_tools/image_build.py', 'pyproject.toml']:
        shutil.copyfile(ROOT / relative, repository / relative)

    shutil.copytree(ROOT / 'images/bootloaders', repository / 'images/bootloaders')
    (repository / 'scripts/build-deb.sh').write_text(
        '#!/bin/sh\nset -eu\nprintf "%s\\n" "$@" > "$TEST_PACKAGE_ARGS"\n'
        'test "$1" = --version\ntest "$3" = --output-dir\n'
        'mkdir -p "$4"\ntouch "$4/nvyr-router_${2}_all.deb"\n')
    (repository / 'images/fetch-packages.sh').write_text('#!/bin/sh\nexit 0\n')
    (repository / 'build_tools/container_packages.py').write_text(
        'import pathlib, sys\n'
        'destination = pathlib.Path(sys.argv[-1])\n'
        '(destination / "container-packages.json").write_text("{}")\n')
    (repository / 'build_tools/frr_packages.py').write_text(
        'import pathlib, sys\n'
        'assert sys.argv[1:3] == ["--cache", "/opt/nvyr-frr-packages"]\n'
        'destination = pathlib.Path(sys.argv[-1])\n'
        '(destination / "frr-packages.json").write_text("{}")\n')
    (repository / 'build_tools/kernel_packages.py').write_text(
        'import pathlib, sys\n'
        'assert sys.argv[1:3] == ["--cache", "/opt/nvyr-kernel-packages"]\n'
        'destination = pathlib.Path(sys.argv[-1])\n'
        '(destination / "kernel-packages.json").write_text("{}")\n'
        '(destination / "kernel-source.tar").write_bytes(b"kernel source bundle")\n')
    tools = tmp_path / 'bin'
    tools.mkdir()

    for name, script in {
        'id': 'echo 0',
        'mktemp': 'mkdir -p "$TEST_IMAGE_STAGE"\nprintf "%s\\n" "$TEST_IMAGE_STAGE"',
        'cp': '''if [ "$1" = /usr/share/live/build/bootloaders/grub-pc/config.cfg ]; then
    printf 'terminal_output gfxterm\\n' > "$2"
else
    exec /bin/cp "$@"
fi''',
        'lb': '''if [ "$1" = config ]; then
    printf '%s\\n' "$@" > lb-arguments
elif [ "$1" = build ]; then
    test -s config/includes.chroot/usr/share/nvyr/build.json || exit 1
    echo 'live-build stdout'
    echo 'live-build stderr' >&2
    if [ "${TEST_LB_STATUS:-0}" != 0 ]; then exit "$TEST_LB_STATUS"; fi
    if [ -n "${TEST_LB_PID:-}" ]; then
        echo $$ > "$TEST_LB_PID"
        exec sleep 60
    fi
    cp config/includes.chroot/usr/share/nvyr/build.json live-image-amd64.hybrid.iso
fi''',
    }.items():
        path = tools / name
        path.write_text('#!/bin/sh\nset -eu\n' + script + '\n')
        path.chmod(0o755)

    # The shell's Python must satisfy the same version requirement as this test run.
    env = os.environ | {'PATH': os.pathsep.join((str(tools), os.path.dirname(sys.executable), os.environ['PATH'])),
                        'TEST_IMAGE_STAGE': str(tmp_path / 'stage'),
                        'TEST_PACKAGE_ARGS': str(tmp_path / 'package-arguments')}
    return repository, env


@pytest.mark.skipif(sys.platform == 'win32', reason='ISO orchestration requires a POSIX shell')
@pytest.mark.parametrize('builder,version,custom_output,debug', [
    (None, None, False, False),
    ('L0crian and nVyR contributors; $(not-a-command)', '0.2.0-rc1', True, True),
])
def test_iso_orchestration_stages_metadata_before_live_build(tmp_path, iso_build, builder, version,
                                                           custom_output, debug):
    repository, env = iso_build
    project_before = (repository / 'pyproject.toml').read_bytes()
    command = ['sh', str(repository / 'images/build.sh')]
    if builder is not None:
        command.extend(['--built-by', builder])
    if version is not None:
        command.extend(['--version', version])
    output = repository / 'dist'
    if custom_output:
        output = tmp_path / 'custom output'
        command.extend(['--output-dir', str(output)])
    if debug:
        command.append('--debug')

    result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    expected_version = version or resolve_version(project=repository / 'pyproject.toml')
    stem = f'nvyr-{expected_version}-amd64'
    image = output / f'{stem}.iso'
    metadata = build_metadata.read(image)

    assert metadata['version'] == expected_version
    assert metadata['build_timestamp'] is not None
    assert metadata['built_by'] == builder
    assert metadata == build_metadata.read(tmp_path / 'stage/config/includes.chroot/usr/share/nvyr/build.json')

    stage = tmp_path / 'stage'
    installed_metadata = stage / 'config/includes.chroot/usr/share/nvyr'

    assert (installed_metadata / 'frr-sources.lock').read_bytes() == (ROOT / 'images/frr-sources.lock').read_bytes()
    assert (installed_metadata / 'frr-packages.json').read_text() == '{}'
    assert (output / f'{stem}.frr-packages.json').read_text() == '{}'
    assert (installed_metadata / 'kernel-sources.lock').read_bytes() == (ROOT / 'images/kernel-sources.lock').read_bytes()
    assert (installed_metadata / 'kernel-packages.json').read_text() == '{}'
    assert (output / f'{stem}.kernel-packages.json').read_text() == '{}'
    assert (output / f'{stem}.kernel-source.tar').read_bytes() == b'kernel source bundle'
    assert build_metadata.read(output / f'{stem}.build.json') == metadata
    assert (stage / f'config/packages.chroot/nvyr-router_{expected_version}_all.deb').exists()
    assert (repository / 'pyproject.toml').read_bytes() == project_before

    expected_digest = hashlib.sha256(image.read_bytes()).hexdigest()
    assert (output / f'{stem}.iso.sha256').read_text() == f'{expected_digest}  {image.name}\n'
    log, = output.glob('*.build.log')
    assert 'live-build stdout\nlive-build stderr\n' in log.read_text()
    assert 'Build exit status: 0' in log.read_text()
    assert ('+ lb build' in log.read_text()) is debug
    package_args = (tmp_path / 'package-arguments').read_text().splitlines()
    assert package_args == ['--version', expected_version, '--output-dir', str(output)] + (['--debug'] if debug else [])

    args = (stage / 'lb-arguments').read_text().splitlines()
    kernel = json.loads((ROOT / 'images/kernel-sources.lock').read_text())
    assert args[args.index('--linux-packages') + 1] == 'linux-image'
    assert args[args.index('--linux-flavours') + 1] == kernel['version'] + kernel['local_version']
    assert args[args.index('--archive-areas') + 1] == 'main non-free-firmware'
    assert args[args.index('--firmware-chroot') + 1] == 'false'

    for option in ('--bootappend-live', '--bootappend-live-failsafe', '--bootappend-install'):
        assert 'console=tty0 console=ttyS0,115200n8' in args[args.index(option) + 1]

    grub = (stage / 'config/bootloaders/grub-pc/config.cfg').read_text()

    assert 'terminal_output console' in grub
    assert 'terminal_output --append serial' in grub
    assert args[args.index('--bootloaders')+1] == 'grub-pc grub-efi'
    assert args[args.index('--debian-installer')+1] == 'false'
    assert not list((stage/'config/bootloaders/isolinux').glob('*'))
    assert 'image_manifest.py' in (stage/'config/hooks/live/0990-manifest.hook.binary').read_text()

    packages = (stage/'config/package-lists/router.list.chroot').read_text().splitlines()

    assert {'wget', 'ethtool', 'iperf3', 'tcpdump', 'nmap', 'usbutils', 'dmidecode',
            'dnsutils', 'mtr-tiny', 'curl', 'python3-pytest', 'firmware-realtek'} <= set(packages)


@pytest.mark.skipif(sys.platform == 'win32', reason='ISO orchestration requires a POSIX shell')
@pytest.mark.parametrize('failed_stage,status', [('package', 31), ('image', 23)])
def test_failed_build_retains_unique_logs_and_the_original_status(tmp_path, iso_build, failed_stage, status):
    """Logging must not mask package/live-build failures or publish a success checksum."""
    repository, environment = iso_build
    if failed_stage == 'package':
        (repository / 'scripts/build-deb.sh').write_text(
            '#!/bin/sh\necho "package failed" >&2\nexit 31\n')
        expected = 'package failed'
    else:
        environment['TEST_LB_STATUS'] = str(status)
        expected = 'live-build stderr'

    output = tmp_path / 'failed output'
    command = ['sh', str(repository / 'images/build.sh'), '--output-dir', str(output)]
    for attempt in range(2):
        result = subprocess.run(command, env=environment, capture_output=True, text=True)
        assert result.returncode == status
        assert expected in result.stdout
        assert f'Build exit status: {status}' in result.stdout

    logs = list(output.glob('*.build.log'))
    assert len(logs) == 2
    for log in logs:
        assert expected in log.read_text()
        assert f'Build exit status: {status}' in log.read_text()
    assert not list(output.glob('*.iso'))
    assert not list(output.glob('*.sha256'))
    assert not list(output.glob('*.build.json'))


@pytest.mark.parametrize('version', ['0.1.0', '0.2.0-rc1', '1.0~rc2+test.3', '2.0.0-1'])
def test_version_override_sets_metadata_and_staged_package_control(tmp_path, version):
    """Overrides share one version without rewriting the project's release version."""
    project = tmp_path / 'pyproject.toml'
    project.write_text('[project]\nversion = "0.1.0"\n')
    control = tmp_path / 'control'
    control.write_text('Package: nvyr-router\nVersion: @VERSION@\nArchitecture: all\n')
    write_control(control, version)
    output = tmp_path / 'build.json'
    write_metadata(output, project, version=version)

    assert control.read_text() == f'Package: nvyr-router\nVersion: {version}\nArchitecture: all\n'
    assert build_metadata.read(output)['version'] == version
    assert resolve_version(project=project) == '0.1.0'


@pytest.mark.parametrize('version', ['', '../escape', '1/2', '-1', 'a1', '1.0-', '1 2', '1\nVersion: 2', '1:2'])
def test_unsafe_or_unsupported_version_is_rejected(version):
    with pytest.raises(ValueError, match='version'):
        resolve_version(version)


@pytest.mark.skipif(sys.platform == 'win32', reason='Package orchestration requires a POSIX shell')
@pytest.mark.parametrize('arguments', [
    ['--version'], ['--version='], ['--version', '../escape'], ['--output-dir='], ['--unknown'],
])
def test_package_builder_rejects_invalid_options_without_staging(tmp_path, arguments):
    environment = os.environ | {'PATH': os.pathsep.join((os.path.dirname(sys.executable), os.environ['PATH']))}
    output = tmp_path / 'artifacts'
    result = subprocess.run(['sh', str(ROOT / 'scripts/build-deb.sh'), '--output-dir', str(output), *arguments],
                            env=environment, text=True, capture_output=True)

    assert result.returncode != 0
    assert not output.exists()


@pytest.mark.skipif(sys.platform == 'win32', reason='ISO interruption uses POSIX process groups')
def test_interrupted_iso_build_stops_assembly_and_keeps_log(tmp_path, iso_build):
    """Ctrl-C remains a failed build and stops the separate live-build process group."""
    repository, environment = iso_build
    marker = tmp_path / 'live-build.pid'
    environment['TEST_LB_PID'] = str(marker)
    process = subprocess.Popen(['sh', str(repository / 'images/build.sh')], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    group = None
    try:
        deadline = time.monotonic() + 10
        while not marker.exists():
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.02)
        child = int(marker.read_text())
        group = os.getpgid(child)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=15)

        assert process.returncode == 130, stdout + stderr
        log, = (repository / 'dist').glob('*.build.log')
        assert 'Build interrupted.' in log.read_text()
        assert 'Build exit status: 130' in log.read_text()
        assert not list((repository / 'dist').glob('*.sha256'))

        # An orphan may await reaping, but no live assembly process may remain.
        deadline = time.monotonic() + 5
        while True:
            try:
                state = (Path('/proc') / str(child) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == 'Z':
                break
            assert time.monotonic() < deadline, 'live-build continued after Ctrl-C'
            time.sleep(0.02)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        if group is not None:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.skipif(shutil.which('git') is None, reason='source identity tests require Git')
def test_git_metadata_distinguishes_clean_staged_unstaged_and_untracked_sources(tmp_path):
    """Build identity includes the exact commit and every form of local source change."""
    def git(*arguments):
        command = ['git', '-C', str(tmp_path), '-c', 'user.name=Build test',
                   '-c', 'user.email=build@example.invalid', '-c', 'commit.gpgsign=false']
        return subprocess.run([*command, *arguments], check=True, capture_output=True, text=True).stdout.strip()

    git('init')
    project = tmp_path / 'pyproject.toml'
    original = '[project]\nversion = "0.1.0"\n'
    project.write_text(original)
    git('add', 'pyproject.toml')
    git('commit', '-m', 'Initial build source')
    revision = git('rev-parse', 'HEAD')
    assert source_revision(tmp_path) == {'git_commit': revision, 'git_dirty': False}

    project.write_text(original + '# Local change\n')
    assert source_revision(tmp_path)['git_dirty'] is True
    git('add', 'pyproject.toml')
    assert source_revision(tmp_path)['git_dirty'] is True
    git('commit', '-m', 'Changed build source')
    (tmp_path / 'untracked').touch()
    assert source_revision(tmp_path)['git_dirty'] is True

    output = tmp_path / 'build.json'
    write_metadata(output, project)
    document = json.loads(output.read_text())
    assert document['git_commit'] == git('rev-parse', 'HEAD')
    assert document['git_dirty'] is True
