"""Privileged, argument-free session launcher and isolated Podman image lifecycle."""

import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import subprocess
import sys
import uuid

from nvyr.helpers.access import ROLE_GROUPS
from nvyr.storage import atomic_json

RUNTIME = Path('/run/nvyr-sessions')
STORAGE = Path('/var/lib/nvyr-sessions')
BUNDLE = Path('/usr/share/nvyr/session-images')
SOCKET = '/run/nvyr/configd.sock'


def podman(*arguments):
    """Never use workload storage, user container settings, or a remote Podman socket."""
    return ['/usr/bin/podman', '--root', str(STORAGE / 'storage'),
            '--runroot', str(RUNTIME / 'storage'), '--storage-driver=overlay',
            '--storage-opt=overlay.mount_program=/usr/bin/fuse-overlayfs', *arguments]


def environment():
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
            'TERM': 'xterm', 'CONTAINERS_CONF': '/usr/share/nvyr/session-containers.conf'}


def execute(*arguments, **options):
    return subprocess.run(podman(*arguments), env=environment(), check=True, **options)


def start_time(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except FileNotFoundError:
        return None


def metadata(pid, uid):
    """Resolve trusted host terminal metadata from the peer's actual cgroup."""
    try:
        groups = Path(f'/proc/{pid}/cgroup').read_text()
        match = re.search(r'/nvyrsession([0-9a-f]{32})\.slice/', groups)
        if match:
            record = json.loads((RUNTIME / 'sessions' / (match[1] + '.json')).read_text())
            if record['uid'] == uid and start_time(record['launcher']) == record['start']:
                return record['tty'], record['source']
    except (OSError, ValueError, KeyError):
        pass
    return None


def remove(identifier):
    execute('rm', '--force', '--time=0', '--ignore', 'nvyr-session-' + identifier,
            stdout=subprocess.DEVNULL, timeout=20)
    (RUNTIME / 'sessions' / (identifier + '.json')).unlink(missing_ok=True)


def reap():
    """Bound orphan lifetime if a launcher is killed before its finally block runs."""
    for path in (RUNTIME / 'sessions').glob('*.json'):
        record = json.loads(path.read_text())
        if start_time(record['launcher']) != record['start']:
            remove(path.stem)

    # /run is empty after reboot, but Podman's persistent container records survive.
    result = execute('ps', '--all', '--format=json', stdout=subprocess.PIPE, text=True, timeout=20)
    for container in json.loads(result.stdout):
        for name in container.get('Names', ()):
            match = re.fullmatch(r'nvyr-session-([0-9a-f]{32})', name)
            if match and not (RUNTIME / 'sessions' / (match[1] + '.json')).exists():
                remove(match[1])


def prepare():
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    (RUNTIME / 'sessions').mkdir(mode=0o700, exist_ok=True)
    STORAGE.mkdir(mode=0o700, exist_ok=True)
    with (RUNTIME / 'prepare.lock').open('w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        manifest = json.loads((BUNDLE / 'manifest.json').read_text())
        marker = STORAGE / 'loaded.json'
        installed = execute('images', '--format=json', stdout=subprocess.PIPE, text=True, timeout=20)
        image_ids = {image['Id'].removeprefix('sha256:') for image in json.loads(installed.stdout)}
        expected_ids = {image.removeprefix('sha256:') for image in manifest['images'].values()}
        if not marker.exists() or json.loads(marker.read_text()) != manifest or not expected_ids <= image_ids:
            execute('load', '--input', str(BUNDLE / 'images.tar'), timeout=120)
            atomic_json(marker, manifest)
        reap()
        # Retagging a new bundle leaves older images dangling. Podman preserves
        # images used by active sessions, so upgrades need not interrupt logins.
        execute('image', 'prune', '--force', stdout=subprocess.DEVNULL, timeout=60)


def account_role(uid):
    account = pwd.getpwuid(uid)
    groups = os.getgrouplist(account.pw_name, account.pw_gid)
    for role, name in ROLE_GROUPS.items():
        if grp.getgrnam(name).gr_gid in groups:
            return account, role
    raise RuntimeError('Account no longer has nVyR login access')


def launch():
    if not os.environ.get('SUDO_UID', '').isdigit():
        raise RuntimeError('Session launcher requires an authenticated sudo caller')
    account, role = account_role(int(os.environ['SUDO_UID']))
    if role == 'dev-admin' or account.pw_uid == 0:
        raise RuntimeError('Developer accounts use direct host login')

    manifest = json.loads((BUNDLE / 'manifest.json').read_text())
    workspace = Path('/config/users') / account.pw_name
    info = workspace.lstat()
    if workspace.is_symlink() or not workspace.is_dir() or info.st_uid != account.pw_uid:
        raise RuntimeError('User workspace is unavailable or has invalid ownership')
    terminal = os.environ.get('TERM', 'xterm')
    if not re.fullmatch(r'[a-zA-Z0-9+_.-]{1,64}', terminal):
        terminal = 'xterm'

    identifier = uuid.uuid4().hex
    name = 'nvyr-session-' + identifier
    # sudo may allocate a second PTY. Its parent-side stdin still identifies the
    # original SSH/console terminal recorded in utmp; SUDO_TTY is not portable.
    try:
        tty = os.readlink(f'/proc/{os.getppid()}/fd/0')
    except OSError:
        tty = 'unknown'
    tty = tty if tty.startswith('/dev/') else 'unknown'
    source = os.environ.get('SSH_CONNECTION', '').split()
    source = source[0] if source else None
    record = {'uid': account.pw_uid, 'launcher': os.getpid(), 'start': start_time(os.getpid()),
              'tty': tty, 'source': source}
    atomic_json(RUNTIME / 'sessions' / (identifier + '.json'), record)

    arguments = ['run', '--rm', '--init', '--interactive', '--tty', '--pull=never',
                 '--name', name, '--label=nvyr.internal=cli-session', '--stop-timeout=1',
                 '--network=none', '--pid=private', '--ipc=private', '--uts=private',
                 '--cgroup-parent=nvyrsession' + identifier + '.slice', '--userns=host',
                 '--hostname', socket.gethostname(), '--user', f'{account.pw_uid}:{account.pw_gid}',
                 '--group-add', str(grp.getgrnam('nvyr-access').gr_gid), '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--read-only', '--pids-limit=64',
                 '--memory=256m', '--memory-swap=256m', '--cpus=1', '--log-driver=none',
                 '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777',
                 '--volume', f'{SOCKET}:{SOCKET}:ro', '--volume', f'{workspace}:/home/user:rw',
                 '--workdir=/home/user', '--env=HOME=/home/user',
                 '--env=USER=' + account.pw_name, '--env=LOGNAME=' + account.pw_name,
                 '--env=TERM=' + terminal, manifest['images'][role]]

    def disconnected(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGHUP, disconnected)
    signal.signal(signal.SIGTERM, disconnected)
    signal.signal(signal.SIGINT, lambda signum, frame: None)
    process = None
    try:
        process = subprocess.Popen(podman(*arguments), env=environment())
        return process.wait()
    finally:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        remove(identifier)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('launch', 'prepare', 'reap'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Session supervision requires root')
    try:
        if args.operation == 'launch':
            sys.exit(launch())
        elif args.operation == 'prepare':
            prepare()
        else:
            reap()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f'nVyR session unavailable: {error}\n')
