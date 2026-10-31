"""Build versioned ISO artifacts with streamed logs and source provenance."""

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

from build_tools.build_metadata import ROOT, resolve_version, write_metadata


def run_logged(command, log):
    """Mirror both output streams without losing the child's exit status."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        with process.stdout:
            while chunk := process.stdout.read1(65536):
                log.write(chunk)
                log.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        status = process.wait()
        return status if status >= 0 else 128 - status
    finally:
        # Interruptions and logging failures must not leave a live-build child running.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def checksum(image):
    """Write a sha256sum-compatible file using the ISO's basename."""
    digest = hashlib.sha256()
    with image.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    image.with_suffix('.iso.sha256').write_text(f'{digest.hexdigest()}  {image.name}\n', encoding='utf-8')


def build(args):
    version = resolve_version(args.version)
    output = args.output_dir.resolve()
    stem = f'nvyr-{version}-amd64'

    # Capture Git state before creating logs or other artifacts in the checkout.
    with tempfile.TemporaryDirectory(prefix='nvyr-build-') as temporary:
        metadata = Path(temporary) / 'build.json'
        write_metadata(metadata, version=version, built_by=args.built_by)
        output.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        log_path = output / f'{stem}-{timestamp}.build.log'
        print(f'Build log: {log_path}', flush=True)

        with log_path.open('xb') as log:
            def report(message):
                print(message, flush=True)
                log.write((message + '\n').encode('utf-8'))
                log.flush()

            report(f'Building nVyR {version}; output directory: {output}')
            command = ['sh', str(ROOT / 'images/assemble.sh'), version, str(output),
                       str(metadata), 'yes' if args.debug else 'no']
            try:
                status = run_logged(command, log)
                if status == 0:
                    checksum(output / f'{stem}.iso')
                    shutil.copyfile(metadata, output / f'{stem}.build.json')
            except KeyboardInterrupt:
                report('Build interrupted.')
                status = 130
            except OSError as error:
                report(f'Build failed: {error}')
                status = 1

            report(f'Build exit status: {status}; log: {log_path}')
            return status


def main():
    def output_directory(value):
        if not value:
            raise argparse.ArgumentTypeError('output directory must not be empty')
        return Path(value)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', help='Version for this ISO and Debian package (default: project version)')
    parser.add_argument('--built-by', help='Builder attribution displayed by show version')
    parser.add_argument('--output-dir', type=output_directory, default=ROOT / 'dist',
                        help='Artifact directory (default: dist; relative paths use the checkout root)')
    parser.add_argument('--debug', action='store_true', help='Trace shell build commands in the output and log')
    args = parser.parse_args()

    try:
        status = build(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Cannot prepare ISO build: {error}\n')
    raise SystemExit(status)


if __name__ == '__main__':
    main()
