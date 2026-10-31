"""Exercise local generation and host application with configd's sandbox restrictions."""

import json
import os
from pathlib import Path
import tempfile

import pytest

from nvyr.config_scripts import container
from nvyr.helpers import containers as worker
from nvyr.helpers.containers import run_apply
from nvyr.helpers.process import cmd, rc_cmd
from nvyr.modules import CommitContext
from nvyr.render import json_text
from nvyr.tree import ReadOnlyTree


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_PODMAN_TEST') != '1', reason='isolated native Podman test only')


def test_native_generation_inside_configd_restrictions_and_single_host_apply(monkeypatch):
    monkeypatch.setattr(worker, 'run_apply', run_apply)
    messages = []
    desired = {'container': {
        'network': {'STAGENET': {'subnet': {'172.29.239.0/24': {}}}},
        'pod': {'STAGEPOD': {'network': {'STAGENET': {}}}},
        'name': {'STAGES': {'image': 'busybox:1.37', 'pod': 'STAGEPOD',
                            'command': 'sleep', 'argument': 'infinity'}}}}
    context = CommitContext(ReadOnlyTree(desired), ReadOnlyTree({}), 'container', ('container',),
                            previous_effective=ReadOnlyTree({}), report=messages.append)
    gathered = container.get_config(context)
    container.verify(gathered, context)

    try:
        with tempfile.TemporaryDirectory(dir=container.RUNTIME) as folder:
            request = Path(folder) / 'input.json'
            result = Path(folder) / 'result.json'
            request.write_text(json_text(gathered))
            script = ('import json,sys; from pathlib import Path; from types import SimpleNamespace; '
                      'from nvyr.config_scripts import container; from nvyr.render import json_text; '
                      'data=container.generate(json.loads(Path(sys.argv[1]).read_text()), SimpleNamespace(recovery=False)); '
                      'Path(sys.argv[2]).write_text(json_text(data))')
            # Use the actual daemon's restrictions, with writable paths limited to this test.
            service = Path('/workspace/packaging/nvyr-configd.service').read_text().splitlines()
            keys = {'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp', 'ProtectKernelTunables',
                    'ProtectKernelModules', 'ProtectControlGroups', 'RestrictNamespaces',
                    'RestrictAddressFamilies', 'LockPersonality', 'CacheDirectory', 'CacheDirectoryMode'}
            properties = [argument for line in service if line.partition('=')[0] in keys
                          for argument in ('--property', line)]
            cmd(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', *properties,
                 '--property=ReadWritePaths=/config /run/nvyr-containers',
                 '/usr/bin/python3', '-I', '-c', script, str(request), str(result)])
            generated = json.loads(result.read_text())
        assert rc_cmd(['podman', 'container', 'exists', 'STAGES'])[0] == 1
        assert not (container.QUADLETS / 'nvyr-container-535441474553.container').exists()

        container.apply(generated, context)
        installed = json.loads(cmd(['podman', 'container', 'inspect', 'STAGES']))[0]
        assert installed['State']['Running']
        assert installed['Image'] == json.loads(generated['forward']['inventory'])['images']['STAGES']
        assert (container.QUADLETS / 'nvyr-container-535441474553.container').read_text() == generated['forward']['containers']['STAGES']['text']
    finally:
        context = CommitContext(ReadOnlyTree({}), ReadOnlyTree(desired), 'container', ('container',),
                                previous_effective=ReadOnlyTree(desired), report=messages.append)
        gathered = container.get_config(context)
        container.verify(gathered, context)
        container.apply(container.generate(gathered, context), context)

    assert rc_cmd(['podman', 'container', 'exists', 'STAGES'])[0] == 1
