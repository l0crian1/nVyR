"""Inject native calls and filesystem roots into the real container script.

This test-only adapter lets existing behavioral cases retain independent fake
hosts while production uses plain lifecycle functions and supporting functions.
"""

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nvyr.config_scripts import container
from nvyr.modules import CommitContext
from nvyr.tree import ReadOnlyTree
from nvyr.op_scripts import containers as operations


def verify_container(configuration, *, vrfs=()):
    container.verify({'container': configuration, 'vrfs': list(vrfs)}, SimpleNamespace())


class ContainerHarness:
    def __init__(self, *, state=container.STATE, quadlets=container.QUADLETS, registries=container.REGISTRIES,
                 execute=container.cmd, status=container.rc_cmd, report=print):
        self.state = Path(state)
        self.quadlets = Path(quadlets)
        self.registries = Path(registries)
        self.pending = self.state.with_suffix('.pending.json')
        self.execute = execute
        self.status = status
        self.report = report
        # Model configd separately from the script's native-object inventory.
        self.configuration = {}
        self.generated_configurations = {}

    def __getattr__(self, name):
        if name in ('pull', 'restart', 'restart_pod'):
            function = getattr(operations, '_' + name)
        else:
            function = getattr(container, 'read_state' if name == 'read' else name)

        def invoke(*args, **kwargs):
            with ExitStack() as patches:
                for key, value in (('STATE', self.state), ('QUADLETS', self.quadlets), ('REGISTRIES', self.registries),
                                   ('cmd', self.execute), ('rc_cmd', self.status)):
                    patches.enter_context(patch.object(container, key, value))
                patches.enter_context(patch.object(operations, 'cmd', self.execute))
                patches.enter_context(patch.object(operations, 'configured_state',
                                                   lambda: {'configuration': self.configuration,
                                                            'images': container.read_state()['images']}))
                for key in ('image_id', 'owned', 'validate_units', 'unmount'):
                    if key in self.__dict__ or key in type(self).__dict__:
                        patches.enter_context(patch.object(container, key, getattr(self, key)))
                if name == 'generate':
                    recovery = kwargs.pop('recovery', False)
                    previous = self.configuration
                    context = CommitContext(ReadOnlyTree({'container': args[0]}), ReadOnlyTree({'container': previous}),
                                            'container', ('container',), recovery,
                                            previous_effective=ReadOnlyTree({'container': previous}), report=self.report)
                    configuration = container.get_config(context)
                    configuration['vrfs'] = kwargs.pop('vrfs', [])
                    container.verify(configuration, SimpleNamespace())
                    generated = function(configuration, context)
                    self.generated_configurations[id(generated)] = deepcopy(args[0])
                    return generated
                if name == 'apply':
                    if args[0] is not None:
                        container.apply(args[0], report=self.report)
                    self.configuration = self.generated_configurations.pop(id(args[0]))
                    return None
                if name == 'read':
                    return {'configuration': self.configuration, 'images': container.read_state()['images']}
                if name in ('pull', 'restart', 'restart_pod'):
                    kwargs['report'] = self.report
                return function(*args, **kwargs)

        return invoke
