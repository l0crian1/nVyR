"""Lifecycle doubles for isolated engine tests; never installed with nVyR."""

from nvyr.modules import registry
from nvyr.tree import lookup


class LifecycleStub:
    def __init__(self):
        self.calls = []

    def _stage(self, stage, context):
        self.calls.append((context.owner, stage, context.recovery))

    def get_config(self, context):
        self._stage("get_config", context)
        return lookup(context.effective, context.root, {})

    def verify(self, configuration, context):
        self._stage("verify", context)

    def generate(self, configuration, context):
        self._stage("generate", context)
        return configuration

    def apply(self, generated, context):
        self._stage("apply", context)


class RecordingModule(LifecycleStub):
    """Record lifecycle calls around a real feature implementation."""

    def __init__(self, implementation):
        super().__init__()
        self.implementation = implementation

    def get_config(self, context):
        self._stage("get_config", context)
        return self.implementation.get_config(context)

    def verify(self, configuration, context):
        self._stage("verify", context)
        return self.implementation.verify(configuration, context)

    def generate(self, configuration, context):
        self._stage("generate", context)
        return self.implementation.generate(configuration, context)

    def apply(self, generated, context):
        self._stage("apply", context)
        return self.implementation.apply(generated, context)


def recorded_registry(schema):
    return {name: RecordingModule(module) for name, module in registry(schema).items()}


def firewall_context(effective, previous, owner, root, recovery=False, *, previous_effective, schema=None):
    """Construct the same ownership and dependency context that configd supplies."""
    from nvyr.helpers.dependencies import Dependencies
    from nvyr.modules import CommitContext
    from nvyr.schema import Schema
    from nvyr.tree import ReadOnlyTree

    # Rendering callers have already validated this schema; reuse their instance
    # instead of compiling the entire command tree again for each snapshot pair.
    if schema is None:
        schema = Schema.bundled()
    current = schema.ownership.snapshot(effective)
    prior = schema.ownership.snapshot(previous_effective)
    return CommitContext(effective, previous, owner, root, recovery,
                         previous_effective=previous_effective,
                         dependencies=Dependencies(schema),
                         sections=ReadOnlyTree(current.sections.get(owner, {})),
                         previous_sections=ReadOnlyTree(prior.sections.get(owner, {})))
