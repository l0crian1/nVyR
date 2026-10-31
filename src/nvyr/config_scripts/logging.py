"""Configure early file collectors independently of packet-filter installation."""

from nvyr.helpers import frr_reload, logging_formatters, logging_runtime
from nvyr.errors import RouterError, ValidationError
from nvyr.tree import lookup


def get_config(context):
    return {
        'logging': lookup(context.effective, ('system', 'logging'), {}),
        'previous': lookup(context.previous_effective, ('system', 'logging'), {}),
    }


def verify(configuration, context):
    for name, options in lookup(configuration['logging'], ('service',), {}).items():
        # An override must specify a threshold; an empty service has no effect.
        if 'level' not in options:
            raise ValidationError(f'system logging service {name}: level is required')


def generate(configuration, context):
    return {
        'files': logging_formatters.render(configuration['logging']),
        'previous_files': logging_formatters.render(configuration['previous']),
        'frr': {'global': ['log syslog']},
    }


def apply(prepared, context):
    try:
        logging_runtime.install(prepared['files'])
        # FRR retains daemon names and severities; the collector owns thresholds.
        frr_reload.manager.apply('logging', prepared['frr'], context.state_directory,
                                 adapter=logging_runtime.FrrLogging())
    except Exception as error:
        try:
            logging_runtime.install(prepared['previous_files'])
        except Exception as restore_error:
            raise RouterError(f'Logging apply failed ({error}); restoration failed: {restore_error}') from restore_error
        raise RouterError(f'Logging apply failed; previous configuration restored: {error}') from error
