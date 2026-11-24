"""Manage the supplicant instance adopting each named MACsec device."""

from pathlib import Path

from nvyr.helpers import template
from nvyr.helpers.process import cmd

DIRECTORY = Path('/run/nvyr-netlink/macsec')


def unit(name):
    return f'nvyr-macsec@{name}.service'


def stop(name):
    directory = DIRECTORY / name
    if directory.exists():
        cmd(['systemctl', 'stop', unit(name)])
        (directory / 'supplicant.conf').unlink(missing_ok=True)
        (directory / 'parent').unlink(missing_ok=True)
        control = directory / 'ctrl'
        if control.exists():
            control.rmdir()
        directory.rmdir()


def synchronize(name, settings):
    directory = DIRECTORY / name
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = directory / 'supplicant.conf'
    environment = directory / 'parent'
    desired = template.render('macsec/supplicant.conf.j2', {'directory': directory, 'settings': settings})
    parent = 'PARENT=' + settings['parent'] + '\n'
    changed = not config.exists() or config.read_text() != desired
    changed_parent = not environment.exists() or environment.read_text() != parent
    if changed_parent:
        template.write(environment, parent)
    if changed:
        template.write(config, desired)

    # A kernel link recreation can stop a device-bound service while the config stays identical.
    if changed or changed_parent:
        cmd(['systemctl', 'restart', unit(name)])
    elif not (directory / 'ctrl' / settings['parent']).exists():
        cmd(['systemctl', 'start', unit(name)])
