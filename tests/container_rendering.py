"""Render real Quadlet templates for focused output assertions."""

from nvyr.helpers.template import render


def container_unit(name, configuration, image, image_user=None):
    return render('containers/container.container.j2', {
        'name': name, 'configuration': configuration, 'image': image, 'image_user': image_user})


def pod_unit(name, configuration):
    return render('containers/pod.pod.j2', {'name': name, 'configuration': configuration})


def network_unit(name, configuration):
    return render('containers/network.network.j2', {'name': name, 'configuration': configuration})
