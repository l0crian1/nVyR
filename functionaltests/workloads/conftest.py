"""Install standalone workloads and pods in one transaction for this package."""

import pytest

from functionaltests.container_scenarios import batch_containers, publication_client
from nvyr.helpers.process import cmd


@pytest.fixture(scope='package', autouse=True)
def container_scenario(config, request):
    """All workloads coexist; each mutation case owns its container or pod."""
    image = request.config.getoption('--container-image')
    if not image:
        pytest.skip('Pass --container-image with a preloaded BusyBox-compatible image')
    cmd(['podman', 'image', 'inspect', image])
    with publication_client() as client, batch_containers(config, request, image, ('containers.conf', 'pods.conf')) as resources:
        yield resources | {'client_namespace': client}
