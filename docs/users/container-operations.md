# Container operations

For implementation and testing, see the [developer guide](../dev/container-operations.md).

Inspect running, stopped and failed containers, their networks and images. These
commands complement [container configuration](containers.md).

## Commands

```text
show containers
show containers name DNS
show containers name DNS detail

show containers statistics
show containers statistics name DNS
show containers statistics name DNS follow

show containers networks
show containers networks name LAN

show containers images

restart container DNS
```

## Container status and detail

`show containers` combines running configuration from configd, Podman inventory and
systemd service state. It includes exited containers and configured containers
that have not been created, including startup failures. Unmanaged Podman
containers are also visible and identified as unmanaged. Pending candidate
configuration does not appear in this operational view.

The default and name-filtered views are tables. `detail` adds the command,
timestamps, exit status, image ID, restart count, network addresses, mounts and
resource limits. Environment values and arbitrary inspection metadata are not
included. Managed restart counts come from systemd's automatic-restart counter;
unmanaged counts come from Podman. They are not a lifetime history of manual
restart operations.

## Networks and images

Network inventory includes the native bridge, VRF, subnets, gateways and attached
containers. A named network also shows its container addresses. Missing
configured networks remain visible. Image inventory correlates current container
image IDs, rather than assuming a moving image tag identifies the running image.

## Resource usage

Statistics take a single snapshot unless `follow` is selected. Follow refreshes
until Ctrl+C. A concurrent image or configuration operation causes a clear
retry message rather than an indefinite display wait.

## Managed restart

`restart container` requires net-admin or administrator. It restarts the
generated systemd service, allowing a failed startup to be retried even when no
native container exists. It preserves configuration and the image pinned by that
service; it does not pull an image. Disabled containers, unmanaged objects, missing
generated units and interrupted container transactions cannot be restarted this
way. Startup failures are reported without a success message.
