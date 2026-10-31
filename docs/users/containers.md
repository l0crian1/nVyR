# Containers

For implementation and testing, see the [developer guide](../dev/containers.md).

nVyR manages rootful Podman containers and Netavark bridge networks. Net-admins
and administrators can configure them and download images. Netavark owns the
bridges, veth pairs, addressing, DNS, and port-publishing/NAT rules.
The image ships Podman 6.1.4, Netavark 2.1.0 and Aardvark DNS 2.1.0 together.

## Images and configuration

Download an image before committing an enabled container:

```text
add container image docker.io/library/busybox:1.37

configure

set container network SERVICES subnet 172.20.0.0/24 gateway 172.20.0.1
set container network SERVICES subnet fd00:20::/64 gateway fd00:20::1

set container name TEST image docker.io/library/busybox:1.37 command sleep argument infinity
set container name TEST network SERVICES address 172.20.0.10
set container name TEST network SERVICES address fd00:20::10
set container name TEST network SERVICES alias example

set container name TEST environment TZ value America/New_York

set container name TEST volume DATA source TEST/data
set container name TEST volume DATA destination /data

commit
save
```

Image names may omit the registry and tag, for example `add container image
l0crian/segman`. Podman supplies `latest` when the tag is omitted. Short names use
Docker Hub by default. Configure an ordered search list with unique priorities:

```text
set container registry quay.io priority 10
set container registry docker.io priority 20

commit
```

Explicit registry names continue to work. Podman's existing short-name aliases
take precedence over the search list. Lower priorities are searched first; pulls
do not prompt for a registry. Removing all registry entries restores Docker Hub.
This setting does not restart existing containers. Image completion suggests the
names and tags already installed in the router's rootful Podman store.
`container name` and `container network` are anchored. Nested attachments, volumes,
and published ports use separate commands for their settings, following the existing
nested-tag parser convention. `description` is available on networks and containers.

The optional `command` is one executable/command token passed after the image to
Podman; it replaces the image CMD and retains its ENTRYPOINT. `argument` is one
quoted string, split with shell-style quoting. Order and repeated arguments are
preserved. There is no host shell expansion: dollars, percent signs, and shell
operators remain literal arguments. A shell inside the container must be requested
explicitly if the application needs one.

`show containers` lists running and stopped containers, plus configured containers
that have not been created. It combines Podman state with service status so startup
failures remain visible.
In configuration mode, use `run show containers`.

Interactive stdin and a terminal are enabled by default, so images such as Alpine
can keep their default shell running without a command override. Disable either
independently when an application needs closed stdin or separate stdout/stderr:

```text
set container name APP interactive disable
set container name APP tty disable
```

Deleting either `disable` leaf restores that default. Neither setting overrides the
image's command or prevents a process from exiting on its own. Use
`show containers name APP detail` and `show log containers name APP` to inspect
exit status and application output, including after a container exits.

## Networks and published ports

Omit attachment `address` values for automatic allocation. One static IPv4 and one
static IPv6 address can be selected per attachment. Multiple named networks and
DNS aliases are supported. Subnets must not overlap between configured networks.

Podman container and network names match the configured names without an `nvyr-`
prefix: use `podman inspect TEST` or `podman network inspect SERVICES`. Ownership
is checked using the `nvyr.managed` label; existing unmanaged objects are rejected.

This development change does not migrate earlier `nvyr-` names. Remove the old
container/network configuration and commit using the previous build before updating,
then recreate it with the new naming and attachment IDs. Persistent volume data is
retained when those objects are removed.

Netavark creates each bridge as `pd-<network>` and each host-side veth as
`pd-<container>-<id>`. Attachment `id` defaults directly to `0`, accepts `0` through
`9`, and must be unique within a container. A second attachment needs another ID:

```text
set container name WEB network SERVICES id 0
set container name WEB network PRIVATE id 1
```

These create `pd-WEB-0` and `pd-WEB-1`, attached to `pd-SERVICES` and `pd-PRIVATE`.
Removing an attachment does not renumber the others. Container names allow at most
10 ASCII characters and network names at most 12, so all generated interface names
fit Linux's 15-byte limit. Names start with a letter or digit and may also contain
underscores and hyphens. Podman's network-mode names (`bridge`, `host`, `none`,
`private`, `slirp4netns`, `pasta`, and `default`) are reserved. Network and container
descriptions remain configuration metadata; nVyR does not set Linux interface
descriptions because Netavark does not expose that option.

Generated bridge and veth names must not collide: a network named `WEB-0` conflicts
with container `WEB` attachment ID `0`.

```text
set container network PRIVATE subnet 172.21.0.0/24
set container network PRIVATE internal
set container network PRIVATE disable-dns

set container name WEB network SERVICES

set container name WEB port HTTP protocol tcp
set container name WEB port HTTP source-address 10.0.1.1
set container name WEB port HTTP source-port 8080
set container name WEB port HTTP destination-port 80
```

`internal` prevents external routing; `disable-dns` disables Netavark's DNS service
for that network. Published ports support TCP, UDP, and SCTP. Omitting source-address
publishes on all host IPv4 addresses. Attachments must reference a configured network;
a referenced network cannot be deleted.

Separate bridges are isolated by default. Containers on the same bridge can
communicate; direct traffic between different bridges is blocked by Netavark.
To permit routing between two container networks, explicitly disable isolation
on both networks:

```text
set container network SERVICES isolation disable
set container network PRIVATE isolation disable
```

Deleting `isolation disable` restores the default. This is independent of
`internal`: disabling isolation does not enable external routing on an internal
network. nVyR firewall rules still apply, and Netavark 2.1 permits access through
explicitly published host ports even when bridges are isolated. Changing the
option recreates the affected network and its attached containers during commit.

Host networking is explicitly selected:

```text
set container name DNS allow-host-networking
```

It cannot be combined with network attachments or published ports. A container with
neither an attachment nor host networking gets `network=none`, not a default bridge.

Netavark uses its own nftables table. nVyR's firewall continues to control traffic:
Netavark accepting or publishing traffic does not override a drop in nVyR's chains.
Configure the applicable input/output/forward policy, including translated addresses
where relevant. Host-networked applications share the router's sockets and ports.

## Persistence and resource limits

Relative bind sources resolve beneath `/config/containers/`. Absolute sources can
select existing host files or directories elsewhere. Missing directories beneath
`/config/containers/` are created with mode 0700, including when specified by their
absolute path. External sources must already exist. Symlinks in source paths are
rejected; use the actual path, such as `/run/` instead of a `/var/run/` symlink.
Destinations are absolute file or directory paths and cannot overlap. Add
`read-only` to prohibit container writes. Image-declared anonymous volumes are
disabled; configure persistent directories explicitly.

```text
set container name DNS volume DATA source DNS/data
set container name DNS volume DATA destination /data

set container name DNS volume HOSTS source /etc/hosts
set container name DNS volume HOSTS destination /etc/hosts
set container name DNS volume HOSTS read-only
```

Only `/config/containers/` data participates in its existing image-upgrade transfer.
Mounting an external path does not add it to that transfer.

Set ownership and permissions explicitly when the image's services need them:

```text
set container name APP volume DATA owner user redis group redis
set container name APP volume DATA mode 0700

set container name APP volume DATA owner recursive
```

`owner user` and `owner group` accept image account names or numeric UID/GID values.
Names resolve from `/etc/passwd` and `/etc/group` in the selected image without
running its programs. Specify either or both; omitted ownership fields remain
unchanged. Numeric IDs do not require matching image accounts. These settings
change the host source, not the container process identity or host account databases.

`owner recursive` also changes ownership of existing directory contents, without
following symlinks. `mode` accepts three or four octal digits and affects only the
mounted file or top-level directory, never its children. Omitting these settings
preserves existing metadata. Removing them does not reset previous permissions.
Ownership and mode changes are persistent data preparation, including on read-only
mounts; they are not undone when a later container startup fails. Recursive ownership
can take time for large directories. Verify account names against the image you use;
the `redis` example requires that account in the image.

Deleting, disabling, or recreating a container preserves its persistent directories.
The Podman image cache and writable container layers are separately stored in
`/config/podman/storage`; these are not allowed as user-configured bind mounts.
Podman uses `fuse-overlayfs` for image layers so storage works on the live ISO's
overlay filesystem as well as installed systems.
Writable container layers are disposable. Stop workloads before copying their data
for an image upgrade if application-consistent data is required.

Defaults are 512 MiB memory (no additional swap allowance), one CPU, 256 processes/
threads, and `on-failure` restart policy. Override with:

```text
set container name TEST memory 1g cpus 0.5 process-limit 512 restart-policy always
```

Memory accepts whole bytes or binary k/m/g suffixes, from 6 MiB through 1 TiB.
CPU limits accept 0.01–1024 CPUs; process-limit accepts 1–65536. Restart policies
are `no`, `on-failure`, and `always`. Containers retain the image's configured user;
capabilities use Podman's default set. nVyR does not force no-new-privileges;
it can be enabled explicitly. Arbitrary Podman arguments are not exposed.

## Additional container and network options

Netavark owns VRF attachment and MTU configuration for its bridges and endpoints:

```text
set vrf name BLUE table 210

set container network SERVICES vrf BLUE
set container network SERVICES mtu 1400
set container network SERVICES disable-dns
```

The VRF must exist in configuration; dependencies prevent deleting it while a
network references it. VRFs apply before containers. IPv6 networks require an MTU
of at least 1280. Network changes recreate affected networks and their containers.
VRF networks require network-level `disable-dns`: Aardvark DNS 2.1 cannot bind
their bridge addresses. Containers can still use explicit external name servers.

Container options are independent of the network-level `disable-dns` setting:

```text
set container name APP host-name app01
set container name APP name-server 1.1.1.1
set container name APP name-server 9.9.9.9

set container name APP capability net-admin
set container name APP capability net-raw
set container name APP device /dev/net/tun
set container name APP device /dev/net/tun permissions rw

set container name APP entrypoint "/usr/local/bin/start"
set container name APP environment-file APP/settings.env

set container name APP tmpfs /tmp size 64m
set container name APP tmpfs /tmp mode 1777
```

Use `set container name APP disable-dns` instead of `name-server` to leave the image's
`/etc/resolv.conf` untouched. This does not block DNS packets. Both DNS options
require a bridge attachment or host networking. When network DNS is enabled,
Aardvark can forward queries to the selected servers.

An omitted entrypoint preserves image metadata. `entrypoint ""` clears it. Quoted
entrypoint text is split into argv without a host shell; `command` and `argument`
remain the arguments following the entrypoint. Deleting the override restores the
image's entrypoint.

Environment files must already exist beneath `/config/containers/`. Only regular
files are accepted and symlinks are rejected in every path component. Generation
snapshots their contents before changing workloads; explicit `environment` values
override file values. Applying container configuration rereads the file and recreates
its container if contents changed. Rollback restores the previous snapshot. Snapshots
are held in root-only runtime files. The persistent inventory retains only their
fingerprints.

Device sources must be character or block devices beneath `/dev`. Their destination
defaults to the same path; `destination` can select another `/dev` path. Permissions
default to `rwm` and can select read (`r`), write (`w`), and mknod (`m`).

Tmpfs data is disposable and defaults to Podman's mount capacity and permissions
when omitted. Size accepts bytes or binary k/m/g suffixes through 1 TiB. Mounts use
noexec, nosuid and nodev. Tmpfs, persistent volumes and device destinations cannot
overlap.

`set container name APP privileged` enables Podman's privileged mode, including
all capabilities and broad device access. It overrides configured
capability restrictions and ignores a configured `no-new-privileges` restriction. Net-admins can configure
this option, so they can grant a container host-root-equivalent access. Prefer
specific capabilities and devices when they satisfy the application.

Named `capability` values add to Podman's default capability set. nVyR does not
maintain a separate list of default capabilities.

Use `capability none` to drop Podman's default set and all other
capabilities. Named capabilities on the same container are then added explicitly:

```text
set container name APP capability none

set container name APP capability net-admin
```

With just the first command, the container has no capabilities. With both, it has
only `NET_ADMIN`. Deleting `capability none` restores Podman's default capability set
alongside any explicitly named capabilities. Privileged mode still grants all
capabilities and overrides these restrictions.

Use `no-new-privileges` to prevent programs from gaining privileges through setuid,
setgid or executable file capabilities. This can prevent `sudo` and similar helpers
inside an image from working; it does not remove capabilities already held by a process.

```text
set container name APP no-new-privileges

delete container name APP no-new-privileges
```

Deleting the option restores Podman's default behavior when the container is recreated
on commit. Privileged mode overrides this option.

## Pods

A pod groups containers that share networking, hostname and IPC namespaces. Its
members use the same IP addresses and can reach each other over `localhost`.
They share the same port space: two members cannot both listen on the same
address and port. Filesystems and resource limits remain separate; configure
volumes on each member when they need shared files.

Create ordinary container networks first. Networks need no special pod settings,
and a network can connect both pods and standalone containers.

```text
set container network SERVICES subnet 172.20.0.0/24 gateway 172.20.0.1

set container pod WEB description "Application and cache"
set container pod WEB host-name web
set container pod WEB network SERVICES address 172.20.0.10

set container pod WEB port HTTPS protocol tcp source-port 443 destination-port 443

set container name APP image example/web:latest
set container name APP pod WEB

set container name CACHE image redis:alpine
set container name CACHE pod WEB
```

Preload the images with `add container image` before committing. In this example,
APP reaches Redis at `127.0.0.1:6379`. The application images still need their own
appropriate settings and persistent storage.

`container pod <name>` is anchored. It supports `description`, `disable`,
`host-name`, `name-server`, `disable-dns`, `allow-host-networking`, `network`, and
`port`. Network attachments support the same `id`, `address`, and `alias` settings
as standalone containers. A pod can attach to VRF networks through the network's
existing `vrf` setting.

```text
set container network BACKEND subnet 172.21.0.0/24

set container pod WEB network SERVICES id 0
set container pod WEB network BACKEND id 1
set container pod WEB network BACKEND address 172.21.0.10 alias web-backend
```

These attachments create `pd-WEB-0` and `pd-WEB-1`. Attachment IDs default to `0`,
must be unique within the pod, and range from `0` to `9`. Pod names follow the
same ten-character limit as containers, and pod and container names must be
distinct. The container name `pod` is reserved for pod operational commands.
Quadlet also reserves `<pod>-infra` for its infrastructure container.
Existing bridge/veth name collision checks apply to pods too. Netavark creates
the shared connections; members do not each create another veth.

A member's `pod` setting conflicts with its own `network`, `port`,
`allow-host-networking`, `host-name`, `name-server`, and `disable-dns`. Set those
on the pod. Images, commands, environment, volumes, capabilities, devices, memory,
CPU allowances and restart policies stay on the individual containers. An
unattached pod has isolated networking; host networking must be explicit and
cannot be combined with attachments or published ports.

```text
set container pod WEB name-server 1.1.1.1

set container name APP memory 256m cpus 0.5
set container name CACHE memory 128m cpus 0.5
```

Changing a pod or one of its networks recreates the affected pod and its members.
Changing only one container recreates that member and preserves its siblings.
`set container pod WEB disable` stops the pod and every member; removing it starts
members that are not individually disabled. A referenced pod cannot be deleted
until its member references are removed. Failed commits restore the previous
pod and member configuration through the existing container rollback pipeline.

```text
show containers pods
show containers pod WEB
show containers name APP detail
show system services container name WEB

restart container pod WEB
```

The pod view shows shared addresses, published ports, and member states, including
failed services that never created a native container. Restart waits for the pod
and enabled member services to start. Pod namespaces remain alive when individual
members exit, allowing their configured restart policies to work independently.

## Connecting to a container

Network administrators can open `/bin/sh` in a running managed container, or run
a quoted shell command inside it:

```text
connect container TEST

connect container TEST send-command "hostname; ip address"
```

Exit the shell to return to the nVyR prompt. The image must contain `/bin/sh`.
Commands run as the container's configured user; they do not start a stopped
container or evaluate shell expressions on the router. Pod members use their
container names just like standalone containers.

## Updates and recovery

```text
update container image name docker.io/library/busybox:1.37
update container image container TEST
```

Both update forms and `add` run a normal `podman pull`, fetching the current image
while reusing layers already available locally; they do not restart containers.
Image names accept an optional registry, tag or sha256 digest. Local archive and
directory transports are not exposed. Running instances are pinned to their
selected image ID, including across unrelated commits and boot recovery.

To adopt an updated image, disable and commit the container, then delete its disable
setting and commit again. Configuration changes recreate affected containers. A
network change stops its consumers before recreating the network and its consumers.
Other containers remain running. Commit failures attempt to restore previous
definitions and selected images; failure to restore is reported as a recovery error.
An operation journal records affected names before native changes, allowing boot
recovery to clean up an interrupted apply. A successful commit confirms that the
service started; it is not an application health check.

Container startup failures are reported without preventing login. Use [container operations](container-operations.md) and [container logs](logging.md#container-logs) to inspect them.

## Container user and group

`uid` and `gid` select the process identity **inside the workload container**.
Both default to `auto`: retain the image user and the selected user's primary
group. Numeric values range from 0 through 4294967294. These settings do not
allocate host users, change host account IDs or configure user-namespace mapping.
There is no reserved CLI-session UID/GID block.

```text
set container name APP uid 1000 gid 1000
```

Bind-mounted files still need permissions appropriate to the container's runtime
identity. Internal CLI sessions use a separate Podman store and do not appear in
`show containers`, image suggestions or workload inventory commands.
