# Containers: implementation and maintenance

For configuration and command usage, see the [user guide](../users/containers.md).

## Configuration implementation

`src/nvyr/config_scripts/container.py` owns the four configuration stages:

- `get_config()` gathers current and previous container configuration and configured
  VRF names. It uses `context.get_changed()` to identify affected objects and their
  network and pod consumers.
- `verify()` checks relationships, required settings and conflicting options.
- `generate()` resolves image IDs, captures environment-file contents, and renders
  changed `.network`, `.pod` and `.container` files. It snapshots the installed files
  for rollback rather than rendering the previous configuration again.
- `apply()` installs the generated result in dependency order. It does not render
  templates, resolve image tags or transform the configuration again. If application
  fails, it uses the prepared rollback result.

Supporting functions sit above the stage that uses them. The Quadlet templates
contain their native sections and directives; small formatters handle argument
quoting, network attachments and other compound values. Shared filesystem helpers
provide safe directory traversal, file reading and bind mounts beneath an explicit
root directory.

Generation runs directly in the configuration script and validates temporary files
with Podman's Quadlet generator. Configd's unit declares `CacheDirectory=containers`
so Podman can lock its short-name alias cache during local image inspection, even
with `ProtectSystem=strict`. This supports names such as `alpine` without granting
write access to other cache directories.

Apply sends one prepared result to a host worker
because configd's mount restrictions prevent workload mounts and service setup.
The worker holds the container operation lock and rejects the result if the managed
inventory or interrupted-operation cleanup list changed after generation. It calls
the script's `apply()` stage directly, without a commit context; it neither
revalidates the configuration nor reruns generation. Its private request file is
removed afterward. An unchanged configuration and unchanged external inputs need
no host worker.

Configd is the source of running configuration, including for container operational
commands. The container inventory stores managed object/interface names, pinned image
IDs, and configuration/environment fingerprints. It does not store a second copy
of the CLI configuration or environment contents. Before changing native objects,
apply records the names that might need cleanup if interrupted. Configd's transaction
journal determines the configuration to restore; the cleanup list only identifies
native objects that may have been created before that configuration was published.

For a failed live application, the script restores the captured files and previous
inventory. It does not regenerate the old definitions or resolve their image tags.
This restores container configuration, not application data written to mounted
volumes. Ownership checks cover affected objects, including foreign pod members,
before any workloads are stopped.

Systemd stops affected units, including completed network services and services
waiting to restart. The script removes their definitions and changed native networks,
installs the prepared files, reloads systemd once, and starts the affected units
together. Quadlet dependencies determine startup order; Netavark handles interfaces,
VRF attachment and MTU. Unchanged workloads remain running.

## Packaging and testing

The ISO includes Podman, catatonit, fuse-overlayfs, Netavark, aardvark-dns, and crun.
Catatonit provides Podman's local infrastructure process for pods; no separate
infrastructure image download is required. Updating only the `.deb`
requires installing the matching container packages too; stock Trixie versions
are too old. See [dependency packaging](debian.md#router-dependency-versions).
Configuration checks are in `/usr/lib/nvyr/smoketests/test_container.py` and
`test_container_validation.py`. Workload, restart and operational behavior is in
`/usr/lib/nvyr/functionaltests/workloads/test_container.py`. Use `--container-image` with a
preloaded BusyBox-compatible image; neither suite downloads images. See the
[smoketest instructions](../../smoketests/README.md) and
[functional test instructions](../../functionaltests/README.md).

`test_container_pods.py` covers shared pod networking, IPv4/IPv6, attachment names,
independent member changes, pod disable/restart, and reference/conflict validation.

## Bind-mount isolation

The worker pins each opened source file or directory as a private bind mount before
Podman receives it. Descriptor-based traversal rejects symlinks and parent traversal.
Relative sources resolve below `/config/containers/`; absolute sources remain host
paths. Only missing directories below `/config/containers/` are created. External
sources are checked in the host namespace before stopping workloads, then reopened
and pinned during apply. Staging targets and cleanup support both files and directories.

Generation resolves named volume owners from the pinned image's account files via
a read-only inspection operation in the host worker. Podman mounts the image, the
worker reads its account databases, and the image is unmounted in a finally block.
No image entrypoint executes. Numeric IDs, source resolution, recursion and mode are
captured in the prepared mount records. Apply performs the requested ownership and
permission changes before binding the sources. These persistent metadata changes,
like application writes to a volume, are not a transactional filesystem snapshot;
compensation restores runtime definitions, not arbitrary previous volume metadata.

## Runtime units and execution

The container script installs runtime Quadlet files under `/run/containers/systemd/`; the unit name
is `nvyr-container-<hex-encoded-container-name>.service`. Startup does not pull images.
Pods use `nvyr-pod-<hex-encoded-pod-name>.service` and member units reference their
`.pod` definition. Networks use `.network` definitions and
`nvyr-network-<hex-encoded-network-name>-network.service`. Their consumers reference
the definitions so systemd orders network, pod and container startup.
Container failures during boot are reported without preventing configd/login startup.
Systemd handles ongoing restarts. Workload mounts and changes run in a controlled
systemd worker outside configd's restricted mount namespace. Display commands query
Podman and systemd directly from the host-side operational script. Their shared
lock fails promptly if a workload change is in progress, and statistics release it
between samples. Workload output uses the configured container log files.

## Registry schema history

The ordered registry tree replaces `container default-registry`. Remove an
explicit old setting before updating an existing development router, then configure
its registry entries using the new syntax; saved configurations are not migrated.
