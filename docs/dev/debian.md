# Build nVyR with Docker

Use `nvyr-image-builder` to build either the nVyR Debian package or the complete
router ISO. Run the commands below from the repository root, with Docker running
Linux containers. The current image target is **Debian 13 (trixie), amd64**.

The host needs Docker, access to this checkout, and network access for dependency
downloads. Python, compilers and live-build run inside the builder. Allow space in
Docker's storage for package compilation and ISO assembly, as well as space in
`dist/` for the results.

Before publishing binary packages or ISOs, follow the
[licensing and source-distribution requirements](../../THIRD_PARTY.md).

To run GitHub's regression tests and package builds before pushing, use the
separate [local CI test container](testing.md).

## Build the builder

Use the published builder without compiling its cached packages locally:

```sh
docker pull l0crian/nvyr-image-builder:0.1.1
docker tag l0crian/nvyr-image-builder:0.1.1 nvyr-image-builder
```

The local tag lets you use the commands below unchanged. Use a published version
matching your checkout's `images/Dockerfile` marker, or `latest` for the most
recent published builder.

To build it locally instead:

```sh
docker build -t nvyr-image-builder -f images/Dockerfile .
```

This installs the build tools and prepares the pinned kernel, FRR and container-stack
packages. The initial kernel compilation is substantial; ISO builds reuse the
compiled package. Docker caches these layers, so subsequent builds reuse unchanged work.
Run this command again when the builder's inputs change; it is not needed for
every Python, schema or template edit.

### Publish a builder version

The first line of `images/Dockerfile` controls the builder release version:

```dockerfile
# builder-version: 0.1.2
```

Increase this `MAJOR.MINOR.PATCH` value when changing the builder, including its
copied kernel/FRR/container source locks, packaging helpers or FRR patches. Commit the
version bump together with those changes.

The [Publish image builder workflow](../../.github/workflows/image-builder.yml)
watches `images/Dockerfile` on `main`. A version increase builds an amd64 image
and publishes both `l0crian/nvyr-image-builder:<version>` and `:latest`. The first
addition of the marker also publishes. Dockerfile edits without a version change
skip publication; other project edits do not trigger the workflow.

It uses the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The
token must have write access to `l0crian/nvyr-image-builder`. The workflow caches
build layers between runs, so unchanged package recipes can be reused.

For a retry, use **Actions → Publish image builder → Run workflow** on `main`.
A manual run rebuilds and republishes the current version and `latest` without
requiring another bump. The builder version is independent of nVyR's release
version and the ISO's `--built-by` attribution.

## Build only the Debian package

```sh
docker run --rm -v "$PWD:/workspace" --entrypoint /bin/sh nvyr-image-builder /workspace/scripts/build-deb.sh
```

Output: `dist/nvyr-router_0.1.0_all.deb`.

The default version comes from `project.version` in `pyproject.toml`. To override
it for one package build, or select a different output directory:

```sh
docker run --rm -v "$PWD:/workspace" --entrypoint /bin/sh nvyr-image-builder \
  /workspace/scripts/build-deb.sh --version 0.2.0-rc1 --output-dir /workspace/dist
```

The staged Debian control file and package filename use that version. The source
`pyproject.toml` and control template remain unchanged. `--debug` enables shell
command tracing for package builds as well.

This builds schemas, validates and installs operational-script wrappers, and
packages the Python code, templates, service files, smoketests and acceptance-test
agent. It does not build an ISO, bundle runtime dependency packages into the
nVyR `.deb`, or run the test suites. Privileged mode is not needed.

Inspect the package metadata, including its dependencies:

```sh
docker run --rm -v "$PWD:/workspace" --entrypoint dpkg-deb nvyr-image-builder --info /workspace/dist/nvyr-router_0.1.0_all.deb
```

## Build the ISO

```sh
docker run --rm --privileged -v "$PWD:/workspace" nvyr-image-builder
```

To identify who built the image in `show version`, supply an optional attribution:

```sh
docker run --rm --privileged -v "$PWD:/workspace" nvyr-image-builder --built-by "L0crian"
```

Names may contain spaces. If omitted, `show version` displays `Not specified`.

Available ISO build options:

- `--version VERSION`: use this version for the ISO metadata, bundled Debian
  package and artifact names. Defaults to `project.version` in `pyproject.toml`.
- `--built-by NAME`: builder attribution shown by `show version`.
- `--output-dir PATH`: write artifacts here. Defaults to `/workspace/dist` in the
  builder container; relative paths are resolved from the checkout root.
- `--debug`: trace shell commands while retaining normal live-build output.
- `--help`: display the options without starting a build.

```sh
docker run --rm --privileged -v "$PWD:/workspace" nvyr-image-builder \
  --version 0.1.0 \
  --built-by "L0crian" \
  --output-dir /workspace/dist \
  --debug
```

Versions start with a digit and may contain letters, digits, dots, plus signs,
tildes and hyphens, for example `0.1.0`, `0.2.0-rc1` or `0.2.0~rc1`. A trailing
hyphen, whitespace, path separators and Debian epoch prefixes are not accepted.
The override changes this ISO/package build; it does not change the project
version used by separate Python wheel builds. Builder-container tags remain
independent of the nVyR version.

The default entrypoint runs `images/build.sh`. It first builds the nVyR `.deb`,
then assembles the Debian live filesystem, installs dependencies, runs the image
hooks and produces the ISO. There is no need to build the package separately first.

Privileged mode is required for live-build's mount and chroot operations. Build
staging stays in the container's Linux filesystem; completed artifacts are copied
into the checkout's `dist/` directory.

Outputs for version `0.1.0`:

- `dist/nvyr-router_0.1.0_all.deb` — the package included in this ISO.
- `dist/nvyr-0.1.0-amd64.iso` — bootable live/installation media with BIOS and UEFI
  support. Secure Boot is not supported.
- `dist/nvyr-0.1.0-amd64.iso.sha256` — SHA-256 checksum of the completed ISO.
- `dist/nvyr-0.1.0-amd64.build.json` — version, UTC build timestamp, builder
  attribution, Git commit and dirty state. The same metadata is installed at
  `/usr/share/nvyr/build.json` and included in the ISO manifest.
- `dist/nvyr-0.1.0-amd64-<timestamp>.build.log` — combined standard output/error
  from this build, including package assembly. Each run gets a separate log.
- `dist/nvyr-0.1.0-amd64.packages.lock` — the downloaded package pins.
- `dist/nvyr-0.1.0-amd64.frr-packages.json` — FRR package hashes and recipe identity.
- `dist/nvyr-0.1.0-amd64.container-packages.json` — container-stack package hashes
  and recipe identity.
- `dist/nvyr-0.1.0-amd64.kernel-packages.json` — kernel release, package/source
  hashes and recipe identity.
- `dist/nvyr-0.1.0-amd64.kernel-source.tar` — the matching upstream kernel source,
  Debian baseline configuration, resolved configuration, source lock and build recipe.

The Git fields are `git_commit` and `git_dirty`. Dirty state includes staged,
unstaged and untracked files, captured before this build creates its outputs.
Both fields are `null` when building a source archive without `.git`. Keep custom
output directories ignored by Git if they are inside the checkout.

Build output is streamed to the console and saved to the log. Failed builds keep
their log and return a nonzero exit status. A checksum is produced only after
successful ISO assembly. Check a downloaded or copied ISO from its directory:

```sh
sha256sum -c nvyr-0.1.0-amd64.iso.sha256
```

Artifact filenames other than logs are reused for the same version. An older
artifact can remain in
`dist/` after a failed build; its presence alone does not indicate success. Check
the command's exit status and the final build output.

Do not overwrite an ISO that a running VM is using as its live filesystem. Stop
the VM first or build/copy to a different media path. If a lab platform imports
ISOs into its own storage, replace that imported copy before booting the new build.

## When to rebuild what

- **Python, schemas, templates, operational scripts or smoketests:** rebuild the
  `.deb` for a quick development update, or build the ISO to include them in an image.
- **Runtime dependency declarations, image package lists or boot hooks:** rebuild
  the ISO. A package-only update does not refresh the router's complete OS.
- **`images/Dockerfile`, kernel/FRR/container source locks, their packaging helpers, or
  FRR build patches:** rebuild `nvyr-image-builder`, then build the ISO.
- **`images/packages.lock`:** rebuild the ISO to download and install the new
  pinned packages. This lock is read from the mounted checkout during assembly.

Mounting the checkout supplies current project files; it does not update packages
already cached inside the builder. A stale kernel/FRR/container cache is rejected rather
than silently included. Rebuilding the builder normally fixes this without
`--no-cache` or deleting Docker's entire cache.

## Kernel maintenance

The image uses **Linux 6.18 LTS**, pinned to **6.18.59** in
`images/kernel-sources.lock`. Debian remains the userspace distribution. The
builder compiles upstream Linux with the general-purpose Debian amd64 kernel
configuration, retaining hardware drivers, module support and BTF. It replaces
Debian-specific certificate paths and adds the `-nvyr-amd64` release suffix.
Separate debug-symbol packages are not included in the image.

The ISO includes Debian's `firmware-realtek` package from `non-free-firmware`
for Realtek NIC firmware, including the RTL8168H onboard and RTL8156B USB
Ethernet patches. These files accompany the kernel drivers; updating only
`nvyr-router.deb` does not install them.

Automatic live-build firmware inclusion is disabled. Firmware packages are
selected explicitly in `images/router.list.chroot`, so enabling the firmware
repository does not add the entire firmware collection to the ISO.

The source archive and baseline configuration package are checked against their
pinned SHA-256 hashes before extraction. Required networking, container and boot
features are checked after Kconfig resolves dependencies. ISO assembly selects
the exact versioned package through live-build and requires exactly the pinned
kernel in `/boot`; Debian's moving `linux-image-amd64` meta-package is not installed.

For a maintenance update, change the version, package revision, source URL/hash
and source timestamp in the lock, then bump the builder version and rebuild it.
Review configuration changes when refreshing the Debian baseline. Boot the new
ISO and test interfaces, VRFs, bridges, containers, conntrack and flowtables before
publishing. Installing only `nvyr-router.deb` does not upgrade the kernel.

The opt-in [native hook lifecycle test](../../tests/test_kernel_flowtables_live.py)
requires root and `NVYR_KERNEL_TEST=1` inside a disposable test system. It checks
flowtable hooks as matching interfaces are created, renamed and removed. The
installed firewall packet functional tests separately verify IPv4 and IPv6 offload.

Retain the published kernel source bundle alongside the matching ISO. Its upstream
archive contains Linux's license notices; the accompanying resolved configuration
and recipe describe how nVyR built that binary. See [third-party licensing](../../THIRD_PARTY.md)
for the other components' source-distribution requirements.

## Updating a development router

For a package-only update, copy the new `.deb` to the router. From its Linux shell,
with the file in the current directory:

```sh
sudo dpkg -i ./nvyr-router_0.1.0_all.deb
```

Read the installation result before proceeding. **`dpkg -i` does not download
missing dependencies.** For example, installing a package containing the DNS
operational commands does not itself install `python3-dnspython`.

When dependencies have changed, building and booting the new ISO provides the
complete dependency set. For a deliberate package-only update, supply the required
dependency packages too. APT can resolve dependencies only when suitable package
sources are configured; the built router image excludes build-time APT sources,
and stock Debian packages do not supply every pinned nVyR dependency version.

Long-running processes retain their loaded code after a package update. The nVyR
package reloads systemd unit definitions but does not automatically restart configd
or netlinkd. Restart the affected services deliberately during testing, or reboot.
Newly launched operational scripts use the installed files immediately.

For installing or upgrading a full router image, follow
[installation and image management](installation.md). A `.deb` update does not
create a new bootable image or update the ISO build timestamp.

## Router dependency versions

The repository's package declarations and locks are the source of truth:

- [`packaging/debian/control`](../../packaging/debian/control) declares dependencies
  required by the nVyR Debian package.
- [`images/router.list.chroot`](../../images/router.list.chroot) selects packages for
  the complete router image, including development and diagnostic tools.
- [`images/packages.lock`](../../images/packages.lock) pins downloaded Debian packages
  by version, architecture, URL and SHA-256 checksum, including nftables and Kea.
- [`images/frr-sources.lock`](../../images/frr-sources.lock) and
  [`build_tools/frr_packages.py`](../../build_tools/frr_packages.py) define the FRR build.
  Approved patches live in [`vendor/frr/`](../../vendor/frr).
- [`images/container-sources.lock`](../../images/container-sources.lock) and
  [`build_tools/container_packages.py`](../../build_tools/container_packages.py) define
  Podman, Netavark, Aardvark DNS and containers-common packaging.
- [`images/kernel-sources.lock`](../../images/kernel-sources.lock) and
  [`build_tools/kernel_packages.py`](../../build_tools/kernel_packages.py) define the
  LTS kernel source, Debian configuration baseline and package build.
- [`images/0100-router.hook.chroot`](../../images/0100-router.hook.chroot) applies image
  integration and checks installed dependency versions.

Add runtime dependencies to the package declaration and image list where needed.
When changing a pinned dependency, update its lock and any corresponding version
requirements/checks together, then rebuild and test the resulting image.

Downloaded packages are checked against their hashes and package metadata. Kernel,
FRR and container packages are cached in `/opt/nvyr-kernel-packages`,
`/opt/nvyr-frr-packages` and `/opt/nvyr-container-packages` inside the builder; their recipe and artifact hashes
are verified before ISO staging. Do not bypass those checks to get a build through.

These locks do not freeze every Debian userspace package. Updating the pinned
components is an explicit maintenance task; they do not automatically follow
upstream releases. Detailed FRR integration belongs in [frr.md](frr.md).

## Troubleshooting

### Builder reports missing tools or stale cached packages

Rebuild `nvyr-image-builder` with the command above, then retry. Updating project
files through the bind mount cannot install new builder dependencies.

### Download returns 404 or fails a checksum

Check the failed URL and its entry in `images/packages.lock` or the relevant source
lock. A genuine unavailable artifact needs a reviewed replacement and updated pin.
Do not remove checksum validation. A URL ending in `%0D` indicates a carriage
return in the input; restore the lock file's LF line endings.

### Operational-script packaging rejects a shebang

Operational Python scripts require `#!/usr/bin/env python3` followed by an LF line
ending. Check the file's first line and line endings. The repository's
`.gitattributes` declares LF for operational scripts and Linux deployment files.

### Docker fails before the build starts

Errors such as `failed to create new OS thread` or `failed to start shim` occur in
Docker's runtime, before the nVyR scripts execute. Check the Docker host's resource
and process limits and whether other containers are exhausting them. Changing
nVyR's package code will not resolve that startup failure.

### Keep a failed ISO build for inspection

Use a named container without `--rm` when reproducing the failure:

```sh
docker run --name nvyr-build-debug --privileged -v "$PWD:/workspace" nvyr-image-builder

docker logs nvyr-build-debug

docker cp nvyr-build-debug:/var/tmp ./dist/build-debug
```

Run the copy after the container exits. ISO staging lives under
`/var/tmp/nvyr-image.*`; package staging lives under `/var/tmp/nvyr-deb.*`. The copy
can be large. Once the evidence is no longer needed, remove the stopped container:

```sh
docker rm nvyr-build-debug
```

## Validate the result

A successful build confirms packaging and image-assembly checks passed. It does
not run the live smoketests or prove that the router boots and restores its saved
configuration correctly.

Boot the newly built image in a test VM, confirm login and service startup, then
use the relevant procedures:

- [Live smoketests](../../smoketests/README.md) — feature tests on the router.
- [Save/reboot acceptance tests](../../acceptance/README.md) — combined configuration
  application, saving, reboot and recovery checks.
- [Operational testing](operational-testing.md) — installed command behavior,
  permissions and empty/failure cases.
- [Installation verification](installation.md#verification) — installation,
  image upgrades and rollback.

## Image build identity

`show version` reads the image's `/usr/share/nvyr/build.json`. The builder records
the project version, optional `built_by` attribution and UTC assembly-start timestamp
before `lb build`; it does not generate a new timestamp on boot or package installation. This file travels
with the live filesystem and installed image.

Updating only the `.deb` does not replace the image's build attribution or date.
`show version` uses a headerless table and also displays the project copyright and
repository URL. `show license` prints the installed MIT license in full.

Source locks and package manifests are also retained under `/usr/share/nvyr/` for
inspection. Use these records to identify the image and dependency artifacts being
tested, rather than relying on a reused ISO filename.
