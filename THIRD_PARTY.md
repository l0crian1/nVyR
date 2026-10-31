# Third-party licensing

nVyR's original source code, schemas, templates, tests, build scripts and
documentation are licensed under the [MIT License](LICENSE), except where a
file or this notice identifies different terms. The MIT license does not
relicense third-party code, packages, container images or data.

## FRR reload patch

`vendor/frr/reload-ordering.patch` contains changes to and context from
FRRouting's `tools/frr-reload.py` at tag `frr-10.7.1`:

- Upstream copyright: Copyright (C) 2014 Cumulus Networks, Inc.
- nVyR changes: Copyright (c) 2026 L0crian and nVyR contributors.
- License: **GPL-2.0-or-later**.
- Source: https://github.com/FRRouting/frr/blob/frr-10.7.1/tools/frr-reload.py
- License text: [vendor/frr/COPYING](vendor/frr/COPYING).
- Changes and build provenance: [vendor/frr/README.md](vendor/frr/README.md).

The patch and modified upstream program remain under GPL-2.0-or-later.
The patch is included in the Git repository and Python source distribution.
The modified program is installed by the separately built `frr-pythontools`
package, not by the nVyR Python wheel or `nvyr-router` Debian package.

Python wheels declare `MIT` in their SPDX license metadata. Source archives
declare `MIT AND GPL-2.0-or-later` because they also contain the FRR patch;
this describes the combined archive, not a change to the license of nVyR's
original files.

## Separately installed dependencies

### Linux kernel

The image builder compiles the upstream Linux version pinned in
`images/kernel-sources.lock`, using a configuration extracted from the pinned
Debian amd64 package. Linux retains its upstream licenses (primarily
GPL-2.0-only, with the syscall exception and per-file terms documented in its
`COPYING` and `LICENSES/` files). It is a separate Debian package; nVyR's MIT
license does not apply to the kernel.

Each ISO build publishes a matching `.kernel-source.tar` with the upstream source
archive, baseline and resolved configurations, lock and build recipe. Distribute
that bundle with the corresponding binary release and preserve the upstream
notices. Kernel build details are in [docs/dev/debian.md](docs/dev/debian.md#kernel-maintenance).

### Other dependencies

Python libraries and system programs retain their own licenses and copyright
notices. Dependency declarations are in `pyproject.toml` and
`packaging/debian/control`; image selections and pinned inputs are in `images/`.
Those declarations are not a complete license inventory of an assembled ISO.

In particular, pyroute2 offers GPL-2.0-or-later or Apache-2.0; nVyR uses the
Apache-2.0 option. pyudev remains under LGPL-2.1-or-later, including the applicable
notice, source and library-replacement requirements. Other dependencies have
their own terms. Installing or invoking a dependency does not replace its
license with nVyR's MIT license.

- [pyroute2 license](https://github.com/svinota/pyroute2/blob/master/LICENSE)
- [pyudev license](https://github.com/pyudev/pyudev/blob/master/COPYING)

For installed Debian packages, consult `/usr/share/doc/<package>/copyright`
and any accompanying notices. Preserve these when distributing an image.
Custom-built packages must also retain the notices required by their bundled
dependencies, including vendored Go and Rust code.

Container images pulled by a user are separate works with their own licenses.
The nVyR MIT license does not grant rights to redistribute those images.

## DB-IP GeoIP data

IP Geolocation by [DB-IP](https://db-ip.com).

DB-IP Country Lite is licensed under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
The database is downloaded at runtime rather than included in this repository.
nVyR selects country ranges and converts them to firewall set members; these
derived data retain the applicable attribution requirements. Preserve DB-IP
attribution, the license link and identification of changes when redistributing
the data or derived data.

See the [DB-IP download and licensing page](https://db-ip.com/db/download/ip-to-country-lite)
and [nVyR GeoIP documentation](docs/users/firewall-geoip.md).

## Distributing packages and ISOs

Publishing the source repository does not turn the complete router image into
an MIT-only distribution. Before publishing binary releases:

1. Retain copyright notices, license texts and required notices for the exact
   package versions and bundled dependencies in that release.
2. Provide corresponding source through a method permitted by each applicable
   license. For modified FRR, include the matching upstream source, nVyR patch,
   and build/installation scripts. Apply the same process to other components
   requiring source availability, even when nVyR has not modified them.
3. Keep the release's source material, package versions and build inputs
   together. Upstream links and hashes are useful provenance, but are not by
   themselves a complete corresponding-source delivery mechanism.
4. Include GeoIP attribution if redistributing downloaded or derived data.

The current image build produces binary artifacts and version manifests; it
does not assemble a complete corresponding-source release or audit every
bundled dependency's notices. Complete that release work before publishing
ISOs as license-complete binary releases.
