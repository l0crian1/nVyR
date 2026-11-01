# Run the GitHub CI checks locally

The [Build and test workflow](../../.github/workflows/test.yml) uses the same
Python 3.13 Linux container and [script](../../scripts/test-ci.sh) as local runs.
Docker must be running Linux containers. No router or privileged container is
required.

From the repository root, build the test image:

```sh
docker build -t nvyr-test -f tests/container/Dockerfile .
```

Run the checks from PowerShell:

```powershell
docker run --rm -v "${PWD}:/workspace" nvyr-test
```

The same command works in a Linux shell. The container copies the current
checkout, including uncommitted changes, onto its temporary Linux filesystem.
This avoids Windows file-sharing overhead and lets tests use Linux permissions.
Build outputs, experiment data, virtual environments and test caches are excluded
from that copy. Reports and packages are copied back even when a check fails;
generated source changes stay inside the disposable container.

Source changes do not require rebuilding the image. Rebuild when
`pyproject.toml` dependencies, the test Dockerfile or its constraints change.
The image is separate from `nvyr-image-builder`; it does not compile the kernel,
FRR or Podman.

## Checks and results

The script stops on the first failed stage:

1. Check that generated schemas match their sources.
2. Install the current checkout using the image's cached dependencies.
3. Run `tests/` with two pytest workers, distributing complete files to workers.
4. Build the Python source distribution and wheel.
5. Build the Debian package.

Pytest prints the 30 slowest test durations and writes its report to
`test-results/framework.xml`. Packages are written to `dist/`. Both directories
are ignored by Git. A successful run exits with status zero and prints
`All CI checks passed`.

These are the CI regression and packaging checks. Native integration tests with
explicit opt-in flags remain skipped; this command does not run the router's
`smoketests/`, `functionaltests/` or reboot acceptance suite.

Dependency downloads happen during the image build. The test script uses those
installed dependencies for editable installation and distribution builds.
`tests/container/constraints.txt` selects pyroute2 0.7.7 to match the router's
Debian trixie package; newer releases changed its Netlink codec API. Review this
constraint when upgrading the router dependency.
