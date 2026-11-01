FROM python:3.13-slim-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    dpkg-dev git iproute2 iputils-ping less procps rsync traceroute tzdata util-linux \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies without baking a copy of the source into the test image.
COPY pyproject.toml /opt/nvyr-test/pyproject.toml
COPY tests/container/constraints.txt /opt/nvyr-test/constraints.txt
RUN python - <<'PY'
import subprocess
import tomllib

with open('/opt/nvyr-test/pyproject.toml', 'rb') as source:
    metadata = tomllib.load(source)

dependencies = [
    *metadata['build-system']['requires'],
    *metadata['project']['dependencies'],
    *metadata['project']['optional-dependencies']['test'],
    'build',
    'wheel',
]
subprocess.check_call([
    'python', '-m', 'pip', 'install', '--no-cache-dir',
    '--constraint', '/opt/nvyr-test/constraints.txt', *dependencies,
])
PY

WORKDIR /workspace
ENTRYPOINT ["sh", "/workspace/scripts/test-container.sh"]
