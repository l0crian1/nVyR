# builder-version: 0.1.7
FROM debian:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    live-build debootstrap xorriso squashfs-tools \
    grub-pc-bin grub-efi-amd64-bin mtools dosfstools ca-certificates dpkg-dev wget python3 python3-yaml \
    build-essential pkg-config libgpgme-dev libseccomp-dev libsystemd-dev libbtrfs-dev git go-md2man man-db \
    && apt-get clean

# Build the pinned container stack once per builder image, outside the Windows mount.
COPY build_tools/container_packages.py /opt/nvyr-build/build_tools/container_packages.py
COPY images/container-sources.lock /opt/nvyr-build/images/container-sources.lock
RUN python3 /opt/nvyr-build/build_tools/container_packages.py /opt/nvyr-container-packages

# Preserve FRR's Debian build options and cache our Lua-enabled routing packages.
COPY build_tools/frr_packages.py /opt/nvyr-build/build_tools/frr_packages.py
COPY images/frr-sources.lock /opt/nvyr-build/images/frr-sources.lock
COPY vendor/frr/reload-ordering.patch /opt/nvyr-build/vendor/frr/reload-ordering.patch
COPY vendor/frr/keychain-reload.patch /opt/nvyr-build/vendor/frr/keychain-reload.patch
COPY vendor/frr/ospf-reload.patch /opt/nvyr-build/vendor/frr/ospf-reload.patch
COPY vendor/frr/rip-reload.patch /opt/nvyr-build/vendor/frr/rip-reload.patch
COPY vendor/frr/rip-vrf-routemap.patch /opt/nvyr-build/vendor/frr/rip-vrf-routemap.patch
COPY vendor/frr/isis-reload.patch /opt/nvyr-build/vendor/frr/isis-reload.patch
COPY vendor/frr/ldp-reload.patch /opt/nvyr-build/vendor/frr/ldp-reload.patch
COPY vendor/frr/bgp-addpath.patch /opt/nvyr-build/vendor/frr/bgp-addpath.patch
RUN python3 /opt/nvyr-build/build_tools/frr_packages.py /opt/nvyr-frr-packages

# Build the reviewed LTS kernel once, rather than tracking Debian's kernel meta-package.
RUN apt-get update && apt-get install -y --no-install-recommends \
    flex bison libelf-dev libdw-dev libssl-dev bc rsync cpio kmod xz-utils zstd dwarves debhelper \
    && apt-get clean
COPY build_tools/kernel_packages.py /opt/nvyr-build/build_tools/kernel_packages.py
COPY images/kernel-sources.lock images/Dockerfile /opt/nvyr-build/images/
RUN python3 /opt/nvyr-build/build_tools/kernel_packages.py /opt/nvyr-kernel-packages

# Keep this small collector build after the routing and kernel package layers.
COPY build_tools/ulogd_packages.py /opt/nvyr-build/build_tools/ulogd_packages.py
COPY images/ulogd-sources.lock /opt/nvyr-build/images/ulogd-sources.lock
COPY vendor/ulogd/icmp-printflow.patch /opt/nvyr-build/vendor/ulogd/icmp-printflow.patch
RUN python3 /opt/nvyr-build/build_tools/ulogd_packages.py /opt/nvyr-ulogd-packages

WORKDIR /workspace

ENTRYPOINT ["/bin/sh", "/workspace/images/build.sh"]
