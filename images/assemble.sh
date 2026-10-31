#!/bin/sh
# Internal live-build stage, invoked by build_tools.image_build with resolved options.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

version=$1
output=$2
metadata=$3
debug=$4
stem="nvyr-$version-amd64"
if [ "$debug" = yes ]; then
    set -x
fi

if [ "$(id -u)" != 0 ]; then
    echo 'live-build requires root in an isolated Debian build environment' >&2
    exit 1
fi

set -- --version "$version" --output-dir "$output"
if [ "$debug" = yes ]; then
    set -- "$@" --debug
fi
sh "$repository/scripts/build-deb.sh" "$@"

# live-build needs native Linux mount/symlink/device behavior, not a /mnt/c workdir.
work=$(mktemp -d /var/tmp/nvyr-image.XXXXXX)
cd "$work"

kernel_release=$(python3 - "$repository/images/kernel-sources.lock" <<'PY'
import json
import sys

with open(sys.argv[1]) as stream:
    kernel = json.load(stream)
print(kernel['version'] + kernel['local_version'])
PY
)

# Firmware is selected explicitly in router.list.chroot; automatic inclusion
# would pull in every available firmware package from non-free-firmware.
lb config --mode debian --distribution trixie --architectures amd64 \
    --iso-volume 'nVyR' \
    --binary-images iso-hybrid --debian-installer false --archive-areas "main non-free-firmware" \
    --firmware-chroot false \
    --bootloaders 'grub-pc grub-efi' --uefi-secure-boot disable \
    --apt-recommends false --debootstrap-options '--variant=minbase' \
    --linux-packages linux-image --linux-flavours "$kernel_release" \
    --bootappend-live 'boot=live components noautologin nocomponents=user-setup,sudo hostname=nvyr locales=en_US.UTF-8 console=tty0 console=ttyS0,115200n8' \
    --bootappend-live-failsafe 'boot=live components noautologin nocomponents=user-setup,sudo hostname=nvyr locales=en_US.UTF-8 memtest noapic noapm nodma nomce nosmp nosplash vga=788 console=tty0 console=ttyS0,115200n8' \
    --bootappend-install 'console=tty0 console=ttyS0,115200n8'

mkdir -p config/package-lists config/packages.chroot config/hooks/live \
    config/includes.chroot/lib/live/config config/includes.chroot/usr/share/nvyr config/rootfs

# live-build temporarily restores APT sources for binary-stage tools. Exclude
# them from the immutable OS, while retaining APT for explicit administrator use.
printf '%s\n' 'etc/apt/sources.list' 'etc/apt/sources.list.d/*.list' 'etc/apt/sources.list.d/*.sources' > config/rootfs/excludes

# One text menu for BIOS/UEFI, serial and VGA; no graphical theme resets terminals.
cp -R "$repository/images/bootloaders" config/

sh "$repository/images/fetch-packages.sh" config/packages.chroot
python3 "$repository/build_tools/container_packages.py" \
    --cache /opt/nvyr-container-packages config/packages.chroot
python3 "$repository/build_tools/frr_packages.py" \
    --cache /opt/nvyr-frr-packages config/packages.chroot
python3 "$repository/build_tools/kernel_packages.py" \
    --cache /opt/nvyr-kernel-packages config/packages.chroot
install -m 0644 "$repository/images/packages.lock" config/includes.chroot/usr/share/nvyr/packages.lock
install -m 0644 "$repository/images/container-sources.lock" config/includes.chroot/usr/share/nvyr/container-sources.lock
install -m 0644 config/packages.chroot/container-packages.json config/includes.chroot/usr/share/nvyr/container-packages.json
install -m 0644 "$repository/images/frr-sources.lock" config/includes.chroot/usr/share/nvyr/frr-sources.lock
install -m 0644 config/packages.chroot/frr-packages.json config/includes.chroot/usr/share/nvyr/frr-packages.json
install -m 0644 "$repository/images/kernel-sources.lock" config/includes.chroot/usr/share/nvyr/kernel-sources.lock
install -m 0644 config/packages.chroot/kernel-packages.json config/includes.chroot/usr/share/nvyr/kernel-packages.json
cp "$repository/images/router.list.chroot" config/package-lists/router.list.chroot
cp "$output/nvyr-router_${version}_all.deb" config/packages.chroot/
install -m 0755 "$repository/images/0100-router.hook.chroot" config/hooks/live/0100-router.hook.chroot

# Use the identity captured before staging created any build artifacts.
install -m 0644 "$metadata" config/includes.chroot/usr/share/nvyr/build.json

# Binary hooks run after SquashFS, kernels and initrds, before checksums/ISO mastering.
cat > config/hooks/live/0990-manifest.hook.binary <<EOF
#!/bin/sh
set -eu
python3 "$repository/build_tools/image_manifest.py" --media . --metadata ../config/includes.chroot/usr/share/nvyr/build.json
EOF

lb build

# A failed publication must not leave an old checksum beside a replaced ISO.
rm -f "$output/$stem.iso.sha256"
install -m 0644 live-image-amd64.hybrid.iso "$output/$stem.iso"
install -m 0644 "$repository/images/packages.lock" "$output/$stem.packages.lock"
install -m 0644 config/packages.chroot/container-packages.json "$output/$stem.container-packages.json"
install -m 0644 config/packages.chroot/frr-packages.json "$output/$stem.frr-packages.json"
install -m 0644 config/packages.chroot/kernel-packages.json "$output/$stem.kernel-packages.json"
install -m 0644 config/packages.chroot/kernel-source.tar "$output/$stem.kernel-source.tar"

printf 'Created %s/%s.iso; validate boot and installation in a disposable VM.\n' "$output" "$stem"
