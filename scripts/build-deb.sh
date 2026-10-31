#!/bin/sh
# Run from any directory on Linux. Staging must use native Linux permissions.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output="$repository/dist"
version=''
debug=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--output-dir)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '%s requires a value\n' "$1" >&2
                exit 1
            fi
            if [ "$1" = --version ]; then version=$2; else output=$2; fi
            shift 2
            ;;
        --version=*|--output-dir=*)
            value=${1#*=}
            if [ -z "$value" ]; then
                printf '%s requires a value\n' "${1%%=*}" >&2
                exit 1
            fi
            case "$1" in
                --version=*) version=$value ;;
                --output-dir=*) output=$value ;;
            esac
            shift
            ;;
        --debug) debug=yes; shift ;;
        --help|-h)
            echo 'Usage: scripts/build-deb.sh [--version VERSION] [--output-dir PATH] [--debug]'
            exit 0
            ;;
        *) printf 'Unknown build option: %s\n' "$1" >&2; exit 1 ;;
    esac
done

if [ "$debug" = yes ]; then
    set -x
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo 'Building nVyR schemas requires python3. Install Python 3.11+ in the build environment.' >&2
    echo 'For the ISO container, rebuild it: docker build -t nvyr-image-builder -f images/Dockerfile .' >&2
    exit 1
fi

if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    echo 'Building nVyR schemas requires PyYAML. Install python3-yaml in the Debian build environment.' >&2
    echo 'For the ISO container, rebuild it: docker build -t nvyr-image-builder -f images/Dockerfile .' >&2
    exit 1
fi

# Resolve the same default and validate overrides before creating build outputs.
set -- --print-version
if [ -n "$version" ]; then
    set -- "$@" --version "$version"
fi
version=$(python3 "$repository/build_tools/build_metadata.py" "$@")
mkdir -p -- "$output"
output=$(CDPATH= cd -- "$output" && pwd)
stage=$(mktemp -d /var/tmp/nvyr-deb.XXXXXX)
chmod 0755 "$stage"

install -d "$stage/DEBIAN" "$stage/usr/lib/python3/dist-packages/nvyr" \
    "$stage/usr/bin" "$stage/usr/lib/systemd/system" "$stage/usr/share/doc/nvyr-router"

install -m 0644 "$repository/packaging/debian/control" "$stage/DEBIAN/control"
python3 "$repository/build_tools/build_metadata.py" --control "$stage/DEBIAN/control" --version "$version"
install -m 0755 "$repository/packaging/debian/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$repository/packaging/debian/prerm" "$stage/DEBIAN/prerm"

find "$repository/src/nvyr" -type f \( -name '*.py' -o -name '*.json' -o -name '*.j2' \) | while IFS= read -r source; do
    relative=${source#"$repository/src/"}
    install -D -m 0644 "$source" "$stage/usr/lib/python3/dist-packages/$relative"
done

# Ship live tests with the router; building/installing the package never runs them.
for suite in smoketests functionaltests; do
    find "$repository/$suite" -type f \( -name '*.py' -o -name '*.md' -o -name '*.ini' -o -name '*.conf' \) | while IFS= read -r source; do
        relative=${source#"$repository/$suite/"}
        install -D -m 0644 "$source" "$stage/usr/lib/nvyr/$suite/$relative"
    done
done

# The external controller invokes these phases explicitly; never run during builds.
find "$repository/acceptance" -type f \( -name '*.py' -o -name '*.md' -o -name '*.set' \) | while IFS= read -r source; do
    relative=${source#"$repository/acceptance/"}
    install -D -m 0644 "$source" "$stage/usr/lib/nvyr/acceptance/$relative"
done

python3 "$repository/build_tools/kernel_settings.py" --check
python3 "$repository/build_tools/op_scripts.py" \
    --source "$stage/usr/lib/python3/dist-packages/nvyr/op_scripts" --bin "$stage/usr/bin"
python3 "$repository/build_tools/schema_builder.py" --output "$stage/usr/lib/python3/dist-packages/nvyr/schemas"

printf '%s\n' '#!/usr/bin/python3' 'from nvyr.daemon import main' 'main()' > "$stage/usr/bin/configd"
printf '%s\n' '#!/usr/bin/python3' 'from nvyr.cli import main' 'main()' > "$stage/usr/bin/nvyr"
chmod 0755 "$stage/usr/bin/configd" "$stage/usr/bin/nvyr"

# Isolated Python prevents SSH/user environment or home modules from replacing
# the restricted login shell before it has performed its role checks.
printf '%s\n' '#!/usr/bin/python3 -I' 'from nvyr.login import main' 'main()' > "$stage/usr/bin/nvyr-login"
chmod 0755 "$stage/usr/bin/nvyr-login"
for entry in 'nvyr-session nvyr.helpers.session_runtime' 'nvyr-developer-boot nvyr.helpers.developer_access'; do
    set -- $entry
    printf '%s\n' '#!/usr/bin/python3 -I' "from $2 import main" 'main()' > "$stage/usr/bin/$1"
    chmod 0755 "$stage/usr/bin/$1"
done
install -D -m 0644 "$repository/build_tools/session_images.py" "$stage/usr/lib/nvyr/build-session-images.py"
install -D -m 0644 "$repository/packaging/session-containers.conf" "$stage/usr/share/nvyr/session-containers.conf"
for unit in nvyr-developer-access.service nvyr-session-images.service nvyr-session-reap.service nvyr-session-reap.timer; do
    install -m 0644 "$repository/packaging/$unit" "$stage/usr/lib/systemd/system/$unit"
done
install -D -m 0440 "$repository/packaging/nvyr-sudoers" "$stage/etc/sudoers.d/nvyr"
install -D -m 0644 "$repository/packaging/nvyr-live.conf" "$stage/etc/live/config.conf.d/90-nvyr.conf"

printf '%s\n' '#!/usr/bin/python3' 'from nvyr.interface_naming import main' 'main()' > "$stage/usr/bin/nvyr-interface-naming"
chmod 0755 "$stage/usr/bin/nvyr-interface-naming"
install -m 0644 "$repository/packaging/nvyr-interface-naming.service" "$stage/usr/lib/systemd/system/nvyr-interface-naming.service"
install -D -m 0644 "$repository/packaging/70-nvyr-ethernet.rules" "$stage/usr/lib/udev/rules.d/70-nvyr-ethernet.rules"
install -D -m 0644 "$repository/packaging/10-nvyr-ethernet.link" "$stage/usr/lib/systemd/network/10-nvyr-ethernet.link"

for entry in 'nvyr-kernel-settings nvyr.helpers.kernel_settings main' 'nvyr-netlinkd nvyr.netlink_daemon main' 'nvyr-dhcp4 nvyr.helpers.dhcp client_main' 'nvyr-dhcp4-hook nvyr.helpers.dhcp hook_main' 'nvyr-kea nvyr.helpers.kea main' 'nvyr-dhcp-hosts nvyr.helpers.dhcp_hosts main' 'nvyr-logging nvyr.helpers.logging_runtime main'; do
    set -- $entry
    printf '%s\n' '#!/usr/bin/python3' "from $2 import $3" "$3()" > "$stage/usr/bin/$1"
    chmod 0755 "$stage/usr/bin/$1"
done

for unit in nvyr-logging-prepare.service nvyr-nflog@.service nvyr-logrotate.service nvyr-logrotate.timer; do
    install -m 0644 "$repository/packaging/$unit" "$stage/usr/lib/systemd/system/$unit"
done
install -D -m 0644 "$repository/packaging/20-nvyr-rsyslog.conf" "$stage/usr/lib/systemd/system/rsyslog.service.d/20-nvyr.conf"
install -D -m 0644 "$repository/packaging/20-nvyr-journal.conf" "$stage/usr/lib/systemd/journald.conf.d/20-nvyr.conf"

install -m 0644 "$repository/packaging/nvyr-netlinkd.service" "$stage/usr/lib/systemd/system/nvyr-netlinkd.service"
install -m 0644 "$repository/packaging/nvyr-resolver-init.service" "$stage/usr/lib/systemd/system/nvyr-resolver-init.service"
install -m 0644 "$repository/packaging/nvyr-dhcp4@.service" "$stage/usr/lib/systemd/system/nvyr-dhcp4@.service"
install -m 0644 "$repository/packaging/nvyr-configd.service" "$stage/usr/lib/systemd/system/nvyr-configd.service"
install -m 0644 "$repository/packaging/nvyr-geoip-update.service" "$stage/usr/lib/systemd/system/nvyr-geoip-update.service"
install -m 0644 "$repository/packaging/nvyr-geoip-update.timer" "$stage/usr/lib/systemd/system/nvyr-geoip-update.timer"
install -m 0644 "$repository/packaging/nvyr-conntrack.service" "$stage/usr/lib/systemd/system/nvyr-conntrack.service"
install -D -m 0644 "$repository/packaging/nvyr-conntrack-helpers.conf" "$stage/usr/lib/modprobe.d/nvyr-conntrack-helpers.conf"

install -D -m 0644 "$repository/packaging/20-nvyr-serial.conf" "$stage/usr/lib/systemd/system/serial-getty@.service.d/20-nvyr.conf"

for unit in getty@.service serial-getty@.service; do
    install -D -m 0644 "$repository/packaging/30-nvyr-login.conf" "$stage/usr/lib/systemd/system/$unit.d/30-nvyr-login.conf"
done

install -D -m 0644 "$repository/packaging/20-nvyr-console.cfg" "$stage/etc/default/grub.d/20-nvyr-console.cfg"
install -D -m 0755 "$repository/packaging/initramfs/hooks/nvyr" "$stage/usr/share/initramfs-tools/hooks/nvyr"
install -D -m 0755 "$repository/packaging/initramfs/scripts/nvyr" "$stage/usr/share/initramfs-tools/scripts/nvyr"
printf '%s\n' '/etc/default/grub.d/20-nvyr-console.cfg' > "$stage/DEBIAN/conffiles"

install -m 0644 "$repository/packaging/nvyr-ssh@.service" "$stage/usr/lib/systemd/system/nvyr-ssh@.service"
install -m 0644 "$repository/packaging/nvyr-ntp.service" "$stage/usr/lib/systemd/system/nvyr-ntp.service"
printf '%s\n' '#!/usr/bin/python3' 'from nvyr.helpers.ntp import main' 'main()' > "$stage/usr/bin/nvyr-ntp"
chmod 0755 "$stage/usr/bin/nvyr-ntp"
install -m 0644 "$repository/packaging/nvyr-kea@.service" "$stage/usr/lib/systemd/system/nvyr-kea@.service"
install -m 0644 "$repository/packaging/nvyr-dhcp-hosts.service" "$stage/usr/lib/systemd/system/nvyr-dhcp-hosts.service"
install -m 0644 "$repository/packaging/nvyr-dhcp-hosts.timer" "$stage/usr/lib/systemd/system/nvyr-dhcp-hosts.timer"
install -D -m 0755 "$repository/packaging/nvyr-dhcp-hosts-hook" "$stage/usr/share/kea/scripts/nvyr-dhcp-hosts"
install -D -m 0644 "$repository/packaging/nvyr-network.conf" "$stage/usr/lib/tmpfiles.d/nvyr-network.conf"
install -D -m 0644 "$repository/packaging/containers.conf" "$stage/usr/share/containers/containers.conf.d/90-nvyr.conf"
install -D -m 0644 "$repository/packaging/containers-storage.conf" "$stage/etc/containers/storage.conf"

install -D -m 0644 "$repository/packaging/router.nft" "$stage/usr/lib/nvyr/router.nft"
install -D -m 0644 "$repository/packaging/20-nvyr-nftables.conf" "$stage/usr/lib/systemd/system/nftables.service.d/20-nvyr.conf"
install -D -m 0644 "$repository/packaging/50-nvyr-router.conf" "$stage/usr/lib/sysctl.d/50-nvyr-router.conf"

install -m 0644 "$repository/README.md" "$stage/usr/share/doc/nvyr-router/README.md"
install -m 0644 "$repository/packaging/debian/copyright" "$stage/usr/share/doc/nvyr-router/copyright"
install -m 0644 "$repository/LICENSE" "$stage/usr/share/doc/nvyr-router/LICENSE"
install -m 0644 "$repository/THIRD_PARTY.md" "$stage/usr/share/doc/nvyr-router/THIRD_PARTY.md"
install -D -m 0644 "$repository/vendor/frr/COPYING" "$stage/usr/share/doc/nvyr-router/vendor/frr/COPYING"
install -m 0644 "$repository/vendor/frr/README.md" "$stage/usr/share/doc/nvyr-router/vendor/frr/README.md"
install -m 0644 "$repository/docs/users/firewall-geoip.md" "$stage/usr/share/doc/nvyr-router/firewall-geoip.md"
install -m 0644 "$repository/docs/users/ntp.md" "$stage/usr/share/doc/nvyr-router/ntp.md"

dpkg-deb --root-owner-group --build "$stage" "$output/nvyr-router_${version}_all.deb"
