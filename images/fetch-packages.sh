#!/bin/sh
# Download reviewed, checksum-pinned packages into live-build's local repository.
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:?Usage: fetch-packages.sh DESTINATION [CACHE]}
cache=${2:-}
mkdir -p "$destination"
if [ -n "$cache" ]; then
    mkdir -p "$cache"
fi

while read -r package version architecture checksum url; do
    case "$package" in ''|'#'*) continue ;; esac

    filename="$destination/${url##*/}"
    downloaded=no
    if [ -n "$cache" ] && [ -f "$cache/$checksum" ] &&
        cp "$cache/$checksum" "$filename.part" &&
        printf '%s  %s\n' "$checksum" "$filename.part" | sha256sum --check --status; then
        printf 'Using cached %s %s (%s)\n' "$package" "$version" "$architecture"
    else
        printf 'Downloading %s %s (%s)\n' "$package" "$version" "$architecture"
        wget --https-only --timeout=45 --tries=3 --retry-on-http-error=408,429,500,502,503,504 \
            --no-verbose -O "$filename.part" "$url" || {
            status=$?
            printf 'Failed to download %s from %s (wget exit %s)\n' "$package" "$url" "$status" >&2
            exit "$status"
        }

        printf '%s  %s\n' "$checksum" "$filename.part" | sha256sum -c -
        downloaded=yes
    fi

    for field in Package Version Architecture; do
        case "$field" in
            Package) expected=$package ;;
            Version) expected=$version ;;
            Architecture) expected=$architecture ;;
        esac

        actual=$(dpkg-deb -f "$filename.part" "$field")
        if [ "$actual" != "$expected" ]; then
            printf '%s: %s mismatch: expected %s, got %s\n' "$filename" "$field" "$expected" "$actual" >&2
            exit 1
        fi
    done

    if [ -n "$cache" ] && [ "$downloaded" = yes ]; then
        # Publish atomically so simultaneous ISO builds only see complete packages.
        temporary=$(mktemp "$cache/.download.XXXXXXXX")
        cp "$filename.part" "$temporary"
        mv "$temporary" "$cache/$checksum"
    fi
    mv "$filename.part" "$filename"
done < "$directory/packages.lock"
