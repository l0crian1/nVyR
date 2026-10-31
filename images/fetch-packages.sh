#!/bin/sh
# Download reviewed, checksum-pinned packages into live-build's local repository.
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:?Usage: fetch-packages.sh DESTINATION}
mkdir -p "$destination"

while read -r package version architecture checksum url; do
    case "$package" in ''|'#'*) continue ;; esac

    filename="$destination/${url##*/}"
    printf 'Downloading %s %s (%s)\n' "$package" "$version" "$architecture"

    if wget --https-only --timeout=30 --tries=3 --no-verbose -O "$filename.part" "$url"; then
        :
    else
        status=$?
        printf 'Failed to download %s from %s (wget exit %s)\n' "$package" "$url" "$status" >&2
        exit "$status"
    fi

    printf '%s  %s\n' "$checksum" "$filename.part" | sha256sum -c -

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

    mv "$filename.part" "$filename"
done < "$directory/packages.lock"
