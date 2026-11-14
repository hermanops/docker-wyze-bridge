#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: verify-sha256.sh FILE SHA256" >&2
    exit 1
fi

printf '%s  %s\n' "$2" "$1" | sha256sum -c -
