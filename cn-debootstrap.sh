#!/bin/bash
set -e

if ! command -v debootstrap >/dev/null 2>&1; then
    echo "E: debootstrap is not installed" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "E: This script must be run as root" >&2
    exit 1
fi

if [[ -z "${1:-}" ]]; then
    echo "E: Must specify container directory as first argument" >&2
    exit 1
fi
MACHINE_DIR="$1"

if [[ ! "$MACHINE_DIR" =~ ^/[a-z][a-z0-9_/.-]+$ ]]; then
    echo "E: Machine name may only contain 'a-z0-9_/.-'" >&2
    exit 1
elif [ -e "$MACHINE_DIR" ]; then
    echo "E: '$MACHINE_DIR' already exists. Aborting" >&2
    exit 1
fi

if [[ -z "${2:-}" ]]; then
    echo "E: Must specify base distribution as second argument" >&2
    exit 1
fi

if [[ ! "$2" =~ ^(debian|ubuntu):[a-z]{1,32}$ ]]; then
    echo "E: Base distribution must be 'debian:codename' or 'ubuntu:codename'" >&2
    exit 1
fi

# Split distro:codename
IFS=':' read -r DISTRO CODENAME <<< "$2"
BASE="$CODENAME"

# Since we use --as-pid2, exclude systemd,udev,dbus. Use
# --include=locales,tzdata since it is needed in newer releases for
# /etc/localtime
echo "I: Bootstrapping '$DISTRO:$BASE' container in '$MACHINE_DIR'"

# Set components and suites based on distro
if [[ "$DISTRO" == "ubuntu" ]]; then
    COMPONENTS="--components=main,universe"
else
    COMPONENTS=""
fi

# will add -security and -updates in setup-container.sh
exec debootstrap \
    --variant=minbase \
    $COMPONENTS \
    --exclude=systemd,udev,dbus \
    --include=locales,tzdata \
    "$BASE" \
    "$MACHINE_DIR"
