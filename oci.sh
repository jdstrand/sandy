#!/bin/bash
set -e

if ! command -v skopeo >/dev/null 2>&1; then
    echo "E: skopeo is not installed" >&2
    exit 1
fi

if ! command -v umoci >/dev/null 2>&1; then
    echo "E: umoci is not installed" >&2
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

if [[ -z "${2:-}" ]]; then
    echo "E: Must specify base image as second argument" >&2
    exit 1
fi

if [[ ! "$2" =~ ^[a-z][a-z0-9._:-]{0,127}$ ]]; then
    echo "E: Base image must be valid Docker image name (1-128 chars, start with lowercase letter)" >&2
    exit 1
fi
BASE_IMAGE="$2"

if [[ ! "$MACHINE_DIR" =~ ^/[a-z][a-z0-9_/.-]+$ ]]; then
    echo "E: Machine name may only contain 'a-z0-9_/.-'" >&2
    exit 1
elif [ -e "$MACHINE_DIR" ]; then
    echo "E: '$MACHINE_DIR' already exists. Aborting" >&2
    exit 1
fi

# Create temporary directory for OCI operations
TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT HUP INT QUIT TERM

OCI_IMAGE="$TMPDIR/$BASE_IMAGE"
BUNDLE_DIR="$TMPDIR/bundle"

# Copy image from registry to local OCI directory
echo "I: Pulling '$BASE_IMAGE'"
skopeo copy docker://"$BASE_IMAGE" oci:"$OCI_IMAGE":latest

# Create bundle from OCI image
echo "I: Unpacking '$BASE_IMAGE' to '$BUNDLE_DIR'"
umoci unpack --image "$OCI_IMAGE":latest "$BUNDLE_DIR"

# Move the rootfs to the machine directory
echo "I: Moving '$BUNDLE_DIR/rootfs' to '$MACHINE_DIR'"
mv "$BUNDLE_DIR/rootfs" "$MACHINE_DIR"

echo "I: Successfully created '$BASE_IMAGE' container in '$MACHINE_DIR'"
