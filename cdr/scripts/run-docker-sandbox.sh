#!/usr/bin/env bash
# ==============================================================================
# DocShield CDR Engine - Docker Sandbox Execution Driver
# ==============================================================================

set -eo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: ./scripts/run-docker-sandbox.sh <input-file> <output-file>"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file not found: $INPUT"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ABS_INPUT="$(realpath "$INPUT")"
INPUT_FILENAME="$(basename "$ABS_INPUT")"

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
ABS_OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
OUTPUT_FILENAME="$(basename "$OUTPUT")"

IMAGE_NAME="docshield-cdr:latest"

# Build image if it doesn't exist
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building DocShield Docker sandbox image..."
    docker build -t "$IMAGE_NAME" "$PROJECT_ROOT"
fi

echo "============================================================"
echo " Executing DocShield CDR inside Hardened Docker Sandbox     "
echo "============================================================"
echo " Network    : NONE (Airgapped)"
echo " Filesystem : READ-ONLY rootfs"
echo " Input      : $ABS_INPUT (Read-Only Mount)"
echo " Output     : $ABS_OUTPUT_DIR/$OUTPUT_FILENAME"
echo " User       : 10001:10001 (Non-root)"
echo " Memory     : 1024MB Max"
echo " Caps       : ALL DROPPED"
echo "============================================================"

docker run --rm \
    --network none \
    --read-only \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --memory 1024m \
    --memory-swap 1024m \
    --cpus 2.0 \
    --pids-limit 150 \
    --tmpfs /tmp:rw,noexec,nosuid,size=256m \
    --tmpfs /sandbox/scratch:rw,noexec,nosuid,size=256m \
    -v "$ABS_INPUT:/sandbox/input/$INPUT_FILENAME:ro" \
    -v "$ABS_OUTPUT_DIR:/sandbox/output:rw" \
    -v "$PROJECT_ROOT/output/reports:/app/output/reports:rw" \
    -v "$PROJECT_ROOT/output/quarantine:/app/output/quarantine:rw" \
    "$IMAGE_NAME" \
    "/sandbox/input/$INPUT_FILENAME" "/sandbox/output/$OUTPUT_FILENAME"
