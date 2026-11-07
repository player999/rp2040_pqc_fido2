#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
UF2_FILE="$BUILD_DIR/rp2040_fido2_pqc.uf2"

echo "================================================================"
echo " Building and Flashing RP2040 PQC FIDO2 Authenticator"
echo "================================================================"

# Always build first to ensure latest binary
if [ -d "$BUILD_DIR" ]; then
    echo "Compiling latest firmware changes..."
    make -C "$BUILD_DIR" -j4
fi

if [ ! -f "$UF2_FILE" ]; then
    echo "Error: UF2 file not found at $UF2_FILE"
    echo "Please build the project first."
    exit 1
fi

# If RPI-RP2 is not already mounted, trigger automatic reboot to BOOTSEL
if ! mountpoint -q "/media/$USER/RPI-RP2" 2>/dev/null && ! mountpoint -q "/run/media/$USER/RPI-RP2" 2>/dev/null; then
    echo "Device running in FIDO2 mode. Triggering automatic reboot to BOOTSEL..."
    "$SCRIPT_DIR/reboot_bootsel.sh" || true
fi

# Wait for RPI-RP2 mount point
echo "Waiting for RP2040 USB Mass Storage (RPI-RP2)..."
MOUNT_DIR=""
for i in {1..20}; do
    if mountpoint -q "/media/$USER/RPI-RP2" 2>/dev/null; then
        MOUNT_DIR="/media/$USER/RPI-RP2"
        break
    elif mountpoint -q "/run/media/$USER/RPI-RP2" 2>/dev/null; then
        MOUNT_DIR="/run/media/$USER/RPI-RP2"
        break
    fi
    sleep 0.5
done

if [ -z "$MOUNT_DIR" ]; then
    echo "Error: RPI-RP2 mount directory not found."
    echo "Ensure RP2040 is plugged in and in BOOTSEL mode."
    exit 1
fi

sleep 0.5
echo "Found RPI-RP2 at: $MOUNT_DIR"
echo "Copying UF2 firmware: $(basename "$UF2_FILE") ($(stat -c%s "$UF2_FILE") bytes)..."
# RP2040 bootloader reboots instantly when the last block is written, so ignore disconnect error
cp "$UF2_FILE" "$MOUNT_DIR/" 2>/dev/null || true
sync 2>/dev/null || true
sleep 1.5

echo "Flashed successfully! RP2040 is rebooting into FIDO2 mode."
echo "================================================================"
