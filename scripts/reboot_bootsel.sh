#!/bin/bash
set -e

echo "================================================================"
echo " Returning RP2040 to BOOTSEL Programming Mode"
echo "================================================================"

# Method 1: USB CDC 1200-baud touch
CDC_DEV=$(ls /dev/ttyACM* 2>/dev/null | head -n1 || true)
if [ -n "$CDC_DEV" ]; then
    echo "Sending 1200 bps touch signal to $CDC_DEV..."
    stty -F "$CDC_DEV" 1200 2>/dev/null || true
fi

# Method 2: CTAPHID Vendor Reboot packet via hidraw
python3 -c "
import os, glob

for dev_path in glob.glob('/dev/hidraw*'):
    try:
        fd = os.open(dev_path, os.O_RDWR)
        # Send CTAPHID_CMD_VENDOR_REBOOT (0xD1 / 0x51) with Broadcast CID
        packet = b'\x00' + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xD1, 0x00, 0x00]) + bytes(57)
        os.write(fd, packet)
        os.close(fd)
        print(f'Sent reboot packet to {dev_path}')
    except Exception:
        pass
" 2>/dev/null || true

# Wait for RPI-RP2 mount
echo "Waiting for BOOTSEL drive to mount..."
for i in {1..20}; do
    if mountpoint -q "/media/$USER/RPI-RP2" 2>/dev/null; then
        echo "Successfully returned to BOOTSEL mode!"
        echo "Mount point: /media/$USER/RPI-RP2"
        exit 0
    elif mountpoint -q "/run/media/$USER/RPI-RP2" 2>/dev/null; then
        echo "Successfully returned to BOOTSEL mode!"
        echo "Mount point: /run/media/$USER/RPI-RP2"
        exit 0
    fi
    sleep 0.5
done

echo "Check device. (You can also hold the BOOTSEL button for 2 seconds)."
