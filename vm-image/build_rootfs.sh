#!/bin/bash
set -e

echo "[*] Building Alpine Docker image..."
docker build -t sentinel-alpine .

echo "[*] Extracting root filesystem from container..."
CONTAINER_ID=$(docker create sentinel-alpine)
mkdir -p rootfs
docker export $CONTAINER_ID | tar -xC rootfs
docker rm $CONTAINER_ID

echo "[*] Creating blank ext4 filesystem..."
# 500MB ext4 image
dd if=/dev/zero of=rootfs.ext4 bs=1M count=500
mkfs.ext4 rootfs.ext4

echo "[*] Mounting and copying files..."
mkdir -p mnt
# This requires sudo privileges on Linux
sudo mount rootfs.ext4 mnt/
sudo cp -r rootfs/* mnt/
sudo umount mnt/

# Clean up
rm -rf rootfs mnt

echo "[*] Downloading compatible Firecracker kernel (vmlinux)..."
if [ ! -f "vmlinux" ]; then
    # Download a precompiled uncompressed kernel (example URL, Firecracker provides these)
    # Using 5.10 kernel as a stable base
    curl -fsSL -o vmlinux https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
fi

echo "[+] Build complete. rootfs.ext4 and vmlinux are ready."
