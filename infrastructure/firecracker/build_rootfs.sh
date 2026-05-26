#!/bin/bash
# Script to build a minimal Alpine Linux rootfs for Firecracker MicroVM
# Ensure you are running this on a Linux host with root privileges

set -euo pipefail

ROOTFS_IMG="alpine-rootfs.ext4"
MNT_DIR="/tmp/my-rootfs"

echo "[*] Creating an empty ext4 image of 200MB..."
dd if=/dev/zero of=$ROOTFS_IMG bs=1M count=200
mkfs.ext4 $ROOTFS_IMG

echo "[*] Mounting the image..."
mkdir -p $MNT_DIR
sudo mount $ROOTFS_IMG $MNT_DIR

echo "[*] Bootstrapping Alpine Linux..."
# We use a static docker alpine container to copy its rootfs
docker pull alpine:latest
CONTAINER_ID=$(docker create alpine:latest)
docker export $CONTAINER_ID | sudo tar xf - -C $MNT_DIR
docker rm $CONTAINER_ID

echo "[*] Installing required packages (Python3, bash)..."
# We need to run chroot to install packages inside the rootfs
sudo cp /etc/resolv.conf $MNT_DIR/etc/
sudo chroot $MNT_DIR /bin/sh -c "apk update && apk add --no-cache python3 bash"

echo "[*] Configuring auto-startup for sandbox agent..."
sudo bash -c "cat > $MNT_DIR/etc/inittab" <<EOF
::sysinit:/sbin/rc sysinit
::sysinit:/sbin/rc boot
::wait:/sbin/rc default
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/rc shutdown
::restart:/sbin/init
ttyS0::respawn:/bin/sh
EOF

echo "[*] Unmounting..."
sudo umount $MNT_DIR
rm -rf $MNT_DIR

echo "[+] Done. Rootfs image created at $ROOTFS_IMG"
