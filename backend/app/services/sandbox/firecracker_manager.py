import os
import time
import subprocess
import logging
import asyncio
import httpx
import uuid
from typing import Optional

logger = logging.getLogger("firecracker_manager")

class FirecrackerManager:
    def __init__(self, job_id: str, kernel_path: str, rootfs_path: str):
        self.job_id = job_id
        # Firecracker assigns CID 3 and up to guests.
        # We will use a random CID per VM, or just derive from uuid
        self.cid = 3 + (hash(job_id) % 10000)
        self.api_socket = f"/tmp/firecracker-{job_id}.socket"  # nosec B108
        self.kernel_path = kernel_path
        self.rootfs_path = rootfs_path
        self.process: Optional[subprocess.Popen] = None
        self.client = None

    def start_firecracker(self):
        """Spawn the firecracker process with the API socket"""
        if os.path.exists(self.api_socket):
            os.remove(self.api_socket)

        # Assuming `firecracker` is in PATH. If not, this would need an absolute path.
        cmd = ["firecracker", "--api-sock", self.api_socket]
        
        # Start firecracker in the background
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Wait for API socket to become available
        for _ in range(50):
            if os.path.exists(self.api_socket):
                break
            time.sleep(0.01)

        # Use an HTTPX client with unix domain socket transport
        transport = httpx.HTTPTransport(uds=self.api_socket)
        self.client = httpx.Client(transport=transport, base_url="http://localhost")

    def configure_vm(self):
        """Send configurations to Firecracker via REST API"""
        if not self.client:
            raise RuntimeError("Firecracker API client not initialized")

        # 1. Configure Boot Source (Kernel)
        res = self.client.put(
            "/boot-source",
            json={
                "kernel_image_path": self.kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            }
        )
        res.raise_for_status()

        # 2. Configure RootFS (Drive)
        res = self.client.put(
            "/drives/rootfs",
            json={
                "drive_id": "rootfs",
                "path_on_host": self.rootfs_path,
                "is_root_device": True,
                "is_read_only": False
            }
        )
        res.raise_for_status()

        # 3. Configure VSOCK (Communication)
        res = self.client.put(
            "/vsock",
            json={
                "vsock_id": "vsock0",
                "guest_cid": self.cid,
                "uds_path": f"/tmp/v.sock-{self.job_id}"  # nosec B108
            }
        )
        res.raise_for_status()

    def start_instance(self):
        """Start the configured microVM"""
        if not self.client:
            raise RuntimeError("Firecracker API client not initialized")

        res = self.client.put(
            "/actions",
            json={
                "action_type": "InstanceStart"
            }
        )
        res.raise_for_status()
        logger.info(f"Firecracker VM started for job {self.job_id}")

    def cleanup(self):
        """Kill the Firecracker process and clean up sockets"""
        if self.process:
            self.process.kill()
            self.process.wait()
            self.process = None

        if self.client:
            self.client.close()
            self.client = None

        if os.path.exists(self.api_socket):
            try:
                os.remove(self.api_socket)
            except Exception:
                pass

        vsock_path = f"/tmp/v.sock-{self.job_id}"  # nosec B108
        if os.path.exists(vsock_path):
            try:
                os.remove(vsock_path)
            except Exception:
                pass
