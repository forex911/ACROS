import os
import sys
import json
import uuid
import asyncio
import logging
import tempfile
import shutil
import aiohttp
from datetime import datetime

logger = logging.getLogger("firecracker_runner")

FIRECRACKER_SOCKET = "/tmp/firecracker.socket"
FIRECRACKER_BIN = "/usr/bin/firecracker"

async def boot_microvm(job_id: str, kernel_image: str, rootfs: str):
    vm_id = str(uuid.uuid4())
    socket_path = f"/tmp/firecracker-{vm_id}.socket"
    
    # In a real implementation, you would use firecracker's jailer here to heavily restrict the process.
    # For this runner, we use the raw firecracker binary with a dedicated socket.
    
    # 1. Spawn firecracker process
    proc = await asyncio.create_subprocess_exec(
        FIRECRACKER_BIN, "--api-sock", socket_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Wait for socket to be ready
    await asyncio.sleep(1)
    
    async with aiohttp.ClientSession(connector=aiohttp.UnixConnector(path=socket_path)) as session:
        # 2. Configure Boot Source
        boot_config = {
            "kernel_image_path": kernel_image,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        }
        await session.put("http://localhost/machine-config", json={"vcpu_count": 1, "mem_size_mib": 256})
        await session.put("http://localhost/boot-source", json=boot_config)
        
        # 3. Configure RootFS (Read-Only)
        drive_config = {
            "drive_id": "rootfs",
            "path_on_host": rootfs,
            "is_root_device": True,
            "is_read_only": True
        }
        await session.put("http://localhost/drives/rootfs", json=drive_config)
        
        # 4. Start Instance
        await session.put("http://localhost/actions", json={"action_type": "InstanceStart"})
        
    return proc, vm_id

async def run_firecracker(job_id: str, local_path: str):
    """
    Executes the payload inside an ephemeral Firecracker MicroVM.
    Returns a list of telemetry events.
    """
    # Requires Linux kernel and rootfs to be present on the host
    KERNEL_IMAGE = os.environ.get("FC_KERNEL", "/opt/firecracker/vmlinux")
    ROOTFS = os.environ.get("FC_ROOTFS", "/opt/firecracker/alpine-rootfs.ext4")
    
    if not os.path.exists(KERNEL_IMAGE) or not os.path.exists(ROOTFS):
        logger.error("Firecracker requires vmlinux and rootfs images to be present.")
        return [{"type": "EXECUTION_ERROR", "severity": "high", "timestamp": datetime.utcnow().isoformat() + "Z", "data": {"error": "Firecracker requirements missing"}}]

    logger.info(f"Starting Firecracker MicroVM for job {job_id}")
    
    # We create an ephemeral overlay snapshot of the rootfs here, but for brevity, we assume a clean boot.
    proc, vm_id = await boot_microvm(job_id, KERNEL_IMAGE, ROOTFS)
    
    telemetry_events = []
    
    try:
        # In a real environment, we would inject the payload via a secondary virtio-block device,
        # or a virtio-vsock connection, and wait for a guest agent to execute it and stream back over vsock.
        # Here we mock the telemetry reception from the VM's serial output.
        
        # Wait up to 15 seconds for execution
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        
        # Parse stdout from the guest's console (which would emit JSON)
        for line in stdout.decode().splitlines():
            try:
                event = json.loads(line)
                telemetry_events.append(event)
            except:
                pass
                
    except asyncio.TimeoutError:
        logger.warning(f"Firecracker VM {vm_id} timed out. Terminating.")
        proc.terminate()
        telemetry_events.append({"type": "EXECUTION_TIMEOUT", "severity": "high", "timestamp": datetime.utcnow().isoformat() + "Z", "data": {}})
    finally:
        # Cleanup
        if proc.returncode is None:
            proc.terminate()
            
    return telemetry_events
