import os
import shutil
import tempfile
import logging
from typing import Optional

import docker

logger = logging.getLogger("sandbox.docker_runner")


def run_in_sandbox(image: str, command: str, artifact_path: Optional[str] = None,
                   seccomp_profile: Optional[str] = None, timeout: int = 60,
                   memory: str = "512m", cpus: float = 0.5):
    """Run a command inside a short-lived container with hardened defaults.

    Note: This helper is a convenience wrapper. For executing untrusted binaries
    in production prefer microVMs (Firecracker) or gVisor.
    """
    client = docker.from_env()

    binds = {}
    workdir = "/work"
    if artifact_path:
        # mount artifact read-only into container
        binds[os.path.abspath(artifact_path)] = {
            'bind': f"{workdir}/artifact",
            'mode': 'ro'
        }

    security_opts = []
    if seccomp_profile:
        security_opts.append(f"seccomp={seccomp_profile}")

    host_config = client.api.create_host_config(
        binds=binds,
        security_opt=security_opts or None,
        network_mode='none',
        cap_drop=['ALL'],
        read_only_rootfs=True,
        pids_limit=256,
        mem_limit=memory,
    )

    container = None
    try:
        logger.info("Creating container %s", image)
        container = client.api.create_container(
            image=image,
            command=command,
            host_config=host_config,
            working_dir=workdir,
        )
        cid = container.get('Id')
        client.api.start(cid)
        exit_code = client.api.wait(cid, timeout=timeout)
        logs = client.api.logs(cid, stdout=True, stderr=True).decode('utf-8', errors='ignore')
        return {'exit_code': exit_code.get('StatusCode', -1), 'logs': logs}
    finally:
        if container:
            try:
                client.api.remove_container(container.get('Id'), force=True)
            except Exception:
                pass
