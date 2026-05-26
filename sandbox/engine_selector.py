import os
import logging
from .local_sandbox import run_sandbox as run_local
from .gvisor_runner import run_gvisor
from .kata_runner import run_kata
from .firecracker_runner import run_firecracker

logger = logging.getLogger("engine_selector")

class EngineSelector:
    def __init__(self):
        # Default to local dev wrapper if running outside K8s/Production
        self.mode = os.environ.get("SANDBOX_MODE", "local_dev").lower()
        logger.info(f"Initialized Sandbox Engine Selector in mode: {self.mode}")

    async def execute(self, job_id: str, local_path: str):
        logger.info(f"Routing job {job_id} to engine: {self.mode}")
        
        if self.mode == "gvisor":
            return await run_gvisor(job_id, local_path)
        elif self.mode == "kata":
            return await run_kata(job_id, local_path)
        elif self.mode == "firecracker":
            return await run_firecracker(job_id, local_path)
        elif self.mode == "local_dev":
            return await run_local(job_id, local_path)
        else:
            logger.error(f"Unknown sandbox mode: {self.mode}, falling back to local_dev.")
            return await run_local(job_id, local_path)

sandbox_engine = EngineSelector()
