import asyncio
import logging
import datetime
import subprocess
import os
import sys
import json
import threading

logger = logging.getLogger("mock_sandbox")

def _run_mock_blocking(job_id: str, local_path: str):
    telemetry_events = []
    
    # We always use the python sandbox_wrapper.py for python files
    # For non-python files, we execute them safely with shell=False
    if local_path.endswith('.py'):
        wrapper_path = os.path.join(os.path.dirname(__file__), "..", "runtime_analysis", "sandbox_wrapper.py")
        cmd = [sys.executable, wrapper_path, job_id, local_path]
    elif local_path.endswith('.bat'):
        cmd = ["cmd.exe", "/c", local_path]
    elif local_path.endswith('.js'):
        cmd = ["node", local_path]
    else:
        cmd = [local_path]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False, # Ensure Command Injection is prevented
        )
    except Exception as e:
        logger.error(f"Failed to start mock sandbox process: {e}")
        return telemetry_events

    def _read_stream(stream):
        for raw_line in stream:
            try:
                line_str = raw_line.decode('utf-8', errors='replace').strip()
                if not line_str:
                    continue

                try:
                    data = json.loads(line_str)
                    if data.get("__telemetry__"):
                        event_payload = {
                            "type": data["event_type"],
                            "severity": data.get("severity", "info"),
                            "timestamp": data.get("timestamp") or (datetime.datetime.utcnow().isoformat() + "Z"),
                            "data": data["data"],
                        }
                        from app.services.runtime_analysis.telemetry_classifier import classify_event
                        classified = classify_event(event_payload)
                        if classified:
                            telemetry_events.append(classified)
                    else:
                        # Fallback for arbitrary JSON that isn't sentinel telemetry
                        telemetry_events.append({
                            "type": "EXECUTION_OUTPUT",
                            "severity": "info",
                            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                            "data": {"output": line_str}
                        })
                except json.JSONDecodeError:
                    # Capture raw stdout from uninstrumented scripts (like .bat or .js)
                    telemetry_events.append({
                        "type": "EXECUTION_OUTPUT",
                        "severity": "info",
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "data": {"output": line_str}
                    })
            except Exception as e:
                logger.error(f"Error reading stream: {e}")

    stdout_thread = threading.Thread(target=_read_stream, args=(process.stdout,))
    stderr_thread = threading.Thread(target=_read_stream, args=(process.stderr,))
    stdout_thread.start()
    stderr_thread.start()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning(f"Mock Sandbox execution for {job_id} timed out. Terminating.")
        process.kill()
        telemetry_events.append({
            "type": "EXECUTION_TIMEOUT",
            "severity": "high",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "data": {},
        })

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    return telemetry_events


async def run_mock_sandbox(job_id: str, local_path: str):
    """
    Simulates the execution of malware inside a Firecracker microVM.
    Used for local development when SANDBOX_MODE=mock.
    """
    logger.info(f"[MockSandbox] Booting simulated microVM for job {job_id}")
    await asyncio.sleep(0.5) # Simulate VM boot
    
    logger.info(f"[MockSandbox] Executing payload {local_path}")
    
    # Actually run the payload in an isolated process on the host
    telemetry_events = await asyncio.to_thread(_run_mock_blocking, job_id, local_path)
    
    logger.info(f"[MockSandbox] Destroying simulated microVM for job {job_id}")
    return telemetry_events
