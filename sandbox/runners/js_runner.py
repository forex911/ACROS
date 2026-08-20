"""
JavaScript Runner — Sandbox JS File Executor

Executes JavaScript files by delegating to Node.js with the
sandbox_wrapper.js instrumentation layer. Collects telemetry
from the Node process stdout in the standard ACROS JSON protocol.
"""

import sys
import os
import json
import subprocess
import datetime
import logging

logger = logging.getLogger("js_runner")

# Default timeout for JS execution
JS_TIMEOUT = 30  # seconds


def send_telemetry(job_id: str, event_type: str, data: dict):
    """Emit telemetry in the standard ACROS JSON protocol."""
    msg = {
        "__telemetry__": True,
        "job_id": job_id,
        "event_type": event_type,
        "data": data,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    print(json.dumps(msg), flush=True)


def run_js(job_id: str, file_path: str, timeout: int = JS_TIMEOUT) -> int:
    """
    Execute a JavaScript file inside the sandbox.

    Uses Node.js with an optional wrapper script for instrumentation.
    Collects telemetry from stdout and re-emits it.

    Args:
        job_id: Unique job identifier.
        file_path: Path to the .js file to execute.
        timeout: Max execution time in seconds.

    Returns:
        Exit code (0 = success).
    """
    if not os.path.exists(file_path):
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"File not found: {file_path}"})
        return 1

    # Check if Node.js is available
    node_bin = _find_node()
    if not node_bin:
        send_telemetry(job_id, "EXECUTION_ERROR", {
            "error": "Node.js not found in PATH. Cannot execute JavaScript files.",
        })
        return 1

    os.environ["AEGIS_JOB_ID"] = job_id
    os.environ["SENTINEL_JOB_ID"] = job_id

    send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})
    send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": f"node {os.path.basename(file_path)}"})

    # Look for the wrapper script
    wrapper_path = _find_wrapper()
    if wrapper_path:
        cmd = [node_bin, wrapper_path, job_id, file_path]
    else:
        cmd = [node_bin, file_path]

    # Build restricted environment
    safe_env = _build_safe_env(job_id)

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env,
            cwd=os.path.dirname(file_path) or ".",
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            send_telemetry(job_id, "EXECUTION_TIMEOUT", {
                "timeout_seconds": timeout,
            })
            return 124

        # Parse stdout for telemetry JSON lines
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("__telemetry__"):
                    # Re-emit telemetry from the Node process
                    send_telemetry(
                        job_id,
                        data.get("event_type", "UNKNOWN"),
                        data.get("data", {}),
                    )
                else:
                    send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": line[:500]})
            except json.JSONDecodeError:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": line[:500]})

        # Capture stderr
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        if stderr_text:
            send_telemetry(job_id, "EXECUTION_OUTPUT", {
                "output": stderr_text[:1000],
                "stream": "stderr",
            })

        return process.returncode or 0

    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
        return 1


def _find_node() -> str | None:
    """Find the Node.js binary in PATH."""
    import shutil
    return shutil.which("node") or shutil.which("nodejs")


def _find_wrapper() -> str | None:
    """Find the sandbox_wrapper.js if available."""
    # Check relative to this script
    runner_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(runner_dir, "..", "..", "backend", "app", "services",
                     "runtime_analysis", "sandbox_wrapper.js"),
        os.path.join(runner_dir, "sandbox_wrapper.js"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None


def _build_safe_env(job_id: str) -> dict:
    """Build a restricted environment for the Node.js process."""
    stripped_vars = {
        "MONGO_URI", "REDIS_URL", "JWT_SECRET", "SECRET_KEY",
        "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "NEO4J_URI", "NEO4J_PASSWORD", "API_KEY",
    }

    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "NODE_ENV": "sandbox",
        "AEGIS_JOB_ID": job_id,
        "SENTINEL_JOB_ID": job_id,
        "AEGIS_SANDBOX": "1",
    }

    # Add required system vars
    for var in ("SYSTEMROOT", "TEMP", "TMP", "HOME", "USER"):
        if var in os.environ:
            safe_env[var] = os.environ[var]

    return safe_env


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python js_runner.py <job_id> <target_script.js>")
        sys.exit(1)

    exit_code = run_js(sys.argv[1], sys.argv[2])
    sys.exit(exit_code)
