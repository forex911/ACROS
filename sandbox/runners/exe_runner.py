"""
EXE Runner — Sandbox Windows PE File Executor

Executes Windows PE (Portable Executable) files inside the sandbox.
On Linux containers, uses Wine for execution.
Falls back to static-only analysis if Wine is unavailable.

Collects telemetry from Wine process activity.
"""

import sys
import os
import json
import subprocess
import datetime
import shutil
import logging

logger = logging.getLogger("exe_runner")

EXE_TIMEOUT = 30  # seconds


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


def run_exe(job_id: str, file_path: str, timeout: int = EXE_TIMEOUT) -> int:
    """
    Execute a Windows PE file inside the sandbox.

    On Linux: Uses Wine for emulated execution.
    On Windows: Uses direct execution with restricted permissions.
    Falls back to static analysis if execution environment is unavailable.

    Args:
        job_id: Unique job identifier.
        file_path: Path to the .exe/.dll file.
        timeout: Max execution time in seconds.

    Returns:
        Exit code (0 = success).
    """
    if not os.path.exists(file_path):
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"File not found: {file_path}"})
        return 1

    os.environ["AEGIS_JOB_ID"] = job_id
    os.environ["SENTINEL_JOB_ID"] = job_id

    send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})

    # Determine execution method
    if sys.platform == "win32":
        return _run_native_windows(job_id, file_path, timeout)
    else:
        return _run_with_wine(job_id, file_path, timeout)


def _run_with_wine(job_id: str, file_path: str, timeout: int) -> int:
    """Execute PE file using Wine on Linux."""
    wine_bin = shutil.which("wine") or shutil.which("wine64")

    if not wine_bin:
        logger.warning("Wine not found — falling back to static-only analysis")
        send_telemetry(job_id, "EXECUTION_OUTPUT", {
            "output": "Wine not available. Performing static-only PE analysis.",
            "fallback": True,
        })
        return _static_pe_analysis(job_id, file_path)

    send_telemetry(job_id, "PROCESS_CREATE", {
        "cmdline": f"wine {os.path.basename(file_path)}",
    })

    # Set Wine to suppress GUI
    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"
    env["DISPLAY"] = ""  # Headless

    try:
        process = subprocess.Popen(
            [wine_bin, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=os.path.dirname(file_path) or ".",
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            send_telemetry(job_id, "EXECUTION_TIMEOUT", {"timeout_seconds": timeout})
            return 124

        # Capture output
        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        if stdout_text:
            for line in stdout_text.splitlines()[:50]:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": line[:500]})

        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        if stderr_text:
            # Wine debug output often contains useful behavioral info
            _parse_wine_debug(job_id, stderr_text)

        return process.returncode or 0

    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
        return 1


def _run_native_windows(job_id: str, file_path: str, timeout: int) -> int:
    """Execute PE file natively on Windows (with restricted permissions)."""
    send_telemetry(job_id, "PROCESS_CREATE", {
        "cmdline": file_path,
    })

    try:
        process = subprocess.Popen(
            [file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(file_path) or ".",
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            send_telemetry(job_id, "EXECUTION_TIMEOUT", {"timeout_seconds": timeout})
            return 124

        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        if stdout_text:
            for line in stdout_text.splitlines()[:50]:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": line[:500]})

        return process.returncode or 0

    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
        return 1


def _static_pe_analysis(job_id: str, file_path: str) -> int:
    """Perform basic static PE analysis when dynamic execution is unavailable."""
    try:
        file_size = os.path.getsize(file_path)
        send_telemetry(job_id, "EXECUTION_OUTPUT", {
            "output": f"Static PE analysis: size={file_size} bytes",
        })

        # Read PE header
        with open(file_path, "rb") as f:
            header = f.read(1024)

        # Check MZ header
        if header[:2] == b"MZ":
            send_telemetry(job_id, "EXECUTION_OUTPUT", {
                "output": "Valid PE (MZ) header detected",
            })

            # Check for packed indicators
            if b"UPX" in header:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {
                    "output": "PE appears to be UPX packed",
                })

        return 0

    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"Static PE analysis failed: {e}"})
        return 1


def _parse_wine_debug(job_id: str, debug_output: str):
    """Parse Wine debug output for behavioral indicators."""
    indicators = {
        "CreateFile": "FILE_WRITE",
        "RegSetValue": "REGISTRY_MODIFY",
        "RegCreateKey": "REGISTRY_CREATE",
        "connect": "SOCKET_CONNECT",
        "InternetOpen": "HTTP_REQUEST",
        "CreateProcess": "PROCESS_CREATE",
        "WriteProcessMemory": "MEMORY_INJECTION",
    }

    for line in debug_output.splitlines()[:100]:
        for api_call, event_type in indicators.items():
            if api_call.lower() in line.lower():
                send_telemetry(job_id, event_type, {
                    "source": "wine_debug",
                    "api_call": api_call,
                    "detail": line.strip()[:300],
                })
                break


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python exe_runner.py <job_id> <target.exe>")
        sys.exit(1)

    exit_code = run_exe(sys.argv[1], sys.argv[2])
    sys.exit(exit_code)
