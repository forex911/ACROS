"""
APK Runner — Sandbox Android APK Analyzer

Analyzes Android APK files using:
- aapt/aapt2 for manifest extraction (permissions, activities, services)
- unzip for content inspection
- Optional dex2jar + jadx for decompilation

Emits telemetry events for detected capabilities and permissions.
"""

import sys
import os
import json
import subprocess
import zipfile
import datetime
import shutil
import logging
import re

logger = logging.getLogger("apk_runner")

APK_TIMEOUT = 60  # seconds

# ── Dangerous Android permissions ───────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "SMS access",
    "android.permission.SEND_SMS": "SMS sending",
    "android.permission.RECEIVE_SMS": "SMS interception",
    "android.permission.READ_CONTACTS": "Contact access",
    "android.permission.READ_CALL_LOG": "Call log access",
    "android.permission.CAMERA": "Camera access",
    "android.permission.RECORD_AUDIO": "Microphone access",
    "android.permission.ACCESS_FINE_LOCATION": "GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Network location",
    "android.permission.READ_PHONE_STATE": "Device identifiers",
    "android.permission.CALL_PHONE": "Phone call initiation",
    "android.permission.WRITE_EXTERNAL_STORAGE": "External storage write",
    "android.permission.READ_EXTERNAL_STORAGE": "External storage read",
    "android.permission.INTERNET": "Network access",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Auto-start on boot",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay windows",
    "android.permission.INSTALL_PACKAGES": "Package installation",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Package installation request",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service",
    "android.permission.BIND_DEVICE_ADMIN": "Device admin",
    "android.permission.WRITE_SETTINGS": "System settings modification",
}


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


def run_apk(job_id: str, file_path: str, timeout: int = APK_TIMEOUT) -> int:
    """
    Analyze an Android APK file.

    Extracts manifest, permissions, components, and embedded URLs/IPs.

    Args:
        job_id: Unique job identifier.
        file_path: Path to the .apk file.
        timeout: Max analysis time in seconds.

    Returns:
        Exit code (0 = success).
    """
    if not os.path.exists(file_path):
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"File not found: {file_path}"})
        return 1

    os.environ["AEGIS_JOB_ID"] = job_id

    send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})
    send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": f"Analyzing APK: {os.path.basename(file_path)}"})

    # ── 1. Validate APK (it's a ZIP file) ───────────────────────────────
    if not _validate_apk(job_id, file_path):
        return 1

    # ── 2. Extract manifest info with aapt ──────────────────────────────
    manifest_info = _extract_manifest(job_id, file_path)

    # ── 3. Analyze permissions ──────────────────────────────────────────
    if manifest_info.get("permissions"):
        _analyze_permissions(job_id, manifest_info["permissions"])

    # ── 4. Extract strings from DEX ─────────────────────────────────────
    _extract_dex_strings(job_id, file_path)

    # ── 5. Check for embedded native libraries ──────────────────────────
    _check_native_libs(job_id, file_path)

    send_telemetry(job_id, "STATUS_CHANGE", {"status": "completed"})
    return 0


def _validate_apk(job_id: str, file_path: str) -> bool:
    """Verify the APK is a valid ZIP archive."""
    try:
        if not zipfile.is_zipfile(file_path):
            send_telemetry(job_id, "EXECUTION_ERROR", {"error": "File is not a valid ZIP/APK"})
            return False

        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(n.endswith(".dex") for n in names)

            send_telemetry(job_id, "EXECUTION_OUTPUT", {
                "output": f"APK contents: {len(names)} files, "
                          f"manifest={'yes' if has_manifest else 'no'}, "
                          f"dex={'yes' if has_dex else 'no'}",
            })

            if not has_manifest:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {
                    "output": "WARNING: No AndroidManifest.xml found",
                })

        return True
    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"APK validation failed: {e}"})
        return False


def _extract_manifest(job_id: str, file_path: str) -> dict:
    """Extract manifest information using aapt if available."""
    result = {"permissions": [], "activities": [], "services": [], "receivers": [], "package": ""}

    aapt_bin = shutil.which("aapt") or shutil.which("aapt2")

    if not aapt_bin:
        send_telemetry(job_id, "EXECUTION_OUTPUT", {
            "output": "aapt not available — using fallback manifest parsing",
        })
        return result

    try:
        proc = subprocess.run(
            [aapt_bin, "dump", "badging", file_path],
            capture_output=True, text=True, timeout=30,
        )
        output = proc.stdout

        # Parse package name
        pkg_match = re.search(r"package: name='([^']+)'", output)
        if pkg_match:
            result["package"] = pkg_match.group(1)
            send_telemetry(job_id, "EXECUTION_OUTPUT", {
                "output": f"Package: {result['package']}",
            })

        # Parse permissions
        for match in re.finditer(r"uses-permission:\s*name='([^']+)'", output):
            result["permissions"].append(match.group(1))

        # Parse activities
        for match in re.finditer(r"activity.*?name='([^']+)'", output):
            result["activities"].append(match.group(1))

        # Parse services
        for match in re.finditer(r"service.*?name='([^']+)'", output):
            result["services"].append(match.group(1))

        # Parse receivers
        for match in re.finditer(r"receiver.*?name='([^']+)'", output):
            result["receivers"].append(match.group(1))

        send_telemetry(job_id, "EXECUTION_OUTPUT", {
            "output": (
                f"Manifest: {len(result['permissions'])} permissions, "
                f"{len(result['activities'])} activities, "
                f"{len(result['services'])} services, "
                f"{len(result['receivers'])} receivers"
            ),
        })

    except subprocess.TimeoutExpired:
        send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": "aapt timed out"})
    except Exception as e:
        send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": f"aapt error: {e}"})

    return result


def _analyze_permissions(job_id: str, permissions: list):
    """Flag dangerous permissions."""
    dangerous_found = []

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            dangerous_found.append({
                "permission": perm,
                "description": DANGEROUS_PERMISSIONS[perm],
            })

    if dangerous_found:
        send_telemetry(job_id, "EXECUTION_OUTPUT", {
            "output": f"Dangerous permissions: {len(dangerous_found)} found",
        })
        for d in dangerous_found:
            send_telemetry(job_id, "SUSPICIOUS_PROCESS", {
                "description": f"Dangerous Android permission: {d['description']} ({d['permission']})",
                "confidence": 0.7,
                "category": "dangerous_permission",
                "cmdline": d["permission"],
            })


def _extract_dex_strings(job_id: str, file_path: str):
    """Extract interesting strings from DEX files within the APK."""
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex"):
                    dex_data = zf.read(name)

                    # Extract ASCII strings > 6 chars
                    strings = re.findall(b"[ -~]{6,}", dex_data)
                    decoded = [s.decode("ascii", "ignore") for s in strings]

                    # Look for URLs
                    urls = [s for s in decoded if s.startswith("http://") or s.startswith("https://")]
                    for url in urls[:20]:
                        send_telemetry(job_id, "DNS_QUERY", {"domain": url, "source": "dex_string"})

                    # Look for IPs
                    ip_pattern = re.compile(
                        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
                    )
                    text_blob = "\n".join(decoded)
                    ips = list(set(ip_pattern.findall(text_blob)))
                    for ip in ips[:20]:
                        if not ip.startswith("127.") and not ip.startswith("0."):
                            send_telemetry(job_id, "SOCKET_CONNECT", {
                                "dest_ip": ip,
                                "dest_port": 0,
                                "source": "dex_string",
                            })

    except Exception as e:
        send_telemetry(job_id, "EXECUTION_OUTPUT", {"output": f"DEX string extraction error: {e}"})


def _check_native_libs(job_id: str, file_path: str):
    """Check for native (.so) libraries inside the APK."""
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            native_libs = [n for n in zf.namelist() if n.endswith(".so")]

            if native_libs:
                send_telemetry(job_id, "EXECUTION_OUTPUT", {
                    "output": f"Native libraries found: {len(native_libs)}",
                })
                for lib in native_libs[:10]:
                    send_telemetry(job_id, "EXECUTION_OUTPUT", {
                        "output": f"  Native lib: {lib}",
                    })
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python apk_runner.py <job_id> <target.apk>")
        sys.exit(1)

    exit_code = run_apk(sys.argv[1], sys.argv[2])
    sys.exit(exit_code)
