import sys
import os
import json
import socket
import datetime
import subprocess
import atexit
import hashlib

def send_telemetry(job_id, event_type, data):
    # Sends telemetry securely over a local socket to the backend telemetry router
    # For now, we will print it in a specific JSON format to stdout, and the parent will parse it.
    msg = {
        "__telemetry__": True,
        "job_id": job_id,
        "event_type": event_type,
        "data": data,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    print(json.dumps(msg), flush=True)

def instrument_socket(job_id):
    original_gethostbyname = socket.gethostbyname
    def monitored_gethostbyname(host):
        send_telemetry(job_id, "DNS_QUERY", {"domain": host})
        return original_gethostbyname(host)
    socket.gethostbyname = monitored_gethostbyname

    original_getaddrinfo = socket.getaddrinfo
    def monitored_getaddrinfo(host, port, *args, **kwargs):
        if host and isinstance(host, str):
            send_telemetry(job_id, "DNS_QUERY", {"domain": host})
        return original_getaddrinfo(host, port, *args, **kwargs)
    socket.getaddrinfo = monitored_getaddrinfo

    original_connect = socket.socket.connect
    def monitored_connect(self, address):
        if isinstance(address, tuple) and len(address) >= 2:
            ip, port = address[:2]
            send_telemetry(job_id, "SOCKET_CONNECT", {"dest_ip": ip, "dest_port": port, "protocol": "TCP"})
        elif isinstance(address, str):
            send_telemetry(job_id, "SOCKET_CONNECT", {"dest_ip": address, "dest_port": 0, "protocol": "UNIX"})
        return original_connect(self, address)
    socket.socket.connect = monitored_connect


WRITTEN_FILES = set()

def finalize_file_writes():
    job_id = os.environ.get("SENTINEL_JOB_ID", "unknown")
    for file_path in list(WRITTEN_FILES):
        if not os.path.exists(file_path):
            continue
        try:
            size = os.path.getsize(file_path)
            # Only hash files under 50 MB to prevent sandbox stalling
            sha256_hash = ""
            if size <= 50 * 1024 * 1024:
                sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                sha256_hash = sha256.hexdigest()
                
            send_telemetry(job_id, "FILE_CREATE", {
                "path": file_path,
                "size": size,
                "sha256": sha256_hash
            })
        except Exception:
            pass

def audit_hook(event, args):
    job_id = os.environ.get("SENTINEL_JOB_ID", "unknown")
    
    # Process spawning
    if event == "os.system":
        send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": args[0].decode('utf-8') if isinstance(args[0], bytes) else args[0]})
    elif event == "subprocess.Popen":
        try:
            executable = args[0]
            cmd_args = args[1] if len(args) > 1 else []
            if isinstance(cmd_args, list):
                cmd = " ".join(str(x) for x in cmd_args)
            elif isinstance(cmd_args, str):
                cmd = cmd_args
            else:
                cmd = str(cmd_args)
            send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": cmd})
        except Exception:
            pass
        
    # Networking
    elif event == "socket.connect":
        try:
            # args[1] is typically a tuple (ip, port)
            addr = args[1]
            if isinstance(addr, tuple) and len(addr) == 2:
                ip, port = addr
                send_telemetry(job_id, "NETWORK_CONNECT", {"dest_ip": ip, "dest_port": port, "protocol": "TCP"})
        except Exception:
            pass
            
    elif event == "urllib.Request":
        url = args[0]
        send_telemetry(job_id, "HTTP_REQUEST", {"url": url})
        
    # File I/O
    elif event == "open":
        file_path = args[0]
        mode = args[1] if len(args) > 1 else 'r'
        if isinstance(file_path, str):
            # Only log writes to suspicious or important locations, or just log all writes
            if 'w' in mode or 'a' in mode or '+' in mode:
                if not file_path.endswith('.pyc') and '__pycache__' not in file_path:
                    abs_path = os.path.abspath(file_path)
                    WRITTEN_FILES.add(abs_path)
                    send_telemetry(job_id, "FILE_WRITE", {"path": abs_path})

    # Registry operations (Windows winreg module)
    elif event == "winreg.OpenKey":
        try:
            key_path = str(args[1]) if len(args) > 1 else str(args[0])
            send_telemetry(job_id, "REGISTRY_CREATE", {"key": key_path, "operation": "OPEN"})
        except Exception:
            pass
    elif event == "winreg.SetValue" or event == "winreg.SetValueEx":
        try:
            key_path = str(args[0]) if args else "unknown"
            value_name = str(args[1]) if len(args) > 1 else ""
            value_data = str(args[3]) if len(args) > 3 else str(args[2]) if len(args) > 2 else ""
            send_telemetry(job_id, "REGISTRY_MODIFY", {
                "key": key_path,
                "value_name": value_name,
                "value_data": value_data[:200],
                "operation": "MODIFY",
            })
            # Detect persistence: Run keys
            key_lower = key_path.lower()
            if "currentversion\\run" in key_lower or "currentversion\\runonce" in key_lower:
                send_telemetry(job_id, "PERSISTENCE_EVENT", {
                    "mechanism": "registry_run_key",
                    "target": f"{key_path}\\{value_name}",
                })
        except Exception:
            pass
    elif event == "winreg.CreateKey" or event == "winreg.CreateKeyEx":
        try:
            key_path = str(args[1]) if len(args) > 1 else str(args[0])
            send_telemetry(job_id, "REGISTRY_CREATE", {"key": key_path, "operation": "CREATE"})
        except Exception:
            pass

    # Detect ctypes calls that may indicate memory injection
    elif event == "ctypes.dlsym" or event == "ctypes.LoadLibrary":
        try:
            target = str(args[0]) if args else ""
            injection_apis = {"virtualallocex", "writeprocessmemory", "createremotethread",
                              "ntwritevirtualmemory", "rtlcreateuserthread", "setthreadcontext"}
            if any(api in target.lower() for api in injection_apis):
                send_telemetry(job_id, "MEMORY_INJECTION", {
                    "source_pid": os.getpid(),
                    "target_pid": 0,
                    "api_call": target,
                })
        except Exception:
            pass
                    
    # Eval/Exec
    elif event == "exec":
        send_telemetry(job_id, "EXECUTION", {"type": "exec", "target": str(args[0])[:100]})
    elif event == "compile":
        source = args[0]
        if isinstance(source, bytes):
            source = source.decode('utf-8', errors='ignore')
        elif not isinstance(source, str):
            source = str(source)
        if len(source) > 0 and source != "<module>":
            send_telemetry(job_id, "EXECUTION", {"type": "compile", "target": source[:100]})

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python sandbox_wrapper.py <job_id> <target_script.py>")
        sys.exit(1)

    job_id = sys.argv[1]
    target_script = sys.argv[2]
    
    os.environ["SENTINEL_JOB_ID"] = job_id
    
    sys.addaudithook(audit_hook)
    instrument_socket(job_id)
    atexit.register(finalize_file_writes)
    
    send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})
    send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": f"python {target_script}"})
    
    try:
        # We use runpy to execute the target script in the same process space
        import runpy
        runpy.run_path(target_script, run_name="__main__")
    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
