import sys
import os
import json
import socket
import datetime
import tempfile
import shutil

def send_telemetry(job_id, event_type, severity, data):
    msg = {
        "__telemetry__": True,
        "job_id": job_id,
        "event_type": event_type,
        "severity": severity,
        "data": data,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    print(json.dumps(msg), flush=True)

def audit_hook(event, args):
    job_id = os.environ.get("AEGIS_JOB_ID") or os.environ.get("SENTINEL_JOB_ID", "unknown")
    
    try:
        # Process spawning
        if event == "os.system":
            send_telemetry(job_id, "PROCESS_CREATE", "high", {"cmdline": args[0].decode('utf-8') if isinstance(args[0], bytes) else args[0]})
        elif event == "subprocess.Popen":
            executable = args[0]
            cmd_args = args[1] if len(args) > 1 else []
            if isinstance(cmd_args, list):
                cmd = " ".join(str(x) for x in cmd_args)
            elif isinstance(cmd_args, str):
                cmd = cmd_args
            else:
                cmd = str(cmd_args)
            send_telemetry(job_id, "PROCESS_CREATE", "high", {"cmdline": cmd})
            
        # Networking
        elif event == "socket.connect":
            addr = args[1]
            if isinstance(addr, tuple) and len(addr) == 2:
                ip, port = addr
                send_telemetry(job_id, "SOCKET_CONNECT", "medium", {"dest_ip": ip, "dest_port": port, "protocol": "TCP"})
        elif event == "socket.getaddrinfo":
            host = args[0]
            if isinstance(host, str) and not host.startswith("127.") and not host == "localhost":
                send_telemetry(job_id, "DNS_QUERY", "medium", {"query": host})
                
        # File I/O
        elif event == "open":
            file_path = args[0]
            mode = args[1] if len(args) > 1 else 'r'
            if isinstance(file_path, str):
                if 'w' in mode or 'a' in mode or '+' in mode:
                    if not file_path.endswith('.pyc') and '__pycache__' not in file_path:
                        send_telemetry(job_id, "FILE_WRITE", "medium", {"path": file_path})
                        
        # Code execution
        elif event == "compile":
            pass # Keep it less noisy for now unless it's a specific dynamic execution
            
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python local_sandbox.py <job_id> <target_script.py>")
        sys.exit(1)

    job_id = sys.argv[1]
    original_target_script = sys.argv[2]
    
    os.environ["AEGIS_JOB_ID"] = job_id
    os.environ["SENTINEL_JOB_ID"] = job_id
    
    # ── ISOLATION SETUP ──
    # Create a temporary directory for execution
    temp_dir = tempfile.mkdtemp(prefix="aegis_sandbox_")
    
    try:
        # Copy script into the isolated directory
        target_name = os.path.basename(original_target_script)
        isolated_script = os.path.join(temp_dir, target_name)
        shutil.copy(original_target_script, isolated_script)
        
        # Restrict environment by changing CWD and fixing sys.path
        os.chdir(temp_dir)
        sys.path = [temp_dir] + [p for p in sys.path if "acros-ai" not in p and "sentinel-ai" not in p]
        
        sys.addaudithook(audit_hook)
        
        send_telemetry(job_id, "STATUS_CHANGE", "info", {"status": "analyzing"})
        send_telemetry(job_id, "EXECUTION", "high", {"cmdline": f"python {target_name}"})
        
        try:
            import runpy
            runpy.run_path(isolated_script, run_name="__main__")
        except Exception as e:
            send_telemetry(job_id, "EXECUTION_ERROR", "high", {"error": str(e)})
            
    finally:
        # Cleanup isolated environment
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass
