import sys
import os
import json
import socket
import datetime
import subprocess

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
                    send_telemetry(job_id, "FILE_WRITE", {"path": file_path})
                    
    # Eval/Exec
    elif event == "compile":
        # Can indicate eval/exec of dynamic code
        pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python sandbox_wrapper.py <job_id> <target_script.py>")
        sys.exit(1)

    job_id = sys.argv[1]
    target_script = sys.argv[2]
    
    os.environ["SENTINEL_JOB_ID"] = job_id
    
    sys.addaudithook(audit_hook)
    
    send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})
    send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": f"python {target_script}"})
    
    try:
        # We use runpy to execute the target script in the same process space
        import runpy
        runpy.run_path(target_script, run_name="__main__")
    except Exception as e:
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
