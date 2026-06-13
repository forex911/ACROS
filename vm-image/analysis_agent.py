import socket
import sys
import os
import json
import datetime
import subprocess

# VSOCK Constants
VMADDR_CID_HOST = 2
PORT = 5000

def get_vsock_connection():
    """Connect to the host orchestrator over VSOCK"""
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((VMADDR_CID_HOST, PORT))
    return s

class TelemetrySender:
    def __init__(self):
        self.sock = get_vsock_connection()
        self.job_id = "unknown"

    def send(self, event_type, data):
        msg = {
            "__telemetry__": True,
            "job_id": self.job_id,
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
        try:
            self.sock.sendall((json.dumps(msg) + "\n").encode('utf-8'))
        except Exception:
            pass

sender = None

def instrument_socket(job_id):
    original_gethostbyname = socket.gethostbyname
    def monitored_gethostbyname(host):
        if sender:
            sender.send("DNS_QUERY", {"domain": host})
        return original_gethostbyname(host)
    socket.gethostbyname = monitored_gethostbyname

    original_getaddrinfo = socket.getaddrinfo
    def monitored_getaddrinfo(host, port, *args, **kwargs):
        if host and isinstance(host, str) and sender:
            sender.send("DNS_QUERY", {"domain": host})
        return original_getaddrinfo(host, port, *args, **kwargs)
    socket.getaddrinfo = monitored_getaddrinfo

    original_connect = socket.socket.connect
    def monitored_connect(self, address):
        if isinstance(address, tuple) and len(address) >= 2 and sender:
            ip, port = address[:2]
            # Ignore connections to the VSOCK host
            if not (str(ip) == "127.0.0.1" and port == PORT):
                sender.send("SOCKET_CONNECT", {"dest_ip": ip, "dest_port": port, "protocol": "TCP"})
        return original_connect(self, address)
    socket.socket.connect = monitored_connect

def audit_hook(event, args):
    if not sender: return
    
    if event == "os.system":
        sender.send("PROCESS_CREATE", {"cmdline": args[0].decode('utf-8') if isinstance(args[0], bytes) else args[0]})
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
            sender.send("PROCESS_CREATE", {"cmdline": cmd})
        except Exception:
            pass
    elif event == "socket.connect":
        try:
            addr = args[1]
            if isinstance(addr, tuple) and len(addr) == 2:
                ip, port = addr
                sender.send("SOCKET_CONNECT", {"dest_ip": ip, "dest_port": port, "protocol": "TCP"})
        except Exception:
            pass
    elif event == "urllib.Request":
        url = args[0]
        sender.send("HTTP_REQUEST", {"url": url})
    elif event == "open":
        file_path = args[0]
        mode = args[1] if len(args) > 1 else 'r'
        if isinstance(file_path, str) and ('w' in mode or 'a' in mode or '+' in mode):
            if not file_path.endswith('.pyc') and '__pycache__' not in file_path:
                sender.send("FILE_WRITE", {"path": file_path})

def main():
    global sender
    try:
        sender = TelemetrySender()
    except Exception as e:
        print(f"Failed to connect to host VSOCK: {e}")
        sys.exit(1)

    # 1. Receive Payload Information
    try:
        # Expected init message: {"job_id": "...", "filename": "...", "content": "base64..."}
        init_data_raw = sender.sock.recv(1024 * 1024 * 10).decode('utf-8')
        init_data = json.loads(init_data_raw.strip())
        
        job_id = init_data["job_id"]
        filename = init_data["filename"]
        content_b64 = init_data["content"]
        
        sender.job_id = job_id
        
        # Write payload
        import base64
        target_path = f"/sandbox/{filename}"
        with open(target_path, "wb") as f:
            f.write(base64.b64decode(content_b64))
            
    except Exception as e:
        if sender: sender.send("EXECUTION_ERROR", {"error": f"Failed to receive payload: {str(e)}"})
        sys.exit(1)

    # 2. Setup telemetry instrumentation
    sys.addaudithook(audit_hook)
    instrument_socket(job_id)
    
    sender.send("STATUS_CHANGE", {"status": "analyzing"})
    sender.send("PROCESS_CREATE", {"cmdline": f"python {target_path}"})
    
    # 3. Execute
    try:
        if target_path.endswith(".py"):
            import runpy
            runpy.run_path(target_path, run_name="__main__")
        else:
            # Future support for PE/ELF binaries inside linux guest
            subprocess.run([target_path], check=True)
    except Exception as e:
        sender.send("EXECUTION_ERROR", {"error": str(e)})

    # Cleanup socket
    sender.sock.close()

if __name__ == "__main__":
    main()
