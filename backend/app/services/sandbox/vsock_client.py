import socket
import json
import logging
import asyncio

logger = logging.getLogger("vsock_client")

class VsockClient:
    def __init__(self, cid: int, port: int):
        self.cid = cid
        self.port = port
        self.sock = None

    def connect(self, timeout=5.0):
        """Connect to the guest over VSOCK"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((self.cid, self.port))
        self.sock.settimeout(None)

    def send_payload(self, job_id: str, filename: str, content: str):
        """Send the analysis payload to the guest agent"""
        if not self.sock:
            raise ConnectionError("Not connected to VSOCK")
            
        msg = {
            "job_id": job_id,
            "filename": filename,
            "content": content
        }
        self.sock.sendall((json.dumps(msg) + "\n").encode('utf-8'))

    async def stream_telemetry(self):
        """Asynchronous generator to yield telemetry events from the guest"""
        if not self.sock:
            raise ConnectionError("Not connected to VSOCK")

        buffer = ""
        loop = asyncio.get_running_loop()
        
        while True:
            # Non-blocking read via asyncio
            data = await loop.sock_recv(self.sock, 4096)
            if not data:
                break
                
            buffer += data.decode('utf-8')
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        yield event
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to decode VSOCK message: {e}")

    def close(self):
        """Close the VSOCK connection"""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
