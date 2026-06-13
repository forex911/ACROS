# WebSocket Events Reference

Sentinel-AI streams live sandbox telemetry to connected clients via WebSockets, enabling SOC analysts to watch malware execute in real-time directly from the dashboard.

---

## Architecture

The streaming architecture is built on **Redis PubSub**:

```
┌──────────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────┐
│   Sandbox    │────►│  Redis   │────►│   FastAPI     │────►│ Frontend │
│   Worker     │     │  PubSub  │     │  WebSocket    │     │  Client  │
│              │     │          │     │  Endpoint     │     │          │
└──────────────┘     └──────────┘     └──────────────┘     └──────────┘
   Publishes to       Channel:          Subscribes &         Renders in
   stdout → Redis    job_updates:       proxies to           terminal UI
                     {job_id}           WebSocket
```

1. When a sandbox job starts, the backend creates a Redis channel named `job_updates:{job_id}`.
2. The sandbox worker publishes JSON events to this channel as OS-level actions are intercepted.
3. The FastAPI WebSocket endpoint subscribes to this channel and pipes raw JSON to connected clients.
4. The frontend `useWebSocket.ts` hook buffers events using `requestAnimationFrame` to prevent UI freezing during telemetry bursts.

---

## Connection

### Endpoint

```
ws://<backend-url>/ws/jobs/{job_id}/telemetry
```

### JavaScript Client Example

```javascript
const jobId = "a8f3c2d1-e456-4b89-9a12-3c4d5e6f7890";
const ws = new WebSocket(`ws://localhost:8000/ws/jobs/${jobId}/telemetry`);

ws.onopen = () => {
  console.log("Connected to telemetry stream");
};

ws.onmessage = (event) => {
  const telemetry = JSON.parse(event.data);
  
  switch (telemetry.type) {
    case "PROCESS_CREATE":
      console.warn(`[PROCESS] PID ${telemetry.data.pid}: ${telemetry.data.cmdline}`);
      break;
    case "SOCKET_CONNECT":
      console.warn(`[NETWORK] ${telemetry.data.dest_ip}:${telemetry.data.dest_port}`);
      break;
    case "STATUS_CHANGE":
      if (telemetry.data.status === "COMPLETED") {
        console.log("Analysis complete — fetch final report");
        ws.close();
      }
      break;
  }
};

ws.onerror = (error) => {
  console.error("WebSocket error:", error);
};

ws.onclose = () => {
  console.log("Telemetry stream closed");
};
```

---

## Event Taxonomy

### System Events

These events represent OS-level actions intercepted by the sandbox audit hook during dynamic analysis.

#### `PROCESS_CREATE`
An external OS-level executable was spawned.

```json
{
  "type": "PROCESS_CREATE",
  "severity": "high",
  "timestamp": "2026-06-13T14:30:00Z",
  "data": {
    "pid": 4124,
    "ppid": 1024,
    "executable": "cmd.exe",
    "cmdline": "cmd.exe /c start evil.bat"
  }
}
```

#### `FILE_WRITE`
A file handle was opened with write, append, or create permissions.

```json
{
  "type": "FILE_WRITE",
  "severity": "medium",
  "timestamp": "2026-06-13T14:30:05Z",
  "data": {
    "pid": 4124,
    "target": "C:\\Windows\\Temp\\dropped.exe"
  }
}
```

#### `FILE_READ`
A file was read, particularly from sensitive paths (browser databases, credential stores, etc.).

```json
{
  "type": "FILE_READ",
  "severity": "low",
  "timestamp": "2026-06-13T14:30:06Z",
  "data": {
    "pid": 4124,
    "target": "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
  }
}
```

#### `SOCKET_CONNECT`
An outbound TCP or UDP socket connection was established.

```json
{
  "type": "SOCKET_CONNECT",
  "severity": "medium",
  "timestamp": "2026-06-13T14:30:08Z",
  "data": {
    "pid": 4124,
    "dest_ip": "192.168.1.100",
    "dest_port": 443,
    "protocol": "TCP"
  }
}
```

#### `DNS_QUERY`
A hostname resolution request was intercepted.

```json
{
  "type": "DNS_QUERY",
  "severity": "medium",
  "timestamp": "2026-06-13T14:30:07Z",
  "data": {
    "pid": 4124,
    "query": "evil-c2.example.com"
  }
}
```

#### `HTTP_REQUEST`
An HTTP request was intercepted (typically from `requests` or `urllib`).

```json
{
  "type": "HTTP_REQUEST",
  "severity": "medium",
  "timestamp": "2026-06-13T14:30:09Z",
  "data": {
    "pid": 4124,
    "method": "POST",
    "url": "https://evil-c2.example.com/exfil",
    "target": "requests.post()"
  }
}
```

#### `EXECUTION_ERROR`
A runtime crash or unhandled exception occurred during dynamic analysis.

```json
{
  "type": "EXECUTION_ERROR",
  "severity": "high",
  "timestamp": "2026-06-13T14:30:10Z",
  "data": {
    "error": "ModuleNotFoundError: No module named 'pynput'",
    "traceback": "..."
  }
}
```

#### `EXECUTION_TIMEOUT`
The sandbox reached its configured execution time limit.

```json
{
  "type": "EXECUTION_TIMEOUT",
  "severity": "high",
  "timestamp": "2026-06-13T14:30:10Z",
  "data": {
    "timeout_seconds": 10
  }
}
```

### Lifecycle Events

These events represent transitions in the analysis pipeline state machine.

#### `STATUS_CHANGE`

```json
{
  "type": "STATUS_CHANGE",
  "severity": "info",
  "timestamp": "2026-06-13T14:30:00Z",
  "data": {
    "status": "CREATED | RUNNING | COMPLETED | FAILED"
  }
}
```

**State Machine**:

```
CREATED → RUNNING → COMPLETED
                  └→ FAILED
```

---

## Client Implementation Notes

1. **Buffering**: The frontend should buffer rapid bursts of events using `requestAnimationFrame` or `setTimeout` to avoid blocking the UI thread.
2. **Completion**: When the client receives `STATUS_CHANGE` with `status: "COMPLETED"`, the WebSocket will close. Immediately trigger a `GET /analysis/{job_id}` to fetch the final report.
3. **Reconnection**: If the WebSocket disconnects unexpectedly, the client should attempt a single reconnection. If the job is already `COMPLETED`, skip the WebSocket entirely and fetch the report directly.
4. **Color Coding**: The frontend renders telemetry severity as color-coded entries: High = Red, Medium = Orange, Info = Blue.
