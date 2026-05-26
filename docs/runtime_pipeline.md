# Sentinel-AI Runtime Pipeline Architecture

This document explains the runtime analysis architecture of Sentinel-AI, describing the end-to-end execution flow of malware samples.

## 1. Upload Flow
1. A user submits a sample via the frontend `UploadArtifact.tsx` which hits the backend `/upload` endpoint (`upload.py`).
2. The file is streamed locally to disk using `aiofiles` to prevent blocking the asyncio event loop.
3. Static hash metadata (SHA256, MD5, size, entropy) is computed synchronously but offloaded to a thread pool via `asyncio.to_thread`.
4. A job record is created in MongoDB containing the original filename and metadata.

## 2. Static Analysis Flow
The report pipeline (`report_generator.py`) is triggered. It first extracts static information:
- File metadata (hash, entropy, size).
- Strings extraction (`string_extractor.py`), filtering out benign file extensions to extract potential IP/Domain/URL indicators.

## 3. Runtime Execution Flow
Sentinel-AI uses a **Local Subprocess Sandbox** (`sandbox/local_sandbox.py`) for execution.
- A temporary directory is created for the execution (`tempfile.mkdtemp`).
- The Python script is copied into this isolated directory.
- `sys.path` and the current working directory (`CWD`) are restricted to prevent the script from easily accessing Sentinel-AI's backend source code.
- `sys.addaudithook` is injected to monitor OS-level Python calls (`subprocess.Popen`, `socket.connect`, file `open`, etc.).
- `runpy` executes the script natively within this environment.

> [!WARNING]
> **SECURITY LIMITATIONS**: 
> This is a naive "local sandbox". It relies entirely on Python's `sys.addaudithook`. 
> - **It is NOT true malware isolation.**
> - A malicious Python script could use `ctypes` or C-extensions to bypass the audit hook.
> - The script runs on the host machine. If it contains actual destructive code (e.g. deleting files outside the temp dir via raw syscalls), it will execute.
> For production deployment or analyzing real, unknown malware, an isolated virtualization solution MUST be used (e.g., **gVisor, Firecracker, Kata Containers, or isolated VMs**).

## 4. Redis Streaming & WebSocket Telemetry
- As `local_sandbox.py` runs, the `audit_hook` intercepts events and prints JSON telemetry payloads to `stdout`.
- The parent wrapper (`sandbox_runner.py`) continuously reads `stdout` asynchronously.
- Valid telemetry payloads are parsed and published to a Redis PubSub channel (`job_updates:{job_id}`).
- The FastAPI `/ws/jobs/{job_id}/telemetry` endpoint subscribes to this Redis channel and proxies events down to the frontend via WebSockets.
- The frontend `useWebSocket.ts` buffers events using `requestAnimationFrame` to prevent UI freezing during telemetry bursts, and `AnalysisDetail.tsx` renders them in a terminal-like view.

## 5. Persistence & Correlation
- Once the sandbox process completes (or times out after 10s), the extracted events are passed into the correlation engine.
- **IOC Extraction** (`ioc_pipeline.py`): Combines static strings with deterministic runtime events (`SOCKET_CONNECT`, `DNS_QUERY`) to build the IOC table.
- **MITRE ATT&CK** (`mitre_mapper.py`): Maps observed behavior (e.g., `subprocess.Popen` with `schtasks`) to MITRE techniques.
- **AI Correlator** (`ai_correlator.py`): Generates a natural language summary based purely on the structured evidence, avoiding hallucinations.
- The final report, including the full array of telemetry events, is saved to MongoDB (`job_model.py`).
