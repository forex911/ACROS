# Sentinel-AI System Architecture

Sentinel-AI is composed of a React frontend and a FastAPI backend, heavily relying on an asynchronous, event-driven pipeline to analyze malware samples securely and efficiently.

## Core Components

1. **Frontend (React + Vite)**: 
   - A modern SOC dashboard built with Tailwind CSS.
   - Communicates with the backend REST APIs for metadata and IOCs.
   - Establishes a WebSocket connection for real-time telemetry streaming from the sandbox.

2. **Backend (FastAPI)**:
   - Manages file uploads asynchronously using `aiofiles` and thread pools to prevent blocking the event loop while hashing large binaries.
   - Provides REST endpoints for report fetching and WebSocket routes for telemetry.
   - Coordinates the entire analysis pipeline (Static Analysis, Sandbox Execution, AI Correlation).

3. **Database (MongoDB)**:
   - Stores job metadata, static analysis results, extracted IOCs, mapped MITRE tactics, and the full telemetry array in the `sandbox_jobs` collection.

4. **Message Broker (Redis)**:
   - Acts as a PubSub bus for live telemetry. As the sandbox executes, events are published to `job_updates:{job_id}`.
   - The WebSocket endpoint subscribes to this channel to push events to the frontend.

5. **Sandbox (Local Wrapper)**:
   - A specialized Python wrapper (`sandbox/local_sandbox.py`) that isolates execution into a temporary directory.
   - It intercepts OS-level actions (Process creation, File Writes, Network Sockets, DNS) using `sys.addaudithook`.
   - Emits standardized JSON telemetry via `stdout`, which the backend parses and forwards to Redis.

## Pipeline Flow

1. **Submission**: User uploads `malware.py`. Backend computes MD5/SHA256, Size, and Entropy instantly, saving the job to MongoDB.
2. **Static Analysis**: `string_extractor.py` parses the binary for IPs/URLs/Domains, applying strict filters to avoid false positives.
3. **Dynamic Analysis**: The sandbox executes the file for up to 10 seconds, intercepting and logging all system interactions.
4. **Correlation**: 
   - `ioc_pipeline.py` consolidates static and dynamic network indicators.
   - `mitre_mapper.py` assigns ATT&CK techniques based on explicit runtime evidence (e.g. `subprocess.Popen` calls).
   - `ai_correlator.py` generates a deterministic human-readable summary.
5. **Persistence**: The final comprehensive report is merged back into MongoDB.
