# Sentinel-AI API Reference

This document outlines the core backend API endpoints exposed by the Sentinel-AI FastAPI server.

## 1. Artifact Upload
**Endpoint**: `POST /upload`
**Description**: Accepts a malware sample for analysis. The upload stream is non-blocking (using `aiofiles`), computes hashes synchronously via a thread-pool, persists initial metadata to MongoDB, and triggers the `generate_report_pipeline` asynchronously.
**Request**:
- Content-Type: `multipart/form-data`
- Body: `file` (binary)
**Response**:
```json
{
  "file_id": "uuid-string",
  "filename": "original_filename.py",
  "sha256": "hash_string",
  "task_id": "sandbox-uuid",
  "status": "accepted"
}
```

## 2. Analysis Report
**Endpoint**: `GET /analysis/{job_id}`
**Description**: Retrieves the complete analysis report for a given job ID. Use `latest` to fetch the most recently submitted job.
**Response**:
```json
{
  "file_id": "uuid-string",
  "filename": "hello.py",
  "status": "completed",
  "risk_score": 45,
  "ai_summary": "Suspicious behavior detected...",
  "yara_matches": [],
  "mitre_tactics": [
    { "id": "T1059.001", "name": "PowerShell", "evidence": "Spawned: powershell -enc ..." }
  ],
  "iocs": [
    { "type": "ip", "value": "185.11.23.4", "source": "Runtime Telemetry", "confidence": "High" }
  ],
  "metadata": {
    "artifact_sha256": "hash",
    "md5": "hash",
    "size": 1024,
    "entropy": 4.5
  }
}
```

## 3. Real-time Telemetry Stream
**Endpoint**: `WebSocket /ws/jobs/{job_id}/telemetry`
**Description**: A WebSocket endpoint that subscribes to the Redis PubSub channel `job_updates:{job_id}` and pushes live telemetry events to the client as the sandbox executes.
**Message Payload**:
```json
{
  "type": "PROCESS_CREATE",
  "severity": "high",
  "timestamp": "2026-05-26T14:30:00Z",
  "data": {
    "cmdline": "powershell.exe"
  }
}
```
