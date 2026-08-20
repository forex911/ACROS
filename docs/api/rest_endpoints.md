# REST API Reference

This document provides the complete reference for all HTTP endpoints exposed by the ACROS-AI FastAPI backend.

**Base URL**: `http://localhost:8000` (development) or `https://api.ACROS-AI.example.com` (production)

---

## Authentication

All endpoints (except `/health`) require a valid JWT bearer token in the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

Tokens are obtained via the `/auth/login` endpoint and expire after the configured TTL.

---

## 1. Artifact Upload

Upload a malware sample for analysis. The backend streams the file to disk asynchronously, computes static hashes via a thread pool, creates a MongoDB job record, and triggers the full analysis pipeline.

**Endpoint**: `POST /upload`

**Content-Type**: `multipart/form-data`

**Request Body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | binary | Yes | The malware sample to analyze |

**Response** (`201 Created`):

```json
{
  "file_id": "a8f3c2d1-e456-4b89-9a12-3c4d5e6f7890",
  "filename": "suspicious_script.py",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "task_id": "b1c2d3e4-f567-8901-ab23-cd45ef678901",
  "status": "accepted"
}
```

**cURL Example**:

```bash
curl -X POST http://localhost:8000/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@malware_sample.py"
```

**Python Example**:

```python
import requests

response = requests.post(
    "http://localhost:8000/upload",
    headers={"Authorization": f"Bearer {token}"},
    files={"file": open("malware_sample.py", "rb")}
)
print(response.json())
```

---

## 2. Analysis Report

Retrieve the complete analysis report for a given job. The response includes all pipeline outputs: static metadata, YARA matches, MITRE mappings, IOCs, Intelligence Layer results, attack timeline, and AI summary.

**Endpoint**: `GET /analysis/{job_id}`

**Path Parameters**:

| Parameter | Type | Description |
|---|---|---|
| `job_id` | string | The job UUID. Use `latest` to fetch the most recent analysis. |

**Response** (`200 OK`):

```json
{
  "file_id": "a8f3c2d1-e456-4b89-9a12-3c4d5e6f7890",
  "filename": "suspicious_script.py",
  "status": "completed",

  "metadata": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "size": 4096,
    "entropy": 6.2
  },

  "risk_score": 71,
  "risk_factors": [
    "Threat classified as Infostealer",
    "Detected Infostealer Chain",
    "Exhibits Credential Access capability"
  ],
  "risk_calculation": {
    "score": 71,
    "severity": "HIGH",
    "confidence": 95,
    "verdict": "Infostealer",
    "score_breakdown": {
      "capability_risk": 22.75,
      "behavior_risk": 15.0,
      "threat_risk": 20.0,
      "mitre_risk": 4.0,
      "confidence_mod": 9.5
    },
    "reasoning": ["..."]
  },

  "analyst_report": {
    "executive_summary": "Analysis resulted in a HIGH risk score of 71/100...",
    "technical_findings": ["Identified Infostealer Chain: ..."],
    "threat_classification": {
      "family": "Infostealer",
      "confidence": 95,
      "evidence": ["Browser Login Data access", "..."]
    },
    "mitre_coverage": ["T1027", "T1059", "T1555", "T1048"],
    "impact_assessment": {
      "confidentiality": "Critical",
      "integrity": "Medium",
      "availability": "Low"
    },
    "recommended_actions": ["Rotate potentially exposed credentials and tokens."],
    "risk_assessment": { "..." }
  },

  "ai_summary": "Analysis resulted in a HIGH risk score of 71/100...",

  "yara_matches": ["MALWARE_CobaltStrike"],

  "mitre_tactics": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "evidence": "Spawned: powershell -enc JABz..."
    }
  ],

  "iocs": [
    {
      "type": "ip",
      "value": "185.11.23.4",
      "source": "Runtime Telemetry",
      "confidence": "High"
    }
  ],

  "attack_timeline": [
    {
      "timestamp": "2026-06-13T12:00:05Z",
      "action": "PROCESS_CREATE",
      "detail": "cmd.exe /c start evil.bat"
    }
  ],

  "telemetry_count": 12,
  "telemetry_events": ["..."]
}
```

---

## 3. Real-Time Telemetry Stream

A WebSocket endpoint that subscribes to the Redis PubSub channel `job_updates:{job_id}` and pushes live telemetry events as the sandbox executes.

**Endpoint**: `WebSocket /ws/jobs/{job_id}/telemetry`

**Connection**:

```javascript
const ws = new WebSocket("ws://localhost:8000/ws/jobs/abc123/telemetry");

ws.onmessage = (event) => {
  const telemetry = JSON.parse(event.data);
  console.log(telemetry.type, telemetry.data);
};
```

**Message Payload**:

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

**Lifecycle Events**:

When the sandbox completes, a final `STATUS_CHANGE` event is emitted:

```json
{
  "type": "STATUS_CHANGE",
  "severity": "info",
  "data": { "status": "COMPLETED" }
}
```

Upon receiving `COMPLETED`, the client should close the WebSocket and issue a `GET /analysis/{job_id}` to fetch the final report.

---

## 4. Health Check

**Endpoint**: `GET /health`

**Authentication**: None required

**Response** (`200 OK`):

```json
{
  "status": "healthy",
  "version": "2.0.0"
}
```

---

## 5. Metrics

**Endpoint**: `GET /metrics`

**Authentication**: None required (internal network only)

**Response**: Prometheus text format containing:
- `jobs_processed_total` — Counter of total analysis jobs completed
- `malware_detected_total` — Counter of jobs exceeding the risk threshold (score > 60)
- Standard FastAPI HTTP metrics (request duration, status codes, etc.)

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "detail": "Human-readable error description"
}
```

| Status Code | Description |
|---|---|
| `400` | Bad request — missing file, invalid parameters |
| `401` | Unauthorized — missing or invalid JWT token |
| `404` | Not found — job ID does not exist |
| `429` | Rate limited — too many requests |
| `500` | Internal server error — pipeline failure |
