# Pipeline Workflow

This document traces the complete lifecycle of a malware sample from the moment it is uploaded to the final report being served to the analyst. Every stage is documented with the responsible module and the data transformations that occur.

---

## End-to-End Pipeline Diagram

```
 ┌─────────┐
 │  User   │
 │ Upload  │
 └────┬────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    UPLOAD HANDLER                           │
│  upload.py                                                  │
│  1. Stream file to disk (aiofiles, non-blocking)            │
│  2. Compute SHA-256, MD5, size, entropy (thread pool)       │
│  3. Create MongoDB job record (status: "accepted")          │
│  4. Trigger generate_report_pipeline() asynchronously       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              REPORT GENERATION PIPELINE                     │
│  report_generator.py → generate_report_pipeline()           │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ STAGE 1: STATIC ANALYSIS                             │   │
│  │                                                      │   │
│  │  hash_analyzer.py    → SHA-256, MD5, size, entropy   │   │
│  │  string_extractor.py → Printable strings extraction  │   │
│  │  python_analyzer.py  → AST: eval, exec, subprocess   │   │
│  │  pe_analyzer.py      → PE headers, imports, sections │   │
│  └──────────────────────────────┬───────────────────────┘   │
│                                 │                           │
│  ┌──────────────────────────────▼───────────────────────┐   │
│  │ STAGE 2: DYNAMIC SANDBOX EXECUTION                   │   │
│  │                                                      │   │
│  │  orchestrator.py     → State: CREATED → RUNNING      │   │
│  │  local_sandbox.py    → Isolated exec + audit hooks   │   │
│  │  sandbox_runner.py   → stdout parsing → Redis pub    │   │
│  │                                                      │   │
│  │  Output: Telemetry event array                       │   │
│  │  Streaming: Redis PubSub → WebSocket → Frontend      │   │
│  └──────────────────────────────┬───────────────────────┘   │
│                                 │                           │
│  ┌──────────────────────────────▼───────────────────────┐   │
│  │ STAGE 3: CORRELATION & INTELLIGENCE                  │   │
│  │                                                      │   │
│  │  ioc_pipeline.py     → Extract IPs, domains, hashes  │   │
│  │  mitre_mapper.py     → Map telemetry → ATT&CK IDs   │   │
│  │                                                      │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ INTELLIGENCE LAYER (app/analysis/)             │  │   │
│  │  │                                                │  │   │
│  │  │  capability_engine.py  → Extract capabilities  │  │   │
│  │  │  behavior_engine.py    → Detect attack chains  │  │   │
│  │  │  threat_classifier.py  → Classify malware fam. │  │   │
│  │  │  impact_engine.py      → CIA impact assessment │  │   │
│  │  │  risk_engine.py        → Weighted risk score   │  │   │
│  │  │  report_generator.py   → Analyst report        │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │                                                      │   │
│  │  yara_service.py     → Pattern matching scan         │   │
│  └──────────────────────────────┬───────────────────────┘   │
│                                 │                           │
│  ┌──────────────────────────────▼───────────────────────┐   │
│  │ STAGE 4: GRAPH INGESTION                             │   │
│  │                                                      │   │
│  │  graph_ingester.py   → Neo4j: Jobs, Processes, Net   │   │
│  │  threat_correlation  → Build attack timeline         │   │
│  │                                                      │   │
│  │  Note: Non-blocking. Failures logged, never fatal.   │   │
│  └──────────────────────────────┬───────────────────────┘   │
│                                 │                           │
│  ┌──────────────────────────────▼───────────────────────┐   │
│  │ STAGE 5: FINALIZATION                                │   │
│  │                                                      │   │
│  │  Compile report dict (all pipeline outputs)          │   │
│  │  Save to MongoDB (set_report)                        │   │
│  │  Increment Prometheus counters                       │   │
│  │  Emit COMPLETED via Redis PubSub                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Stage 1: Upload Flow

**Module**: `app/api/upload.py`

1. A user submits a sample via the frontend `Workspace.tsx` or the `POST /upload` endpoint.
2. The file is streamed to local disk using `aiofiles` to prevent blocking the asyncio event loop.
3. Static hash metadata (SHA-256, MD5, size, Shannon entropy) is computed synchronously but offloaded to a thread pool via `asyncio.to_thread`.
4. A job record is created in MongoDB containing the original filename, hashes, and initial `status: "accepted"`.
5. `generate_report_pipeline()` is triggered as a background task.

---

## Stage 2: Static Analysis

**Modules**: `app/services/static_analysis/`

| Analyzer | Input | Output |
|---|---|---|
| `hash_analyzer.py` | File path | `{ sha256, md5, size, entropy }` |
| `string_extractor.py` | File path | Array of printable strings (filtered to remove benign file paths and common extensions) |
| `python_analyzer.py` | `.py` file path | AST findings: `EXEC_USAGE`, `BASE64_USAGE`, `SUBPROCESS_USAGE`, `SOCKET_USAGE`, etc. |
| `pe_analyzer.py` | `.exe`/`.dll` path | PE headers, import table, sections, packing indicators |

Python files are analyzed via AST walking; all other files are analyzed via PE header parsing. The outputs are stored in the `static_results` dictionary.

---

## Stage 3: Dynamic Sandbox Execution

**Modules**: `app/services/sandbox/`

### Execution Lifecycle

1. **Orchestrator** (`orchestrator.py`) manages the sandbox state machine: `CREATED → RUNNING → COMPLETED`.
2. **Local Sandbox** (`local_sandbox.py`) creates an isolated execution environment:
   - Creates a temporary directory (`tempfile.mkdtemp`)
   - Copies the target script into the isolated directory
   - Restricts `sys.path` and CWD to prevent access to ACROS source code
   - Injects `sys.addaudithook` to monitor OS-level Python calls (`subprocess.Popen`, `socket.connect`, file `open`, etc.)
   - Executes the script via `runpy`
3. **Sandbox Runner** (`sandbox_runner.py`) reads telemetry from `stdout` asynchronously, parses valid JSON payloads, and publishes them to the Redis PubSub channel `job_updates:{job_id}`.
4. The FastAPI WebSocket endpoint subscribes to this Redis channel and proxies events to the connected frontend.

> **⚠️ Security Limitation**: The local sandbox relies entirely on Python's `sys.addaudithook`. A malicious script could use `ctypes` or C-extensions to bypass the audit hook. For production deployment with real malware, use gVisor, Kata Containers, or Firecracker isolation. See [Sandbox Engine](../architecture/sandbox_engine.md).

---

## Stage 4: Correlation & Intelligence

### IOC Extraction (`ioc_pipeline.py`)
Combines static strings with deterministic runtime events (`SOCKET_CONNECT`, `DNS_QUERY`) to build the IOC table. Enforces strict type checking and confidence scoring.

### MITRE ATT&CK Mapping (`mitre_mapper.py`)
Maps observed telemetry to MITRE techniques deterministically. For example:
- `PROCESS_CREATE` with `powershell` → `T1059.001` (PowerShell)
- `PROCESS_CREATE` with `schtasks` → `T1053.005` (Scheduled Task)
- `FILE_WRITE` to `startup` paths → `T1547.001` (Registry Run Keys / Startup Folder)

### Intelligence Layer (`app/analysis/`)
The 6-stage intelligence pipeline runs in sequence:
1. **CapabilityEngine** — Extracts attacker capabilities from static + dynamic signals
2. **BehaviorEngine** — Correlates capabilities into attack chains
3. **ThreatClassifier** — Classifies the malware family
4. **ImpactEngine** — Calculates CIA impact
5. **RiskEngine** — Computes weighted risk score
6. **AnalystReportGenerator** — Compiles the structured report

See [Intelligence Layer](../architecture/intelligence_layer.md) for complete documentation.

### YARA Scanning (`yara_service.py`)
Scans the uploaded artifact against compiled YARA rules for known malware signatures and behavioral patterns.

---

## Stage 5: Graph Ingestion

**Modules**: `app/services/graph_ingester.py`, `app/services/threat_correlation.py`

All analysis artifacts are written to Neo4j as a directed attack graph:
- `SandboxJob → File` (ANALYZED relationship)
- `SandboxJob → Process → NetworkConnection` (SPAWNED → CONNECTED_TO)
- `SandboxJob → IOC` (EXTRACTED)
- `SandboxJob → MitreTechnique` (MAPPED_TO)
- `File → YaraRule` (MATCHED)

An attack timeline is also constructed from telemetry events and ingested into the graph.

> Graph ingestion is **non-blocking** and **gracefully degraded**. If Neo4j is unavailable, the MongoDB pipeline continues without interruption.

---

## Stage 6: Finalization

1. The complete report dictionary is assembled from all pipeline outputs.
2. The report is persisted to MongoDB via `set_report(job_id, report)`.
3. Prometheus counters are incremented (`jobs_processed_total`, and `malware_detected_total` if score > 60).
4. A `COMPLETED` event is emitted via Redis PubSub to signal the frontend to fetch the final report.

---

## OpenTelemetry Tracing

Each pipeline stage is wrapped in an OpenTelemetry span for distributed tracing:

| Span Name | Coverage |
|---|---|
| `generate_report_pipeline` | Root span for the entire pipeline |
| `static_analysis` | Hash computation, string extraction, AST/PE analysis |
| `sandbox_execution` | Sandbox lifecycle and telemetry collection |
| `correlation_analysis` | IOC extraction, MITRE mapping, Intelligence Layer, YARA |
| `graph_ingestion` | Neo4j graph writes |
| `timeline_generation` | Attack timeline construction |
| `finalize_report` | Report assembly, MongoDB persistence, metric collection |
