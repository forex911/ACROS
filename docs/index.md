# ACROS Documentation

> **Version**: 2.0 &nbsp;|&nbsp; **License**: Proprietary &nbsp;|&nbsp; **Status**: Active Development

ACROS is an intelligence-driven malware analysis platform that combines static analysis, dynamic sandbox execution, behavioral correlation, and AI-powered threat classification to produce enterprise-grade security verdicts.

Unlike conventional sandbox platforms that score individual events (e.g., `+10 for FILE_WRITE`), ACROS employs a multi-stage Intelligence Layer that maps raw telemetry into attacker **capabilities**, sequences them into **behavior chains**, classifies the payload into a **threat family**, and computes a weighted **risk score** grounded in the MITRE ATT&CK framework.

---

## Platform Capabilities

| Capability | Description | Status |
|---|---|---|
| **Static Analysis** | SHA-256/MD5 hashing, entropy calculation, string extraction, Python AST analysis, PE header parsing | ✅ Production |
| **Dynamic Sandbox** | Isolated execution with real-time telemetry capture (Process, File, Network, DNS) via `sys.addaudithook` | ✅ Production |
| **YARA Scanning** | Rule-based pattern matching against uploaded artifacts | ✅ Production |
| **IOC Extraction** | Automated extraction of IPs, domains, URLs, hashes, and suspicious commands | ✅ Production |
| **MITRE ATT&CK Mapping** | Deterministic mapping of observed behaviors to MITRE techniques and tactics | ✅ Production |
| **Intelligence Layer** | Capability extraction → Behavior correlation → Threat classification → Weighted risk scoring | ✅ Production |
| **Graph Analysis** | Neo4j-backed attack graph linking jobs, processes, network connections, and MITRE techniques | ✅ Production |
| **Attack Timeline** | Chronological reconstruction of attacker actions during sandbox execution | ✅ Production |
| **Real-Time Streaming** | WebSocket-based live telemetry streaming from sandbox to SOC dashboard | ✅ Production |
| **AI Analyst Reports** | LLM-generated executive summaries grounded in structured evidence | ✅ Production |
| **Threat Intelligence** | VirusTotal and AbuseIPDB enrichment for IOC reputation scoring | ✅ Production |
| **SIEM Export** | Structured event export for integration with external SIEM platforms | ✅ Production |
| **Threat Hunting** | Query-based hunting across historical analysis data | ✅ Production |
| **Enterprise Sandbox** | gVisor / Kata / Firecracker isolation with eBPF telemetry collection | 🔧 Planned |

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React/Vite)                    │
│  Dashboard │ Analysis Detail │ Attack Graph │ Observability     │
└──────────────────────┬──────────────────────────────────────────┘
                       │  REST + WebSocket
┌──────────────────────▼──────────────────────────────────────────┐
│                     BACKEND (FastAPI / Python)                  │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Upload API  │  │ Analysis API │  │ WebSocket Telemetry    │ │
│  └──────┬──────┘  └──────┬───────┘  └────────────┬───────────┘ │
│         │                │                        │             │
│  ┌──────▼────────────────▼────────────────────────▼───────────┐ │
│  │              Report Generation Pipeline                    │ │
│  │                                                            │ │
│  │  Static Analysis ──► Sandbox ──► IOC + MITRE ──►           │ │
│  │  Intelligence Layer ──► Graph Ingestion ──► Final Report   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              INTELLIGENCE LAYER (app/analysis/)            │ │
│  │                                                            │ │
│  │  CapabilityEngine → BehaviorEngine → ThreatClassifier →   │ │
│  │  ImpactEngine → RiskEngine → AnalystReportGenerator       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         │              │              │
    ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐
    │ MongoDB │   │   Redis   │  │  Neo4j  │
    │ (State) │   │ (PubSub)  │  │ (Graph) │
    └─────────┘   └───────────┘  └─────────┘
```

---

## Documentation Map

### 🚀 Getting Started
- **[Installation Guide](setup/installation.md)** — Deploy the platform locally or via Docker Compose.
- **[Configuration Reference](setup/configuration.md)** — Environment variables for backend, frontend, and external integrations.
- **[Kubernetes Deployment](setup/kubernetes.md)** — Helm charts, GitOps with ArgoCD, and sandbox node isolation.

### 🏗️ Architecture
- **[System Overview](architecture/overview.md)** — High-level distributed architecture, Kubernetes topology, and observability stack.
- **[Intelligence Layer](architecture/intelligence_layer.md)** — Deep dive into the 6-stage Capability → Risk pipeline that replaces legacy event scoring.
- **[Sandbox Engine](architecture/sandbox_engine.md)** — Execution isolation tiers (local dev, gVisor, Kata, Firecracker) and eBPF telemetry collection.
- **[Data Schema](architecture/data_schema.md)** — Telemetry event schema, IOC schema, Intelligence Layer output models, and MongoDB document structure.

### 🔌 API Reference
- **[REST Endpoints](api/rest_endpoints.md)** — Complete reference for the FastAPI backend routes with request/response examples.
- **[WebSocket Events](api/websocket_events.md)** — Real-time telemetry streaming protocol and event taxonomy.

### 🛠️ Development
- **[Pipeline Workflow](development/pipeline_workflow.md)** — End-to-end trace of how a malware sample flows through the system.
- **[Changelog](development/changelog.md)** — Detailed history of architectural overhauls and feature additions.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, React Router, Recharts |
| Backend | Python 3.10+, FastAPI, Pydantic, asyncio, aiofiles |
| Database | MongoDB (primary state), Neo4j (attack graphs), Redis (PubSub + caching) |
| Static Analysis | hashlib, Python AST, pefile, custom string extractor |
| Dynamic Analysis | sys.addaudithook sandbox, eBPF (planned) |
| Threat Intelligence | VirusTotal API, AbuseIPDB API |
| Pattern Matching | YARA |
| Observability | OpenTelemetry, Prometheus, structlog |
| Deployment | Docker Compose (dev), Kubernetes + Helm (prod), ArgoCD (GitOps) |
