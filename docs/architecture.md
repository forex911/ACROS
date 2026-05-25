# Sentinel-AI Architecture

## 1. High-Level Architecture Overview

Sentinel-AI is a distributed, cloud-native malware analysis and behavioral intelligence platform. It utilizes an event-driven architecture with isolated execution sandboxes, real-time telemetry extraction, and machine learning-based threat classification.

```mermaid
graph TD
    User([User / API Client]) -->|Upload Malware| Ingress[Kubernetes Ingress]
    Ingress --> Backend[FastAPI Backend]
    
    Backend -->|Store Artifact| MinIO[(MinIO S3 Immutable Storage)]
    Backend -->|Save Job State| MongoDB[(MongoDB Replica Set)]
    Backend -->|Enqueue Job| Redis[(Redis Pub/Sub & Queue)]
    
    Redis -->|Consume Task| WorkerPool[Celery Worker Pool]
    
    subgraph Isolated Sandbox Node Pool
        WorkerPool -->|Spawn gVisor Container| Sandbox[Hardened Sandbox]
        Sandbox -->|Run Artifact| Exec
        Sandbox -->|Extract Telemetry| Monitor[Watchdog, Scapy, psutil]
    end
    
    Monitor -->|Normalize Events| AIEngine[AI Threat Engine]
    AIEngine -->|Vectorize| XGBoost[(XGBoost Classifier)]
    AIEngine -->|Summarize| LLM[(Transformers MITRE Explainer)]
    
    AIEngine -->|Query IOCs| ThreatIntel[VirusTotal / AbuseIPDB]
    ThreatIntel -->|Final Report| MongoDB
    
    MongoDB -->|WebSocket Pub| Backend
    Backend -->|Stream Results| User
```

## 2. Threat Intelligence Pipeline

```mermaid
sequenceDiagram
    participant Worker as Sandbox Worker
    participant Extractor as IOC Extractor
    participant TI as Threat Intel Service
    participant YARA as YARA Service
    participant External as VT / AbuseIPDB

    Worker->>Extractor: Send Normalized Telemetry
    Extractor->>Extractor: Extract IPs, Domains, Hashes
    
    par Enrichment
        Extractor->>TI: Request IP/Hash reputation
        TI->>External: Query API
        External-->>TI: Return JSON Results
        TI-->>Worker: Enriched IOCs
    and Static Analysis
        Worker->>YARA: Request Static Scan
        YARA-->>Worker: YARA Matches (Tags)
    end
    
    Worker->>Worker: Aggregate Final Report
```

## 3. Kubernetes & Security Architecture

The platform runs on Kubernetes, strictly isolated using Pod Security Standards and Network Policies.

- **Frontend/Backend Namespaces**: `sentinel-backend`, `sentinel-storage`
- **Isolated Worker Namespace**: `sentinel-workers`
  - Runs on dedicated, tainted node pools (`workload-type=isolated-sandbox`).
  - NetworkPolicies drop ALL egress traffic except specific internal IPs (Redis, MinIO).
  - Pod Security contexts enforce `readOnlyRootFilesystem`, `runAsNonRoot`, and `cap_drop: ALL`.
  - Nested container runtime utilizes `gVisor` (`runsc`) via Docker/containerd for deep kernel isolation.

## 4. Observability

- **Metrics**: `prometheus-fastapi-instrumentator` exposes `/metrics` for Prometheus scraping.
- **Logging**: `structlog` emits JSON structured logs.
- **Tracing**: OpenTelemetry auto-instrumentation injects `trace_id` for request correlation across the distributed system.
