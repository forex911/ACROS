<p align="center">
  <h1 align="center">🛡️ Aegis-AI</h1>
  <p align="center">
    <strong>AI-Powered Malware Analysis &amp; Behavioral Intelligence Platform</strong>
  </p>
  <p align="center">
    <a href="#-quickstart"><img src="https://img.shields.io/badge/get%20started-quickstart-blue?style=flat-square" alt="Quickstart"></a>
    <img src="https://img.shields.io/badge/python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
    <img src="https://img.shields.io/badge/fastapi-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/react-19-61dafb?style=flat-square&logo=react&logoColor=black" alt="React 19">
    <img src="https://img.shields.io/badge/typescript-6.0-3178c6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
    <img src="https://img.shields.io/badge/docker-compose-2496ed?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  </p>
</p>

---

Aegis-AI is a cloud-native, distributed malware analysis platform that combines **sandboxed execution**, **real-time behavioral telemetry**, and **machine learning threat classification** to deliver automated, explainable threat intelligence reports — complete with **MITRE ATT&CK mapping**, **IOC extraction**, and **YARA rule matching**.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Quickstart](#-quickstart)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Category | Capabilities |
|---|---|
| **Sandbox Execution** | Local subprocess sandbox with Python audit hooks · gVisor / Firecracker / Kata Containers runners for production isolation |
| **Static Analysis** | SHA256 / MD5 hashing · Entropy calculation · PE file parsing · String extraction with IOC pattern matching |
| **Runtime Monitoring** | Process creation tracking · Network socket interception · File I/O monitoring · DNS query capture via `scapy` |
| **Threat Intelligence** | VirusTotal & AbuseIPDB enrichment · YARA rule scanning · IOC correlation pipeline |
| **AI / ML Engine** | XGBoost malware classifier · Anomaly detection · Transformer-based MITRE ATT&CK explainer · NLP threat summarization |
| **MITRE ATT&CK** | Automated technique mapping from behavioral evidence (e.g. `T1059.001 PowerShell`, `T1053 Scheduled Tasks`) |
| **Real-Time Streaming** | Redis Pub/Sub → WebSocket telemetry pipeline · Live event feed with `requestAnimationFrame` batching |
| **Knowledge Graph** | Neo4j-backed attack graph ingestion · Visual attack chain exploration via React Flow |
| **Threat Hunting** | Query-based hunting across historical analysis data · IOC search and cross-referencing |
| **Observability** | Prometheus metrics · OpenTelemetry distributed tracing · Structured JSON logging via `structlog` |
| **Dashboard** | Risk score visualization · Upload history · Workspace management · Real-time analysis detail view |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         User / API Client                            │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │  Upload / Query
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Kubernetes Ingress (Nginx)                        │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
   ┌─────────────┐      ┌─────────────┐     ┌─────────────────┐
   │   Frontend  │      │    FastAPI  │     │   WebSocket     │
   │ React/Vite  │      │   Backend   │     │   Telemetry     │
   └─────────────┘      └──────┬──────┘     └────────┬────────┘
                               │                     │
          ┌────────────┬───────┼───────┬─────────────┘
          ▼            ▼       ▼       ▼
   ┌───────────┐ ┌──────────┐ ┌─────┐ ┌──────────────────┐
   │  MongoDB  │ │  MinIO   │ │Redis│ │  Neo4j (Graph)   │
   │(Job State)│ │(Artifact)│ │(Pub/│ │ (Attack Chains)  │
   └───────────┘ └──────────┘ │Sub) │ └──────────────────┘
                              └──┬──┘
                                 │ Celery Task
                                 ▼
                    ┌─────────────────────────────┐
                    │   Isolated Sandbox Worker   │
                    │  ┌───────────────────────┐  │
                    │  │ gVisor / Firecracker  │  │
                    │  │ Execution Container   │  │
                    │  └───────────┬───────────┘  │
                    │              │ Telemetry    │
                    │              ▼              │
                    │  ┌───────────────────────┐  │
                    │  │ Monitor (psutil,      │  │
                    │  │  scapy, watchdog)     │  │
                    │  └───────────┬───────────┘  │
                    └──────────────┼──────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     AI Threat Engine         │
                    │  ┌─────────┐ ┌────────────┐  │
                    │  │ XGBoost │ │Transformers│  │
                    │  │Classify │ │MITRE Mapper│  │
                    │  └─────────┘ └────────────┘  │
                    │  ┌─────────┐ ┌────────────┐  │
                    │  │  IOC    │ │   YARA     │  │
                    │  │Pipeline │ │  Scanner   │  │
                    │  └─────────┘ └────────────┘  │
                    └──────────────────────────────┘
```

> For a detailed architecture diagram with Mermaid charts, see [`docs/architecture.md`](docs/architecture.md).

---

## 🔧 Tech Stack

### Backend
| Component | Technology |
|---|---|
| API Server | FastAPI + Uvicorn |
| Task Queue | Celery + Redis |
| Database | MongoDB (Motor async driver) |
| Graph DB | Neo4j |
| Object Storage | MinIO (S3-compatible) |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Static Analysis | YARA, pefile, custom string extractor |
| Runtime Monitor | psutil, scapy, watchdog |
| Observability | Prometheus, OpenTelemetry, structlog |

### AI / ML Engine
| Component | Technology |
|---|---|
| Classification | XGBoost, scikit-learn |
| NLP / Explainer | Hugging Face Transformers, sentence-transformers |
| Threat Intel | VirusTotal API, AbuseIPDB API |
| MITRE Mapping | Custom rule engine + LLM explainer |

### Frontend
| Component | Technology |
|---|---|
| Framework | React 19 + TypeScript 6 |
| Build Tool | Vite 8 |
| Styling | Tailwind CSS 4 |
| State Management | Zustand |
| Data Fetching | TanStack React Query + Axios |
| Visualization | Recharts, React Flow |
| Animation | Framer Motion |
| Routing | React Router 7 |

### Infrastructure
| Component | Technology |
|---|---|
| Containers | Docker, Docker Compose |
| Orchestration | Kubernetes (Helm charts) |
| Sandbox Isolation | gVisor (runsc), Firecracker, Kata Containers |
| Reverse Proxy | Nginx |
| IaC | Terraform |
| GitOps | Argo CD |

---

## 📁 Project Structure

```
aegis-ai/
├── backend/                    # FastAPI backend server
│   ├── app/
│   │   ├── api/routes/         # REST & WebSocket endpoints
│   │   ├── core/               # Config, security, settings
│   │   ├── database/           # MongoDB connection & init
│   │   ├── models/             # Pydantic / ODM models
│   │   ├── schemas/            # Request/response schemas
│   │   ├── services/           # Business logic layer
│   │   │   ├── static_analysis/  # Hash, string, PE analysis
│   │   │   ├── runtime_analysis/ # Dynamic execution analysis
│   │   │   ├── ai_correlator.py  # AI-powered threat correlation
│   │   │   ├── mitre_mapper.py   # MITRE ATT&CK mapping
│   │   │   ├── ioc_pipeline.py   # IOC extraction & enrichment
│   │   │   ├── yara_service.py   # YARA rule scanning
│   │   │   └── ...
│   │   ├── utils/              # Shared utilities
│   │   └── main.py             # FastAPI application entry
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                   # React + Vite frontend
│   └── src/
│       ├── pages/              # Dashboard, AnalysisDetail, Login, ...
│       ├── components/         # Reusable UI components
│       ├── features/           # Feature-specific modules
│       ├── hooks/              # Custom React hooks
│       ├── store/              # Zustand state stores
│       ├── api/                # API client layer
│       ├── websocket/          # WebSocket connection manager
│       └── types/              # TypeScript type definitions
│
├── ai_engine/                  # ML models & LLM services
│   ├── models/                 # Trained model artifacts (.pkl)
│   ├── inference/              # Model inference logic
│   ├── training/               # Model training scripts
│   ├── datasets/               # Training datasets
│   └── llm/                    # LLM-based threat explainer
│
├── sandbox/                    # Sandbox execution engines
│   ├── local_sandbox.py        # Dev sandbox (Python audit hooks)
│   ├── gvisor_runner.py        # gVisor container runner
│   ├── firecracker_runner.py   # Firecracker microVM runner
│   ├── kata_runner.py          # Kata Containers runner
│   ├── engine_selector.py      # Runtime engine selector
│   ├── docker/                 # Sandbox Docker configs
│   ├── network/                # Network isolation configs
│   ├── telemetry/              # Telemetry collection
│   └── decoys/                 # Deception / honeypot assets
│
├── monitor/                    # Host-level monitoring agents
│   ├── ebpf_collector.py       # eBPF-based event collector
│   ├── process_monitor/        # Process activity tracking
│   ├── network_monitor/        # Network traffic capture
│   ├── filesystem_monitor/     # File I/O monitoring
│   └── memory_monitor/         # Memory analysis
│
├── orchestrator/               # Kubernetes job orchestration
│
├── deployment/                 # Deployment configurations
│   ├── docker/                 # Docker build files
│   ├── kubernetes/             # K8s manifests
│   ├── nginx/                  # Reverse proxy config
│   ├── terraform/              # Infrastructure as Code
│   └── observability/          # Prometheus, Grafana, Jaeger
│
├── charts/                     # Helm charts
├── gitops/                     # Argo CD GitOps config
├── infrastructure/             # Firecracker VM setup
├── scripts/                    # Build, deploy, setup scripts
├── docs/                       # Architecture & API docs
├── tests/                      # Integration & E2E tests
├── reports/                    # Generated analysis reports
├── storage/                    # Local artifact storage
│
├── docker-compose.yml          # Local dev stack (MongoDB + Redis)
├── .env                        # Environment variables
└── .gitignore
```

---

## 📋 Prerequisites

- **Python** 3.11+
- **Node.js** 20+ and **npm** 10+
- **Docker** & **Docker Compose**
- **MongoDB** 7+ (or use the Docker Compose stack)
- **Redis** 7+ (or use the Docker Compose stack)

---

## 🚀 Quickstart

### 1. Clone the repository

```bash
git clone https://github.com/forex911/Sentinel.git aegis
cd aegis
```

### 2. Start infrastructure services

```bash
docker-compose up -d
```

This starts **MongoDB** on `localhost:27017` and **Redis** on `localhost:6379`.

### 3. Setup the backend

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root (one already exists with defaults):

```env
MONGO_URI=mongodb://localhost:27017
DATABASE_NAME=aegis_ai
```

### 5. Run the backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API server will be available at **http://localhost:8000**.  
Interactive API docs at **http://localhost:8000/docs**.

### 6. Setup & run the frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at **http://localhost:5173**.

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/upload` | Upload a malware sample for analysis |
| `GET` | `/analysis/{job_id}` | Retrieve analysis report (use `latest` for most recent) |
| `WS` | `/ws/jobs/{job_id}/telemetry` | Real-time telemetry stream via WebSocket |
| `GET` | `/jobs` | List all analysis jobs |
| `GET` | `/reports/{job_id}` | Download full report |
| `POST` | `/auth/login` | Authenticate and receive JWT token |
| `GET` | `/dashboard/stats` | Dashboard statistics |
| `GET` | `/threats` | List detected threats |
| `GET` | `/metrics` | Prometheus metrics endpoint |
| `GET` | `/health` | Health check |

> Full API documentation: [`docs/api/`](docs/api/)

---

## 🚢 Deployment

### Docker

Individual service Dockerfiles are available in `deployment/docker/`.

### Kubernetes

Helm charts are in `charts/aegis-platform/`. Deploy with:

```bash
helm install aegis-ai charts/aegis-platform/ -n aegis --create-namespace
```

### GitOps (Argo CD)

Argo CD application manifests are in `gitops/`. See [`gitops/README.md`](gitops/README.md) for setup.

### Terraform

Infrastructure provisioning configs for sandbox node pools are in `deployment/terraform/`.

---

## 🔒 Security Notes

> [!WARNING]
> The **local subprocess sandbox** (`sandbox/local_sandbox.py`) is for **development only**.  
> It relies on Python's `sys.addaudithook` and can be bypassed by `ctypes` or native extensions.  
> For production use with real malware, deploy with **gVisor**, **Firecracker**, or **Kata Containers**.

- Sandbox workers run in a dedicated Kubernetes namespace (`aegis-workers`) on tainted, isolated node pools.
- Network policies drop all egress except internal services (Redis, MinIO).
- Pod security contexts enforce `readOnlyRootFilesystem`, `runAsNonRoot`, and `cap_drop: ALL`.
- All artifacts are stored immutably in MinIO with content-addressable SHA256 keys.

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m "feat: add my feature"`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a Pull Request

Please ensure:
- Code passes `pytest` and `flake8` checks
- Frontend builds without errors (`npm run build`)
- New endpoints include tests in `tests/`

---

## 📜 License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

---

<p align="center">
  <sub>Built with ❤️ for the cybersecurity community</sub>
</p>
