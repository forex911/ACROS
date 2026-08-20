# Configuration Reference

This document lists all environment variables used by ACROS-AI, organized by component.

---

## Backend Configuration

Create a `.env` file in the `backend/` directory.

### Core Server

| Variable | Required | Default | Description |
|---|---|---|---|
| `HOST` | No | `0.0.0.0` | Server bind address |
| `PORT` | No | `8000` | Server port |
| `DEBUG` | No | `false` | Enable debug mode (never in production) |
| `LOG_LEVEL` | No | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `CORS_ORIGINS` | No | `*` | Comma-separated list of allowed CORS origins |

### Database & Message Broker

| Variable | Required | Default | Description |
|---|---|---|---|
| `MONGODB_URI` | **Yes** | — | MongoDB connection string (e.g., `mongodb://localhost:27017/ACROS`) |
| `REDIS_URI` | **Yes** | — | Redis connection string (e.g., `redis://localhost:6379/0`) |
| `NEO4J_URI` | No | — | Neo4j Bolt connection string (e.g., `bolt://localhost:7687`) |
| `NEO4J_USER` | No | `neo4j` | Neo4j authentication username |
| `NEO4J_PASSWORD` | No | — | Neo4j authentication password |

### External Integrations

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | No | — | OpenAI API key for AI-powered analysis summaries |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal API key for IOC reputation enrichment |
| `ABUSEIPDB_API_KEY` | No | — | AbuseIPDB API key for IP reputation lookups |

### YARA Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `YARA_RULES_DIR` | No | `./yara_rules` | Directory containing compiled YARA rule files |

### Sandbox Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SANDBOX_TIMEOUT` | No | `10` | Maximum sandbox execution time in seconds |
| `SANDBOX_ENGINE` | No | `local_dev` | Sandbox backend (`local_dev`, `gvisor`, `kata`, `firecracker`) |

### Security

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_SECRET_KEY` | **Yes** | — | Secret key for JWT token signing |
| `JWT_ALGORITHM` | No | `HS256` | JWT signing algorithm |
| `JWT_EXPIRY_MINUTES` | No | `60` | Token expiration time in minutes |
| `API_KEY` | No | — | Optional API key for programmatic access |

### Observability

| Variable | Required | Default | Description |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | — | OpenTelemetry collector endpoint |
| `OTEL_SERVICE_NAME` | No | `acros-backend` | Service name for distributed tracing |

---

## Frontend Configuration

Create a `.env` or `.env.local` file in the `frontend/` directory.

| Variable | Required | Default | Description |
|---|---|---|---|
| `VITE_API_URL` | **Yes** | — | Backend API base URL (e.g., `http://localhost:8000`) |
| `VITE_WS_URL` | **Yes** | — | Backend WebSocket base URL (e.g., `ws://localhost:8000`) |

---

## Docker Compose Overrides

When running via Docker Compose, environment variables are configured in `docker-compose.yml`. The service names act as hostnames within the Docker network:

```yaml
services:
  backend:
    environment:
      MONGODB_URI: mongodb://mongo:27017/ACROS
      REDIS_URI: redis://redis:6379/0
      NEO4J_URI: bolt://neo4j:7687

  frontend:
    environment:
      VITE_API_URL: http://backend:8000
      VITE_WS_URL: ws://backend:8000
```

---

## Kubernetes ConfigMaps & Secrets

In Kubernetes deployments, sensitive values are stored as `Secrets` and non-sensitive values as `ConfigMaps`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ACROS-secrets
  namespace: ACROS
type: Opaque
stringData:
  JWT_SECRET_KEY: "your-secret-key"
  OPENAI_API_KEY: "sk-..."
  VIRUSTOTAL_API_KEY: "..."
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ACROS-config
  namespace: ACROS
data:
  MONGODB_URI: "mongodb://mongo-svc:27017/ACROS"
  REDIS_URI: "redis://redis-svc:6379/0"
  SANDBOX_ENGINE: "gvisor"
  SANDBOX_TIMEOUT: "30"
```
