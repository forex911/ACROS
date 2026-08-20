# Installation & Setup

This guide covers deploying ACROS-AI for local development, Docker Compose, and production Kubernetes environments.

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Python** | 3.10+ | Backend runtime |
| **Node.js** | 18+ | Frontend build toolchain |
| **MongoDB** | 6.0+ | Primary data store |
| **Redis** | 7.0+ | PubSub and caching |
| **Neo4j** | 5.0+ | Attack graph database (optional for dev) |

---

## Option 1: Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/ACROS-AI.git
cd ACROS-AI
```

### 2. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory (see [Configuration](configuration.md) for all variables):

```env
MONGO_URI=mongodb://localhost:27017
REDIS_URI=redis://localhost:6379
```

Start the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8000
```

The API is now available at `http://localhost:8000`. Swagger docs are at `http://localhost:8000/docs`.

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

Create a `.env` file in the `frontend/` directory:

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

Start the Vite development server:

```bash
npm run dev
```

The frontend is now available at `http://localhost:5173`.

---

## Option 2: Docker Compose

For a fully containerized development environment:

```bash
docker-compose up --build
```

This starts:
- **Backend** at `http://localhost:8000`
- **Frontend** at `http://localhost:5173`
- **MongoDB** at `mongodb://localhost:27017`
- **Redis** at `redis://localhost:6379`

---

## Option 3: Kubernetes Deployment

See [Kubernetes Deployment](kubernetes.md) for Helm chart installation and ArgoCD GitOps configuration.

---

## Verifying the Installation

### Health Check

```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy", "version": "2.0.0"}
```

### Test Upload

You can test the pipeline using the sample scripts in `tests/samples/`:

| Sample | Expected Behavior |
|---|---|
| `benign_hello.py` | LOW risk — simple print statement |
| `file_writer.py` | MEDIUM risk — writes files to disk |
| `powershell_downloader.py` | HIGH risk — spawns PowerShell with encoded command |
| `ransomware_simulator.py` | CRITICAL risk — simulates file encryption |

**Upload via cURL**:

```bash
curl -X POST http://localhost:8000/upload \
  -F "file=@tests/samples/benign_hello.py"
```

**Upload via Python**:

```python
import requests

response = requests.post(
    "http://localhost:8000/upload",
    files={"file": open("tests/samples/benign_hello.py", "rb")}
)
print(response.json())
```

After uploading, open the frontend dashboard to view the live telemetry stream and final analysis report.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError` | Ensure virtual environment is activated and `pip install -r requirements.txt` completed |
| MongoDB connection refused | Verify MongoDB is running: `mongosh --eval "db.runCommand({ping:1})"` |
| Redis connection refused | Verify Redis is running: `redis-cli ping` (should return `PONG`) |
| WebSocket not connecting | Check that `VITE_WS_URL` matches the backend port |
| Frontend shows CORS errors | Verify CORS origins in `app/main.py` include the frontend URL |
| Neo4j warnings in logs | Neo4j is optional for local dev. Warnings are non-fatal. |
