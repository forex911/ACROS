# Sentinel-AI Installation & Setup

Follow these steps to deploy Sentinel-AI locally for development or testing.

## Prerequisites
- **Python 3.10+**
- **Node.js 18+**
- **MongoDB** (Running locally or accessible via URI)
- **Redis** (Running locally or accessible via URI)

## Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set environment variables (or create a `.env` file):
   ```env
   MONGO_URI=mongodb://localhost:27017
   REDIS_URI=redis://localhost:6379
   ```
5. Run the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

## Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set environment variables in a `.env` file:
   ```env
   VITE_API_URL=http://localhost:8000
   VITE_WS_URL=ws://localhost:8000
   ```
4. Run the Vite development server:
   ```bash
   npm run dev
   ```

## Testing the Pipeline
You can test the pipeline without using the UI by utilizing the scripts inside `tests/samples/`:
- `benign_hello.py`
- `file_writer.py`
- `powershell_downloader.py`
- `ransomware_simulator.py`

Upload them via the frontend, or trigger the backend upload directly via a curl or requests script:
```python
import requests
requests.post('http://localhost:8000/upload', files={'file': open('tests/samples/benign_hello.py', 'rb')})
```
