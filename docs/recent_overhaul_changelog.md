# Sentinel-AI Overhaul Changelog

This document details the recent comprehensive updates made to the Sentinel-AI behavioral analysis pipeline, ensuring accurate, deterministic telemetry and avoiding AI hallucinations.

## 1. Metadata Persistence (Phase 1)
- **Problem**: The frontend Analysis page was showing `N/A` for SHA256 and size, and was showing a truncated UUID for the filename.
- **Solution**: 
  - `upload.py` now calculates `sha256`, `md5`, `size`, and `entropy` synchronously via a thread-pool before MongoDB insertion.
  - `file_utils.py` saves the original filename alongside the UUID path.
  - `job_model.py` explicitly tracks metadata fields (`md5`, `size`, `entropy`, `telemetry`, `iocs`, `mitre_tactics`) at the root document level, avoiding messy nested dictionary overwrites.
  - The frontend `AnalysisDetail.tsx` consumes the new schema, correctly populating the File Metadata card.

## 2. Telemetry Pipeline & Local Sandbox (Phase 2 & 6)
- **Problem**: Telemetry tabs were empty, and the backend executed malware via a simple `subprocess` wrapper without true isolation.
- **Solution**:
  - Introduced `sandbox/local_sandbox.py` to handle isolated execution. It creates a temporary directory, copies the target script, overrides `sys.path`, intercepts calls using `sys.addaudithook`, and runs the code using `runpy`.
  - The telemetry event schema was standardized (e.g., `event_type`, `severity`, `timestamp`, `data`).
  - WebSockets in `jobs.py` properly stream these typed JSON payloads to the frontend.
  - The frontend `AnalysisDetail.tsx` features a real-time, auto-scrolling terminal UI with color-coding based on severity (High = Red, Medium = Orange, Info = Blue).

## 3. IOC Extraction (Phase 3)
- **Problem**: The IOC tab was empty or inconsistent. Generic strings like `.exe` or `.c` were falsely flagged as network domains.
- **Solution**:
  - `string_extractor.py` was updated to aggressively filter out windows file paths and common file extensions.
  - `ioc_pipeline.py` enforces strict type checking (`DOMAIN`, `URL`, `IP`, `HASH`, `command`).
  - Network IOCs are purely sourced from `SOCKET_CONNECT` and `DNS_QUERY` runtime hooks with a "High" confidence rating.
  - The frontend `AnalysisDetail.tsx` renders a clean, fully-featured IOC data table displaying Type, Value, Source, and Confidence.

## 4. Risk Engine Grounding (Phase 4)
- **Problem**: The AI summarizer and MITRE mapper hallucinated techniques simply based on static strings (e.g., mapping PowerShell just because the string "powershell" appeared in a binary).
- **Solution**:
  - `ai_correlator.py` was grounded. Network activity is only mentioned if actual socket or DNS events occur.
  - `mitre_mapper.py` relies on `PROCESS_CREATE` telemetry to map `T1059.001` (PowerShell) and `T1053.005` (Scheduled Task).
  - Persistence is mapped only when `FILE_WRITE` telemetry directly references `startup` or `run` paths.

## 5. Architectural Honesty & Validation (Phase 5 & 7)
- **Documentation**: Added `runtime_pipeline.md` outlining the execution architecture and truthfully documenting the limitations of `sys.addaudithook` vs actual Virtual Machines.
- **Validation**: Added 4 sample scripts in `tests/samples/` to systematically test Benign, File writing, PowerShell invocation, and Ransomware simulation workflows.
