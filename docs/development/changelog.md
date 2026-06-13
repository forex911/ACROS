# Changelog

All notable changes to Sentinel-AI are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.0.0] — 2026-06-13

### Added — Intelligence Layer

Replaced the monolithic `risk_engine.py` with a 6-stage modular Intelligence Layer in `app/analysis/`:

- **Capability Engine** (`capability_engine.py`): Maps raw telemetry into attacker capabilities (e.g., `eval()` + `base64` → `Obfuscated Execution`, Browser DB access → `Credential Access`).
- **Behavior Engine** (`behavior_engine.py`): Correlates capabilities into attack chains (e.g., `Infostealer Chain`, `RAT Chain`, `Surveillance Chain`).
- **Threat Classifier** (`threat_classifier.py`): Classifies payloads into malware families (Infostealer, RAT, Ransomware, Dropper, Spyware, etc.).
- **Impact Engine** (`impact_engine.py`): Calculates Confidentiality, Integrity, and Availability impact using the CIA triad.
- **Risk Engine** (`risk_engine.py`): Computes weighted risk scores (35% Capability + 25% Behavior + 20% Threat + 10% ATT&CK + 10% Confidence).
- **Analyst Report Generator** (`report_generator.py`): Produces structured `AnalystReport` with executive summary, technical findings, and remediation recommendations.

### Changed
- `app/services/report_generator.py`: Updated pipeline orchestrator to route telemetry through the Intelligence Layer instead of the legacy scoring engine.
- Risk score computation is now capability-driven rather than event-count-driven.
- Analysis API response now includes the full `analyst_report` object alongside existing fields.

### Removed
- `app/services/risk_engine.py`: Deprecated legacy event-counting risk engine.
- `app/models/analysis_model.py`: Deprecated monolithic analysis model (replaced by `app/analysis/models.py`).

---

## [1.5.0] — 2026-06-01

### Added — Attack Graph & Timeline
- **Neo4j Graph Ingester** (`graph_ingester.py`): Writes analysis artifacts to Neo4j as a directed attack graph with `SandboxJob`, `Process`, `NetworkConnection`, `DnsQuery`, `IOC`, `MitreTechnique`, and `YaraRule` nodes.
- **Threat Correlation** (`threat_correlation.py`): Builds chronological attack timelines from telemetry events and ingests them into the graph.
- **Attack Dashboard** (`AttackDashboard.tsx`): Frontend page for visualizing the Neo4j attack graph.
- **Observability Dashboard** (`Observability.tsx`): Platform health metrics and trace explorer.

### Added — Enterprise Security
- **SIEM Exporter** (`siem_exporter.py`): Structured event export for SIEM integration.
- **Threat Hunting** (`hunting_service.py`): Query-based hunting across historical analysis data.
- **Intel Enricher** (`intel_enricher.py`): VirusTotal and AbuseIPDB IOC reputation enrichment.
- **Kubernetes Job Manager** (`kubernetes_job_manager.py`): Enterprise sandbox orchestration via K8s Jobs.

---

## [1.0.0] — 2026-05-26

### Added — Core Platform

#### Metadata Persistence
- `upload.py` computes `sha256`, `md5`, `size`, and `entropy` synchronously via thread pool before MongoDB insertion.
- `file_utils.py` saves original filename alongside UUID path.
- `job_model.py` tracks metadata fields at root document level.

#### Telemetry Pipeline & Local Sandbox
- `sandbox/local_sandbox.py`: Isolated execution with temporary directory, `sys.path` restriction, and `sys.addaudithook` monitoring.
- Telemetry event schema standardized (`type`, `severity`, `timestamp`, `data`).
- WebSocket streaming via Redis PubSub to frontend.
- Real-time auto-scrolling terminal UI with severity-based color coding (High = Red, Medium = Orange, Info = Blue).

#### IOC Extraction
- `string_extractor.py`: Aggressive filtering of Windows file paths and common file extensions.
- `ioc_pipeline.py`: Strict type checking (`DOMAIN`, `URL`, `IP`, `HASH`, `command`).
- Network IOCs sourced exclusively from `SOCKET_CONNECT` and `DNS_QUERY` runtime hooks.

#### Risk Engine Grounding
- `ai_correlator.py` grounded to structured evidence only (no hallucination).
- `mitre_mapper.py` relies on deterministic `PROCESS_CREATE` telemetry for technique mapping.
- Persistence mapped only when `FILE_WRITE` directly references `startup` or `run` paths.

#### Validation & Documentation
- 4 sample scripts in `tests/samples/`: benign hello, file writer, PowerShell downloader, ransomware simulator.
- Runtime pipeline documentation with honest security limitation disclosures.
