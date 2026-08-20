# ACROS — Analysis Pipeline Execution Flow

## Overview

Every uploaded malware sample passes through the following pipeline of composable stages. Each stage reads from and writes to a shared `PipelineContext` object.

## Pipeline Architecture

```mermaid
graph TD
    Upload["Upload API<br/>/api/upload"]
    S1["1. Static Analysis<br/>Hash, PE, Python, Strings"]
    S2["2. Sandbox Execution<br/>Orchestrate sandbox, collect telemetry"]
    S3["3. Deobfuscation<br/>Decode obfuscated commands/strings"]
    S4["4. Artifact Collection<br/>Extract dropped files, archives"]
    S5["5. Correlation Analysis<br/>IOC, MITRE, YARA, Capabilities,<br/>Behavior, Threat Classification"]
    S6["6. Risk Scoring<br/>EvidenceEnvelope → RiskEngineV2"]
    S7["7. Graph Ingestion<br/>Neo4j ingestion + graph-assisted scoring"]
    S8["8. Report Finalization<br/>Compile report, save to MongoDB"]
    FE["Frontend Dashboard"]

    Upload --> S1
    S1 --> S2
    S2 --> S3
    S3 --> S4
    S4 --> S5
    S5 --> S6
    S6 --> S7
    S7 --> S8
    S8 --> FE
```

## Stage Details

### 1. Static Analysis (`StaticAnalysisStage`)
- **Input**: `context.local_path`, `context.filename`
- **Output**: `context.static_results` (hash, PE, Python, strings)
- Runs hash analysis, string extraction, and format-specific analysis (PE or Python)

### 2. Sandbox Execution (`SandboxExecutionStage`)
- **Input**: `context.job_id`, `context.local_path`
- **Output**: `context.telemetry_events`
- Orchestrates the sandbox (mock/firecracker) and collects runtime telemetry events

### 3. Deobfuscation (`DeobfuscationStage`)
- **Input**: `context.telemetry_events`, `context.static_results`
- **Output**: `context.deobfuscation_report`, modified events with decoded fields
- Strips encoding layers (base64, hex, URL-encoding, PowerShell)

### 4. Artifact Collection (`ArtifactCollectionStage`)
- **Input**: `context.telemetry_events`, workspace directory
- **Output**: `context.artifact_report`
- Extracts dropped files, classifies artifacts, expands archives recursively

### 5. Correlation Analysis (`CorrelationStage`)
- **Input**: `context.static_results`, `context.telemetry_events`
- **Output**: `context.iocs`, `context.mitre_mappings`, `context.yara_matches`, `context.capabilities`, `context.behavior_chains`, `context.threat`, `context.impact`
- Combines six sub-engines: IOC pipeline, MITRE mapper, YARA scanner, Capability engine, Behavior engine, Threat classifier

### 6. Risk Scoring (`RiskScoringStage`)
- **Input**: All correlation outputs
- **Output**: `context.envelope`, `context.risk_assessment`
- Builds the `EvidenceEnvelope`, runs `RiskEngineV2` (6-layer weighted scoring), propagates child artifact risk

### 7. Graph Ingestion (`GraphIngestionStage`)
- **Input**: All telemetry, IOCs, MITRE, YARA, artifacts
- **Output**: Updated `context.risk_assessment` (with graph bonus), `context.attack_timeline`
- Ingests everything into Neo4j, runs graph-assisted correlation scoring, re-scores if graph bonus applies

### 8. Report Finalization (`ReportFinalizationStage`)
- **Input**: All context data
- **Output**: `context.report`, saved to MongoDB
- Generates the analyst report, persists to MongoDB, emits metrics, broadcasts completion

## Data Flow Diagram

```mermaid
graph LR
    subgraph Evidence Sources
        PE["PE Analysis"]
        STR["String Extraction"]
        TEL["Telemetry Events"]
        IOC["IOC Pipeline"]
        MITRE["MITRE Mapper"]
        YARA["YARA Scanner"]
        CAP["Capability Engine"]
        BEH["Behavior Engine"]
        GRAPH["Graph Scorer"]
    end

    subgraph Unified Container
        ENV["EvidenceEnvelope"]
    end

    subgraph Scoring
        RE["RiskEngineV2<br/>6-Layer Weighted"]
        SC["ScoreContributors"]
    end

    PE --> ENV
    STR --> ENV
    TEL --> ENV
    IOC --> ENV
    MITRE --> ENV
    YARA --> ENV
    CAP --> ENV
    BEH --> ENV
    GRAPH --> ENV
    ENV --> RE
    RE --> SC
```

## Key Design Principles

1. **Single Evidence Container**: All evidence flows through `EvidenceEnvelope` — no evidence source is accidentally ignored
2. **Composable Stages**: Each stage implements `PipelineStage` ABC — can be added, removed, or reordered
3. **Non-Fatal Failures**: Each stage catches exceptions internally — a Neo4j outage won't crash the analysis
4. **Graph as Evidence Provider**: The graph scorer produces `GraphEvidence` that feeds back into the envelope, not a side-channel score
5. **Explainable Scoring**: Every point in the final score traces to a `ScoreContributor` with source, reason, and points
