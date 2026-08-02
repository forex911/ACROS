# Intelligence Layer

The Intelligence Layer is the core analytical engine that distinguishes Aegis-AI from conventional sandbox platforms. Located in `backend/app/analysis/`, it replaces legacy single-event scoring (e.g., `score += 10` for every `FILE_WRITE`) with a multi-stage pipeline that models attacker intent, capability, and behavior natively.

---

## Why the Intelligence Layer Exists

### The Problem with Event-Level Scoring

Traditional sandbox scoring assigns fixed point values to individual system events:

```
PROCESS_CREATE  → +10
FILE_WRITE      → +10
SOCKET_CONNECT  → +10
```

This approach fundamentally fails in two ways:

1. **Advanced malware scores too low**: A credential stealer that reads `Login Data`, reads `Cookies`, creates a `.zip`, and uploads it via a single `POST` request generates only 4 events — scoring 40/100 — despite being a fully functional infostealer.

2. **Benign software scores too high**: A legitimate installer that spawns 20 processes, writes 50 files, and makes 10 network connections for update checks generates 80 events — scoring 800 before normalization — despite being completely benign.

### The Intelligence Approach

Instead of counting events, the Intelligence Layer asks:
- **What can this payload do?** (Capabilities)
- **What attack pattern is it following?** (Behavior Chains)
- **What kind of malware is this?** (Threat Classification)
- **What is the real-world impact?** (CIA Assessment)
- **How confident are we?** (Evidence-Based Risk)

---

## Pipeline Architecture

```
Raw Telemetry + Static Analysis
         │
         ▼
┌─────────────────────┐
│  Capability Engine   │  Maps signals → attacker capabilities
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Behavior Engine     │  Sequences capabilities → attack chains
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Threat Classifier   │  Chains + capabilities → malware family
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Impact Engine       │  Capabilities → CIA impact levels
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Risk Engine         │  Weighted aggregation → final score
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Report Generator    │  All outputs → structured AnalystReport
└─────────────────────┘
```

---

## Stage 1: Capability Engine (`capability_engine.py`)

### Purpose
Converts raw telemetry events and static analysis findings into discrete attacker **capabilities**. A capability represents something the malware *can do* or *is doing*, not just a system event it generated.

### Capability Mapping Table

| Signal(s) | Capability | Severity | MITRE Mapping | Attack Goal |
|---|---|---|---|---|
| `eval()` + `base64` decode | Obfuscated Execution | High | T1027, T1059 | Defense Evasion |
| Browser `Login Data` access | Credential Access | Critical | T1555.003 | Credential Access |
| Cookie database access | Session Theft | Critical | T1539 | Credential Access |
| Discord `leveldb` access | Token Theft | Critical | T1528 | Credential Access |
| `wallet.dat` access | Cryptocurrency Theft | Critical | T1552 | Credential Access |
| Screenshot API usage | Screen Capture | Medium | T1113 | Collection |
| Webcam API usage | Webcam Capture | High | T1125 | Collection |
| ZIP archive creation | Data Staging | Medium | T1074 | Collection |
| `crontab` modification | Persistence | High | T1053.003 | Persistence |
| Registry autostart creation | Persistence | High | T1547.001 | Persistence |
| Anti-VM checks (VBox, VMware, QEMU) | Defense Evasion | High | T1497.001 | Defense Evasion |
| Anti-Debug checks (IsDebuggerPresent, ptrace) | Defense Evasion | High | T1497.001 | Defense Evasion |
| HTTP POST upload | Data Exfiltration | High | T1048 | Exfiltration |

### Output Model

```python
class Capability(BaseModel):
    capability: str          # e.g., "Credential Access"
    severity: str            # "Low" | "Medium" | "High" | "Critical"
    confidence: int          # 0–100
    evidence: List[str]      # ["Browser Login Data access"]
    mitre_mapping: List[str] # ["T1555.003"]
    attack_goal: str         # "Credential Access"
```

### Evidence Aggregation
When multiple telemetry events support the same capability, the engine **aggregates evidence** rather than creating duplicate capabilities. For example, if the sandbox observes both `Login Data` reads and `Key3.db` reads, a single `Credential Access` capability is emitted with both evidence strings attached.

---

## Stage 2: Behavior Engine (`behavior_engine.py`)

### Purpose
Analyzes the array of detected capabilities to find **sequences** or **clusters** that indicate a broader attack pattern. Individual capabilities in isolation may be benign — it is the *combination* that reveals malicious intent.

### Chain Detection Rules

| Required Capabilities | Chain Name | Severity | Attack Goal |
|---|---|---|---|
| (Credential Access OR Session Theft) + Data Staging + Data Exfiltration | **Infostealer Chain** | Critical | Information Theft |
| Screen Capture + Data Staging + Data Exfiltration | **Surveillance Chain** | High | Espionage |
| Persistence + Data Exfiltration | **RAT Chain** | Critical | Command & Control |
| Data Staging + Obfuscated Execution | **Dropper Chain** | High | Execution |

### Output Model

```python
class BehaviorChain(BaseModel):
    chain_name: str     # e.g., "Infostealer Chain"
    severity: str       # "Low" | "Medium" | "High" | "Critical"
    confidence: int     # 0–100
    evidence: List[str] # Aggregated from all constituent capabilities
    attack_goal: str    # "Information Theft"
```

### Extensibility
New chains can be added by defining the required capability set and the resulting chain metadata. The engine is designed as a registry that iterates over all defined chain rules.

---

## Stage 3: Threat Classifier (`threat_classifier.py`)

### Purpose
Maps the combination of detected capabilities and behavior chains to a specific **malware family classification**. This provides analysts with an immediate, actionable label.

### Classification Priority (Highest to Lowest)

| Priority | Condition | Family |
|---|---|---|
| 1 | Infostealer Chain detected, OR (Credential Access + Data Exfiltration) | **Infostealer** |
| 2 | RAT Chain detected | **RAT** |
| 3 | Credential Access OR Session Theft OR Cryptocurrency Theft (without exfiltration chain) | **Credential Stealer** |
| 4 | Ransomware Chain detected OR Shadow Copy Deletion | **Ransomware** |
| 5 | Data Staging + Data Exfiltration (without credential access) | **Data Exfiltration Tool** |
| 6 | Dropper Chain detected | **Dropper** |
| 7 | Screen Capture OR Webcam Capture | **Spyware** |
| 8 | No matching patterns | **Unknown** |

### Supported Families

`Infostealer` · `Credential Stealer` · `RAT` · `Loader` · `Backdoor` · `Dropper` · `Spyware` · `Ransomware` · `Cryptominer` · `Data Exfiltration Tool` · `Unknown`

### Output Model

```python
class ThreatClassification(BaseModel):
    family: str         # e.g., "Infostealer"
    confidence: int     # 0–100
    evidence: List[str] # All evidence from capabilities + chains
```

---

## Stage 4: Impact Engine (`impact_engine.py`)

### Purpose
Calculates the maximum potential business impact of the payload across the **CIA triad** (Confidentiality, Integrity, Availability).

### Impact Mapping

| Capability / Chain | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Credential Access, Session Theft, Cryptocurrency Theft | **Critical** | — | — |
| Data Exfiltration, Screen Capture | **High** | — | — |
| Persistence, Obfuscated Execution | — | **Medium** | — |
| Ransomware Chain | — | **Critical** | **Critical** |

### Output Model

```python
class ImpactAssessment(BaseModel):
    confidentiality: str  # "Low" | "Medium" | "High" | "Critical"
    integrity: str        # "Low" | "Medium" | "High" | "Critical"
    availability: str     # "Low" | "Medium" | "High" | "Critical"
```

---

## Stage 5: Risk Engine (`risk_engine.py`)

### Purpose
Computes the definitive **risk score** (0–100) using a weighted formula that considers all upstream outputs. This is the engine that produces the final numeric verdict.

### Risk Formula

```
Final Risk Score =
    35% × Capability Risk
  + 25% × Behavior Risk
  + 20% × Threat Family Risk
  + 10% × ATT&CK Coverage
  + 10% × Confidence Modifier
```

### Component Scoring

| Component | Scoring Method |
|---|---|
| **Capability Risk** | Sum of per-capability weights: Critical = 25pts, High = 15pts, Medium = 10pts. Capped at 100. |
| **Behavior Risk** | 30pts per detected chain. Capped at 100. |
| **Threat Family Risk** | 100 if a known family is classified, 0 if Unknown. |
| **ATT&CK Coverage** | 10pts per unique tactic observed. Capped at 100. |
| **Confidence Modifier** | Scaled from the highest confidence value across all inputs (0–10pts). |

### Severity Bands

| Score Range | Severity |
|---|---|
| 0 – 29 | **LOW** |
| 30 – 59 | **MEDIUM** |
| 60 – 84 | **HIGH** |
| 85 – 100 | **CRITICAL** |

### Output Model

```python
class RiskAssessment(BaseModel):
    score: int                      # 0–100
    severity: str                   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: int                 # 0–100
    verdict: str                    # Threat family name or "Suspicious"/"Benign"
    score_breakdown: Dict[str, float]  # Per-component weighted contribution
    reasoning: List[str]            # Human-readable reasoning strings
```

### Example Score Breakdown

For a typical infostealer payload:

```json
{
  "score": 71,
  "severity": "HIGH",
  "confidence": 95,
  "verdict": "Infostealer",
  "score_breakdown": {
    "capability_risk": 22.75,
    "behavior_risk": 15.0,
    "threat_risk": 20.0,
    "mitre_risk": 4.0,
    "confidence_mod": 9.5
  }
}
```

---

## Stage 6: Report Generator (`report_generator.py`)

### Purpose
Compiles the outputs of all previous engines into a structured **AnalystReport** suitable for both automated consumption (API responses, SIEM ingestion) and human review (SOC dashboard rendering).

### Report Sections

| Section | Content |
|---|---|
| **Executive Summary** | Auto-generated paragraph summarizing severity, threat family, and key findings |
| **Technical Findings** | Detailed list of detected capabilities and behavior chains with evidence |
| **Threat Classification** | Family label, confidence score, and supporting evidence |
| **MITRE Coverage** | List of all observed MITRE ATT&CK technique IDs |
| **Impact Assessment** | CIA triad impact levels |
| **Recommended Actions** | Automated remediation suggestions based on detected impact |
| **Risk Assessment** | Complete score breakdown with reasoning |

### Output Model

```python
class AnalystReport(BaseModel):
    executive_summary: str
    technical_findings: List[str]
    threat_classification: ThreatClassification
    mitre_coverage: List[str]
    impact_assessment: ImpactAssessment
    recommended_actions: List[str]
    risk_assessment: RiskAssessment
```

---

## Example: Full Intelligence Pipeline Output

Given a payload that:
- Uses `eval()` with `base64` decoding
- Reads browser `Login Data`
- Creates a `.zip` archive
- Uploads via HTTP `POST`

The pipeline produces:

```json
{
  "executive_summary": "Analysis resulted in a HIGH risk score of 71/100. The payload exhibits strong indicators of being a Infostealer.",
  "technical_findings": [
    "Identified Infostealer Chain: requests.post() / HTTP POST upload, Browser Login Data access",
    "Identified Dropper Chain: eval() + base64 decode detected, ZIP archive creation",
    "Capability 'Credential Access': Browser Login Data access",
    "Capability 'Obfuscated Execution': eval() + base64 decode detected",
    "Capability 'Data Staging': ZIP archive creation",
    "Capability 'Data Exfiltration': requests.post() / HTTP POST upload"
  ],
  "threat_classification": {
    "family": "Infostealer",
    "confidence": 95,
    "evidence": [
      "Browser Login Data access",
      "requests.post() / HTTP POST upload",
      "eval() + base64 decode detected",
      "ZIP archive creation"
    ]
  },
  "mitre_coverage": ["T1027", "T1059", "T1555", "T1048"],
  "impact_assessment": {
    "confidentiality": "Critical",
    "integrity": "Medium",
    "availability": "Low"
  },
  "recommended_actions": [
    "Rotate potentially exposed credentials and tokens."
  ],
  "risk_assessment": {
    "score": 71,
    "severity": "HIGH",
    "confidence": 95,
    "verdict": "Infostealer",
    "score_breakdown": {
      "capability_risk": 22.75,
      "behavior_risk": 15.0,
      "threat_risk": 20.0,
      "mitre_risk": 4.0,
      "confidence_mod": 9.5
    },
    "reasoning": [
      "Threat classified as Infostealer",
      "Detected Infostealer Chain",
      "Detected Dropper Chain",
      "Exhibits Credential Access capability",
      "Exhibits Obfuscated Execution capability",
      "Exhibits Data Staging capability",
      "Exhibits Data Exfiltration capability"
    ]
  }
}
```
