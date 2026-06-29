"""
IOC Intelligence Scorer
=======================
Scores extracted IOCs based on their type and confidence level.
High-confidence runtime IOCs (like contacted C2 IPs) contribute
directly to the risk score.
"""

from typing import List, Dict, Tuple

# (ioc_type, confidence) → score
IOC_TYPE_SCORES = {
    # High confidence (runtime-confirmed)
    ("ip", "High"): 20,
    ("domain", "High"): 25,
    ("url", "High"): 15,
    ("command", "High"): 15,
    ("registry_key", "High"): 15,
    ("named_pipe", "High"): 20,
    ("filepath", "High"): 10,
    ("email", "High"): 10,
    ("sha256", "High"): 5,    # sample's own hash is always present
    ("md5", "High"): 5,

    # Medium confidence
    ("ip", "Medium"): 10,
    ("domain", "Medium"): 12,
    ("url", "Medium"): 8,
    ("command", "Medium"): 8,
    ("registry_key", "Medium"): 8,
    ("named_pipe", "Medium"): 10,
    ("filepath", "Medium"): 5,
    ("email", "Medium"): 5,
    ("sha256", "Medium"): 3,
    ("md5", "Medium"): 3,

    # Low confidence (static-only)
    ("ip", "Low"): 3,
    ("domain", "Low"): 3,
    ("url", "Low"): 2,
}

# Known suspicious filenames and paths that elevate scores
SUSPICIOUS_FILENAMES = {
    "mimikatz", "lazagne", "procdump", "psexec", "bloodhound",
    "rubeus", "seatbelt", "sharphound", "cobaltstrike",
}

SUSPICIOUS_PIPES = {
    "\\msagent_", "\\msse-", "\\postex_", "\\status_",
    "\\mypipe-f", "\\mypipe-h", "\\win_svc",
}


def score_iocs(iocs: List[Dict]) -> Tuple[int, List[str]]:
    """
    Score a list of IOCs from the IOC pipeline.
    Sums unique IOC scores and caps at 100.
    
    Returns:
        (score, reasoning): IOC risk score and human-readable reasoning.
    """
    if not iocs:
        return 0, []

    total = 0
    reasoning = []
    seen_values = set()

    # Exclude the sample's own hashes from scoring (they're always present)
    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        confidence = ioc.get("confidence", "Low")

        if not value or value in seen_values:
            continue
        seen_values.add(value)

        # Skip the sample's own hash (it's always extracted and not meaningful)
        if ioc_type in ("sha256", "md5") and "Static Analysis (Hash)" in ioc.get("source", ""):
            continue

        # Base score from type + confidence
        key = (ioc_type, confidence)
        base_score = IOC_TYPE_SCORES.get(key, 0)

        # Bonus: suspicious filenames
        if ioc_type == "filepath":
            val_lower = value.lower()
            if any(sus in val_lower for sus in SUSPICIOUS_FILENAMES):
                base_score += 15
                reasoning.append(f"IOC: Suspicious tool detected: {value[:60]} → +{base_score}")
                total += base_score
                continue

        # Bonus: suspicious named pipes
        if ioc_type == "named_pipe":
            val_lower = value.lower()
            if any(pipe in val_lower for pipe in SUSPICIOUS_PIPES):
                base_score += 10

        if base_score > 0:
            reasoning.append(f"IOC: {ioc_type}={value[:40]} [{confidence}] → +{base_score}")
            total += base_score

    capped = min(100, total)
    return capped, reasoning
