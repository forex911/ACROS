"""
YARA Score Modifier
===================
Translates YARA rule matches into direct risk score modifiers.
Uses rule metadata (meta.category, tags) to determine the modifier weight.
Falls back to rule name heuristics when metadata is absent.
"""

from typing import List, Dict, Tuple

# Category → score modifier (use the highest single match, not cumulative)
YARA_CATEGORY_SCORES = {
    "ransomware": 50,
    "apt": 40,
    "known_family": 25,
    "trojan": 25,
    "rat": 25,
    "backdoor": 25,
    "worm": 25,
    "exploit": 30,
    "generic": 15,
    "suspicious": 15,
    "packer": 10,
    "miner": 20,
}

# Keywords in rule names used as fallback classification
_NAME_KEYWORDS = {
    "ransom": "ransomware",
    "wannacry": "ransomware",
    "lockbit": "ransomware",
    "ryuk": "ransomware",
    "conti": "ransomware",
    "blackcat": "ransomware",
    "apt": "apt",
    "lazarus": "apt",
    "cozy": "apt",
    "fancy": "apt",
    "turla": "apt",
    "emotet": "known_family",
    "trickbot": "known_family",
    "cobalt": "known_family",
    "metasploit": "known_family",
    "mimikatz": "known_family",
    "njrat": "rat",
    "darkcomet": "rat",
    "quasar": "rat",
    "asyncrat": "rat",
    "trojan": "trojan",
    "backdoor": "backdoor",
    "exploit": "exploit",
    "miner": "miner",
    "packed": "packer",
    "upx": "packer",
    "suspicious": "suspicious",
    "generic": "generic",
}


def _classify_rule(match: Dict) -> str:
    """Determine the category of a YARA match from metadata or name."""
    # 1. Check meta.category (highest fidelity)
    meta = match.get("meta", {})
    if isinstance(meta, dict):
        cat = meta.get("category", "").lower()
        if cat in YARA_CATEGORY_SCORES:
            return cat

    # 2. Check tags
    tags = match.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in YARA_CATEGORY_SCORES:
                return tag_lower

    # 3. Fallback: keyword match on rule name
    rule_name = match.get("rule", "").lower()
    for keyword, category in _NAME_KEYWORDS.items():
        if keyword in rule_name:
            return category

    return "generic"


def score_yara_matches(matches: List[Dict]) -> Tuple[int, List[str]]:
    """
    Score YARA matches. Uses cumulative scoring with diminishing returns:
    - 1st match: full score
    - 2nd match: 50% of its score
    - 3rd+ match: 25% of its score
    Cap is 50 points total.
    
    Returns:
        (modifier, reasoning): points to add to the final score.
    """
    if not matches:
        return 0, []

    reasoning = []
    
    # Extract categories and base scores for all matches
    match_scores = []
    for match in matches:
        category = _classify_rule(match)
        score = YARA_CATEGORY_SCORES.get(category, 15)
        rule_name = match.get("rule", "unknown")
        match_scores.append({"rule": rule_name, "category": category, "base_score": score})
        
    # Sort matches by base score (descending) so highest scores are counted first
    match_scores.sort(key=lambda x: x["base_score"], reverse=True)
    
    total_score = 0
    for i, match in enumerate(match_scores):
        if i == 0:
            weight = 1.0
        elif i == 1:
            weight = 0.50
        else:
            weight = 0.25
            
        effective_score = int(match["base_score"] * weight)
        total_score += effective_score
        
        reasoning.append(
            f"YARA: {match['rule']} [{match['category']}] (base {match['base_score']}, weight {weight:.2f}) → +{effective_score}"
        )
        
    # Cap total YARA modifier at 50
    if total_score > 50:
        reasoning.append(f"YARA: Total score {total_score} capped at 50")
        total_score = 50
        
    return total_score, reasoning
