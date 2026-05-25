from pydantic import BaseModel
from typing import List

class AnalysisModel(BaseModel):

    file_id: str

    filename: str

    sha256: str

    risk_score: int

    threat_level: str

    reasons: List[str]