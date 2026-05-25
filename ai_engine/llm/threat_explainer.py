from transformers import pipeline
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ThreatExplainer:
    """
    Uses a small local LLM (e.g., DistilBERT or similar Seq2Seq/CausalLM) to map 
    extracted behavioral anomalies to MITRE ATT&CK tactics and generate human-readable summaries.
    """
    def __init__(self, use_dummy: bool = True):
        self.use_dummy = use_dummy
        self.generator = None
        
        if not self.use_dummy:
            try:
                # Use a small fast model suitable for CPU/edge inference if GPU isn't guaranteed
                self.generator = pipeline('text2text-generation', model='google/flan-t5-small')
            except Exception as e:
                logger.error(f"Failed to load HuggingFace pipeline: {e}")
                self.use_dummy = True

    def generate_explanation(self, risk_score: float, suspicious_events: List[Dict[str, Any]]) -> str:
        if not suspicious_events:
            return "No suspicious behavior detected during execution."

        event_summaries = []
        for e in suspicious_events[:5]: # Limit to top 5 for prompt size
            cat = e.get("event", {}).get("category", "unknown")
            event_summaries.append(f"- {cat} anomaly detected.")
            
        context = "\n".join(event_summaries)
        
        if self.use_dummy or not self.generator:
            return self._dummy_explanation(risk_score, context)
            
        prompt = (
            f"Analyze the following malware sandbox behavior with a risk score of {risk_score}/100. "
            f"Map it to likely MITRE ATT&CK techniques and summarize the threat.\n"
            f"Behaviors:\n{context}\nSummary:"
        )
        
        try:
            result = self.generator(prompt, max_length=150, num_return_sequences=1)
            return result[0]['generated_text']
        except Exception as e:
            logger.error(f"Text generation failed: {e}")
            return self._dummy_explanation(risk_score, context)

    def _dummy_explanation(self, risk_score: float, context: str) -> str:
        explanation = f"The artifact exhibits a risk score of {risk_score}/100. "
        if risk_score > 75:
            explanation += "This is highly indicative of malicious activity. "
            explanation += "Observed behaviors map to potential Execution (TA0002) and Persistence (TA0003) tactics."
        elif risk_score > 40:
            explanation += "The artifact shows suspicious, but not conclusively malicious behavior."
        else:
            explanation += "The artifact appears benign based on dynamic analysis."
            
        return explanation
