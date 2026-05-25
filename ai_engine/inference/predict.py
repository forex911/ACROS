import xgboost as xgb
import numpy as np
import os
import logging

logger = logging.getLogger(__name__)

class MalwareClassifier:
    """
    Loads a pre-trained XGBoost model to classify extracted behavioral features.
    """
    def __init__(self, model_path: str = None):
        if model_path is None:
            # Default to the models directory
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(base_dir, 'models', 'malware_classifier.pkl')
            
        self.model_path = model_path
        self.model = xgb.XGBClassifier()
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(self.model_path) and os.path.getsize(self.model_path) > 0:
                self.model.load_model(self.model_path)
                logger.info(f"Loaded classifier from {self.model_path}")
            else:
                logger.warning("Model file not found or empty. Running in dummy mode.")
                self.model = None
        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")
            self.model = None

    def predict_risk(self, feature_vector: np.ndarray) -> dict:
        """
        Returns a risk score and classification label based on behavioral features.
        """
        # Ensure 2D array
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
            
        if self.model:
            # Real prediction
            probs = self.model.predict_proba(feature_vector)[0]
            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            # Dummy logic based on feature heuristics (e.g. suspicious flags index 3)
            suspicious_score = feature_vector[0][3] * 10
            malicious_prob = min(0.99, 0.1 + suspicious_score)
            
        is_malicious = malicious_prob > 0.75
        
        return {
            "risk_score": round(malicious_prob * 100, 2),
            "is_malicious": is_malicious,
            "label": "malicious" if is_malicious else "benign",
            "confidence": round(abs(malicious_prob - 0.5) * 2 * 100, 2)
        }
