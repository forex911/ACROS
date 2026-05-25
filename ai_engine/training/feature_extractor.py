import numpy as np
from typing import List, Dict, Any

class FeatureExtractor:
    """
    Extracts numerical and categorical features from normalized telemetry 
    to be fed into the XGBoost behavioral classification model.
    """
    def __init__(self):
        # Define the expected feature vector size
        self.feature_dim = 128
        
    def extract_features(self, normalized_events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Converts a sequence of events into a fixed-size feature vector.
        In a real scenario, this uses TF-IDF, CountVectorizer, or a pre-trained embedding model.
        """
        if not normalized_events:
            return np.zeros(self.feature_dim)
            
        vector = np.zeros(self.feature_dim)
        
        # Simple heuristic feature extraction for demonstration
        process_count = 0
        network_count = 0
        file_count = 0
        suspicious_flags = 0
        
        for event in normalized_events:
            category = event.get("event", {}).get("category", "")
            
            if category == "process":
                process_count += 1
                if "suspicious" in event.get("event", {}).get("type", []):
                    suspicious_flags += 1
            elif category == "network":
                network_count += 1
            elif category == "file_system":
                file_count += 1
                if event.get("details", {}).get("suspicious", False):
                    suspicious_flags += 1
                    
        # Map counts to specific indices
        vector[0] = process_count
        vector[1] = network_count
        vector[2] = file_count
        vector[3] = suspicious_flags
        
        # Add some non-linear interactions
        vector[4] = process_count * suspicious_flags
        vector[5] = network_count * file_count
        
        # Normalize the vector
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
            
        return vector

