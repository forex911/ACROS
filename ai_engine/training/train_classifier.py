import os
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_synthetic_data(num_samples=1000):
    """
    Generates synthetic training data for the ACROS AI classifier.
    Features: [proc_cnt, net_cnt, fw_cnt, cap_cnt]
    """
    np.random.seed(42)
    X = []
    y = []

    # Generate Benign Samples
    for _ in range(num_samples // 2):
        proc_cnt = np.random.randint(0, 3)
        net_cnt = np.random.randint(0, 2)
        fw_cnt = np.random.randint(0, 3)
        cap_cnt = 0
        X.append([proc_cnt, net_cnt, fw_cnt, cap_cnt])
        y.append(0)

    # Generate Malicious Samples (Obvious)
    for _ in range(num_samples // 4):
        proc_cnt = np.random.randint(2, 10)
        net_cnt = np.random.randint(2, 20)
        fw_cnt = np.random.randint(2, 15)
        cap_cnt = np.random.randint(1, 5)
        X.append([proc_cnt, net_cnt, fw_cnt, cap_cnt])
        y.append(1)

    # Generate Malicious Samples (Obfuscated/Evasive - high telemetry, no mapped capabilities)
    for _ in range(num_samples // 4):
        proc_cnt = np.random.randint(3, 15)
        net_cnt = np.random.randint(5, 50)
        fw_cnt = np.random.randint(1, 5)
        cap_cnt = 0 # Evaded regex rules
        X.append([proc_cnt, net_cnt, fw_cnt, cap_cnt])
        y.append(1)

    return np.array(X), np.array(y)

def train_and_save():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_dir = os.path.join(base_dir, 'models')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'malware_classifier.pkl')

    logger.info("Generating synthetic dataset for 4 features...")
    X, y = generate_synthetic_data(5000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info("Training XGBoost Classifier...")
    model = xgb.XGBClassifier(
        n_estimators=100, 
        max_depth=4, 
        learning_rate=0.1, 
        use_label_encoder=False, 
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    logger.info(f"Model trained with accuracy: {acc * 100:.2f}%")

    model.save_model(model_path)
    logger.info(f"Successfully saved functional XGBoost model to {model_path}")

if __name__ == "__main__":
    train_and_save()
