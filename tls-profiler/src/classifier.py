import os
import joblib
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

from config import (
    SYNTHESIZED_TRAIN_CSV, MODEL_PKL, ENCODER_PKL, CONTRACT_PKL,
    FEATURE_COLUMNS, NUMERIC_FEATURES
)

def load_synthesized_data(csv_path=SYNTHESIZED_TRAIN_CSV):
    """
    Load synthesized flow data for model training.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Synthesized dataset not found at {csv_path}. Run dataset_adapter.py first.")
    return pd.read_csv(csv_path)

def prepare_data(df):
    """
    Prepares dataset X and y strictly following the FEATURE_COLUMNS contract.
    """
    encoder = LabelEncoder()
    
    # Fit encoder on TLS Version
    df["TLS Version"] = df["TLS Version"].astype(str).fillna("Unknown")
    df["TLS_Version_Encoded"] = encoder.fit_transform(df["TLS Version"])

    # Ensure all numerical features are numeric
    for col in NUMERIC_FEATURES:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

    # Feature matrix X construction
    feature_cols = [c if c != "TLS Version" else "TLS_Version_Encoded" for c in FEATURE_COLUMNS]
    X = df[feature_cols]
    y = df["Label"].astype(int)

    return X, y, encoder, feature_cols

def train_and_evaluate(X, y):
    """
    Trains Random Forest classifier with stratified train/test split.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if len(np.unique(y)) > 1 else None
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("=" * 70)
    print("TLSProfiler - Model Training Evaluation")
    print("=" * 70)
    print(f"Accuracy Score: {accuracy_score(y_test, predictions):.4f}\n")
    print("Classification Report:")
    print(classification_report(y_test, predictions, target_names=["Benign (0)", "Malicious (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    print("=" * 70)

    return model

def save_artifacts(model, encoder, feature_cols):
    """
    Saves trained model, encoder, and feature contract pickles.
    """
    os.makedirs(os.path.dirname(MODEL_PKL), exist_ok=True)

    joblib.dump(model, MODEL_PKL)
    joblib.dump(encoder, ENCODER_PKL)
    joblib.dump(feature_cols, CONTRACT_PKL)

    print(f"[+] Model saved to: {MODEL_PKL}")
    print(f"[+] Encoder saved to: {ENCODER_PKL}")
    print(f"[+] Feature contract saved to: {CONTRACT_PKL}")

def main():
    df = load_synthesized_data()
    X, y, encoder, feature_cols = prepare_data(df)
    model = train_and_evaluate(X, y)
    save_artifacts(model, encoder, feature_cols)

if __name__ == "__main__":
    main()