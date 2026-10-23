import sys
import os
import joblib
import pandas as pd
import numpy as np

# Ensure sys.path includes both current module directory and project root
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from src.config import MODEL_PKL, ENCODER_PKL, CONTRACT_PKL, FEATURE_COLUMNS, NUMERIC_FEATURES
except ModuleNotFoundError:
    from config import MODEL_PKL, ENCODER_PKL, CONTRACT_PKL, FEATURE_COLUMNS, NUMERIC_FEATURES

def load_model_artifacts():
    """
    Loads trained model, label encoder, and feature contract.
    """
    model = joblib.load(MODEL_PKL)
    encoder = joblib.load(ENCODER_PKL)
    
    if os.path.exists(CONTRACT_PKL):
        feature_cols = joblib.load(CONTRACT_PKL)
    else:
        feature_cols = [c if c != "TLS Version" else "TLS_Version_Encoded" for c in FEATURE_COLUMNS]

    return model, encoder, feature_cols

def prepare_inference_features(df, encoder, feature_cols):
    """
    Prepares input flow DataFrame to match the feature contract exact schema.
    """
    df = df.copy()

    # Fill missing values for numerical features
    for col in NUMERIC_FEATURES:
        if col not in df.columns:
            df[col] = 0.0
        else:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

    # Encode TLS Version
    if "TLS Version" in df.columns:
        df["TLS Version"] = df["TLS Version"].astype(str).fillna("Unknown")
        known_versions = set(encoder.classes_)
        df["TLS_Version_Encoded"] = df["TLS Version"].apply(
            lambda x: encoder.transform([x])[0] if x in known_versions else 0
        )
    else:
        df["TLS_Version_Encoded"] = 0

    # Align columns to feature_cols exact order
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_cols]
    return X

def predict_flows(flow_csv="output/flow_features.csv", output_csv="output/predictions.csv"):
    """
    Runs prediction on flow features and outputs predicted label & confidence scores.
    """
    if not os.path.exists(flow_csv):
        raise FileNotFoundError(f"Flow features not found at {flow_csv}")

    df = pd.read_csv(flow_csv)
    if df.empty:
        print("[!] Input flow features CSV is empty.")
        return df

    model, encoder, feature_cols = load_model_artifacts()
    X = prepare_inference_features(df, encoder, feature_cols)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    confidence = probabilities.max(axis=1)

    df["Predicted_Label"] = predictions
    df["Confidence"] = np.round(confidence, 4)
    df["Classification"] = df["Predicted_Label"].map({0: "Benign", 1: "Malicious"})
    df["Prediction"] = df["Predicted_Label"].map({0: "Normal", 1: "Suspicious"})

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"[+] Prediction completed. Saved to {output_csv}")
    return df

# Alias for app.py compatibility
predict_flow_behavior = predict_flows

def main():
    try:
        df = predict_flows()
        print(df[["Flow_ID", "Source IP", "Destination IP", "Predicted_Label", "Classification", "Prediction", "Confidence"]].head(10))
    except Exception as e:
        print(f"[!] Error during prediction: {e}")

if __name__ == "__main__":
    main()