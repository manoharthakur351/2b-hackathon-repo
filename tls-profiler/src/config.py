import os

# ---------------------------------------------------
# Path Configurations
# ---------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
MODELS_DIR = os.path.join(BASE_DIR, "models")

SSLBL_JA3_CSV = os.path.join(DATASET_DIR, "ja3_blacklist.csv")
UNSW_NB15_CSV = os.path.join(DATASET_DIR, "UNSW-NB15_1.csv")
SYNTHESIZED_TRAIN_CSV = os.path.join(DATASET_DIR, "train_synthesized.csv")
MODEL_PKL = os.path.join(MODELS_DIR, "random_forest_model.pkl")
ENCODER_PKL = os.path.join(MODELS_DIR, "label_encoder.pkl")
CONTRACT_PKL = os.path.join(MODELS_DIR, "feature_contract.pkl")

# ---------------------------------------------------
# Canonical Feature Contract (Target X Matrix Schema)
# ---------------------------------------------------
FEATURE_COLUMNS = [
    "Packet_Count",
    "Total_Bytes",
    "Average_Packet_Size",
    "Flow_Duration",
    "Packets_Sent",
    "Packets_Received",
    "Bytes_Sent",
    "Bytes_Received",
    "Byte_Ratio",
    "IAT_Mean",
    "IAT_Std",
    "Domain_Entropy",
    "Cipher_Suite_Count",
    "Extension_Count",
    "TLS Version"
]

# Numerical subset for imputation and scaling
NUMERIC_FEATURES = [
    "Packet_Count",
    "Total_Bytes",
    "Average_Packet_Size",
    "Flow_Duration",
    "Packets_Sent",
    "Packets_Received",
    "Bytes_Sent",
    "Bytes_Received",
    "Byte_Ratio",
    "IAT_Mean",
    "IAT_Std",
    "Domain_Entropy",
    "Cipher_Suite_Count",
    "Extension_Count"
]

# ---------------------------------------------------
# Dataset Column Mapping Rules
# ---------------------------------------------------
UNSW_NB15_COLUMN_MAP = {
    "dur": "Flow_Duration",
    "spkts": "Packets_Sent",
    "dpkts": "Packets_Received",
    "sbytes": "Bytes_Sent",
    "dbytes": "Bytes_Received",
    "smean": "Average_Packet_Size",
    "Label": "Label",
    "label": "Label"
}

CTU13_COLUMN_MAP = {
    "Dur": "Flow_Duration",
    "TotPkts": "Packet_Count",
    "TotBytes": "Total_Bytes",
    "SrcBytes": "Bytes_Sent",
    "Label": "Label"
}
