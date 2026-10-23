import sys
import os
import pandas as pd
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from src.config import (
        CAPTURES_DIR, DATASET_DIR, UNSW_NB15_CSV, SSLBL_JA3_CSV, SYNTHESIZED_TRAIN_CSV,
        FEATURE_COLUMNS, NUMERIC_FEATURES, UNSW_NB15_COLUMN_MAP
    )
    from src.pcap_parser import parse_pcap
    from src.tls_features import extract_tls_features
    from src.flow_generator import generate_flow_features
except ModuleNotFoundError:
    from config import (
        CAPTURES_DIR, DATASET_DIR, UNSW_NB15_CSV, SSLBL_JA3_CSV, SYNTHESIZED_TRAIN_CSV,
        FEATURE_COLUMNS, NUMERIC_FEATURES, UNSW_NB15_COLUMN_MAP
    )
    from pcap_parser import parse_pcap
    from tls_features import extract_tls_features
    from flow_generator import generate_flow_features

class GeneralizedDataSynthesizer:
    def __init__(self, ja3_blacklist_csv=SSLBL_JA3_CSV):
        self.ja3_blacklist = self._load_ja3_blacklist(ja3_blacklist_csv)

    def _load_ja3_blacklist(self, csv_path):
        if os.path.exists(csv_path):
            try:
                df = pd.read_csv(csv_path, comment='#', names=["ja3_md5", "first_seen", "last_seen", "threat"], on_bad_lines='skip')
                return set(df["ja3_md5"].dropna().astype(str).str.strip().str.lower())
            except Exception as e:
                print(f"[!] Could not read SSLBL blacklist: {e}")
        return set()

    def process_pcap(self, pcap_path, label_override=None):
        filename = os.path.basename(pcap_path).lower()
        if label_override is not None:
            label = label_override
        elif any(k in filename for k in ["malware", "rat", "traffic-analysis", "exercise", "botnet", "attack"]):
            label = 1
        else:
            label = 0

        print(f"[*] Processing PCAP: {filename} (Default Label: {label})...")
        try:
            packets, _ = parse_pcap(pcap_path)
            tls_data = extract_tls_features(packets)
            tls_df = pd.DataFrame(tls_data)
            flow_df, _ = generate_flow_features(tls_df)

            if flow_df.empty:
                print(f"[-] No flows extracted from {filename}")
                return pd.DataFrame()

            def get_flow_label(row):
                ja3_val = str(row.get("JA3_Hash", "")).strip().lower()
                if ja3_val and ja3_val in self.ja3_blacklist:
                    return 1
                return label

            flow_df["Label"] = flow_df.apply(get_flow_label, axis=1)
            
            for col in FEATURE_COLUMNS:
                if col not in flow_df.columns:
                    flow_df[col] = 0.0 if col in NUMERIC_FEATURES else "Unknown"

            flow_df["TLS Version"] = flow_df["TLS Version"].fillna("Unknown")
            return flow_df[FEATURE_COLUMNS + ["Label"]]
        except Exception as e:
            print(f"[!] Error processing PCAP {filename}: {e}")
            return pd.DataFrame()

    def process_pcap_directory(self, captures_dir=CAPTURES_DIR):
        all_flows = []
        if not os.path.exists(captures_dir):
            return pd.DataFrame()

        for fname in os.listdir(captures_dir):
            if fname.endswith(".pcap") or fname.endswith(".pcapng"):
                pcap_path = os.path.join(captures_dir, fname)
                df_flows = self.process_pcap(pcap_path)
                if not df_flows.empty:
                    all_flows.append(df_flows)

        if all_flows:
            combined_pcap_df = pd.concat(all_flows, ignore_index=True)
            print(f"[+] Combined PCAP flows count: {len(combined_pcap_df)}")
            return combined_pcap_df
        return pd.DataFrame()

    def process_csv_dataset(self, csv_path=UNSW_NB15_CSV, sample_size=30000):
        if not os.path.exists(csv_path):
            train_fallback = os.path.join(DATASET_DIR, "train.csv")
            if os.path.exists(train_fallback):
                csv_path = train_fallback
            else:
                print(f"[!] CSV dataset not found at {csv_path}")
                return pd.DataFrame()

        print(f"[*] Ingesting and adapting tabular dataset: {os.path.basename(csv_path)}...")
        try:
            df_raw = pd.read_csv(csv_path, nrows=sample_size)
            df = df_raw.rename(columns=UNSW_NB15_COLUMN_MAP)

            if "Packets_Sent" in df.columns and "Packets_Received" in df.columns:
                df["Packet_Count"] = df["Packets_Sent"] + df["Packets_Received"]
            elif "Packet_Count" not in df.columns:
                df["Packet_Count"] = 10

            if "Packets_Sent" not in df.columns and "Packet_Count" in df.columns:
                df["Packets_Sent"] = (df["Packet_Count"] // 2).clip(lower=1)
                df["Packets_Received"] = (df["Packet_Count"] - df["Packets_Sent"]).clip(lower=0)

            if "Bytes_Sent" in df.columns and "Bytes_Received" in df.columns:
                df["Total_Bytes"] = df["Bytes_Sent"] + df["Bytes_Received"]
            elif "Total_Bytes" not in df.columns:
                df["Total_Bytes"] = 1000

            if "Bytes_Sent" not in df.columns and "Total_Bytes" in df.columns:
                df["Bytes_Sent"] = (df["Total_Bytes"] // 2).clip(lower=0)
                df["Bytes_Received"] = (df["Total_Bytes"] - df["Bytes_Sent"]).clip(lower=0)

            if "Bytes_Sent" in df.columns and "Total_Bytes" in df.columns:
                df["Byte_Ratio"] = np.round(df["Bytes_Sent"] / (df["Total_Bytes"] + 1e-5), 4)
            else:
                df["Byte_Ratio"] = 0.5

            if "Average_Packet_Size" not in df.columns:
                df["Average_Packet_Size"] = np.round(df["Total_Bytes"] / (df["Packet_Count"] + 1e-5), 2)

            if "IAT_Mean" not in df.columns and "Flow_Duration" in df.columns:
                df["IAT_Mean"] = np.round(df["Flow_Duration"] / (df["Packet_Count"] + 1e-5), 6)
            elif "IAT_Mean" not in df.columns:
                df["IAT_Mean"] = 0.0

            if "IAT_Std" not in df.columns: df["IAT_Std"] = 0.0
            if "Domain_Entropy" not in df.columns: df["Domain_Entropy"] = 0.0
            if "Cipher_Suite_Count" not in df.columns: df["Cipher_Suite_Count"] = 0
            if "Extension_Count" not in df.columns: df["Extension_Count"] = 0
            if "TLS Version" not in df.columns: df["TLS Version"] = "TLS 1.2"

            if "Label" in df.columns:
                if df["Label"].dtype == object or isinstance(df["Label"].iloc[0], str):
                    label_map = {"normal": 0, "benign": 0, "0": 0, "suspicious": 1, "malicious": 1, "attack": 1, "1": 1}
                    df["Label"] = df["Label"].astype(str).str.strip().str.lower().map(lambda x: label_map.get(x, 0)).astype(int)
                else:
                    df["Label"] = df["Label"].astype(int)
            else:
                df["Label"] = 0

            for col in FEATURE_COLUMNS:
                if col not in df.columns:
                    df[col] = 0.0 if col in NUMERIC_FEATURES else "Unknown"

            df["TLS Version"] = df["TLS Version"].fillna("TLS 1.2").astype(str)

            adapted_df = df[FEATURE_COLUMNS + ["Label"]]
            print(f"[+] Adapted {len(adapted_df)} records from CSV dataset.")
            return adapted_df
        except Exception as e:
            print(f"[!] Error adapting CSV dataset: {e}")
            return pd.DataFrame()

    def synthesize_all(self, output_csv=SYNTHESIZED_TRAIN_CSV):
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        
        pcap_df = self.process_pcap_directory()
        csv_df = self.process_csv_dataset()

        dfs_to_combine = [d for d in [pcap_df, csv_df] if not d.empty]
        if not dfs_to_combine:
            raise ValueError("No data could be processed from PCAPs or CSVs!")

        synthesized_df = pd.concat(dfs_to_combine, ignore_index=True)

        for num_col in NUMERIC_FEATURES:
            synthesized_df[num_col] = pd.to_numeric(synthesized_df[num_col], errors='coerce').fillna(0.0)

        synthesized_df.to_csv(output_csv, index=False)
        print("=" * 70)
        print(f"[+] Synthesized Dataset Successfully Created: {output_csv}")
        print(f" Total Rows: {len(synthesized_df)}")
        print(f" Malicious (1): {(synthesized_df['Label'] == 1).sum()}")
        print(f" Benign (0):    {(synthesized_df['Label'] == 0).sum()}")
        print("=" * 70)
        return synthesized_df

if __name__ == "__main__":
    synthesizer = GeneralizedDataSynthesizer()
    synthesizer.synthesize_all()
