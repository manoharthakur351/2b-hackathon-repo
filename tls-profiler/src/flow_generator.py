import os
import numpy as np
import pandas as pd


def load_tls_data(file_path="output/tls_features.csv"):
    """
    Load TLS packet data from CSV.
    """
    return pd.read_csv(file_path)


def first_non_empty(series):
    for val in series:
        if pd.notna(val) and str(val).strip() != "":
            return str(val)
    return ""


def generate_flow_features(df):
    """
    Group packets into bidirectional network flows, compute flow statistics, and tag packets with Flow_ID.
    """
    if df.empty:
        return pd.DataFrame(), df

    df = df.copy()
    # Ensure clean timestamp sorting
    df = df.sort_values(by="Timestamp").reset_index(drop=True)
    df["Flow_ID"] = 0

    flows = []

    # Create canonical bidirectional flow key: (min_ip, max_ip, min_port, max_port, TLS Version)
    grouped = df.groupby(
        [
            df.apply(lambda r: tuple(sorted([str(r["Source IP"]), str(r["Destination IP"])])), axis=1),
            df.apply(lambda r: tuple(sorted([int(r["Source Port"]), int(r["Destination Port"])])), axis=1),
            "TLS Version"
        ]
    )

    flow_id = 1
    for (ip_pair, port_pair, tls_ver), group in grouped:
        df.loc[group.index, "Flow_ID"] = flow_id

        src_ip_orig = group.iloc[0]["Source IP"]
        dst_ip_orig = group.iloc[0]["Destination IP"]

        packet_count = len(group)
        total_bytes = int(group["Length"].sum())
        avg_pkt_size = round(float(group["Length"].mean()), 2)
        min_ts = float(group["Timestamp"].min())
        max_ts = float(group["Timestamp"].max())
        duration = round(max_ts - min_ts, 4)

        # Directional split based on initial packet direction
        sent_mask = group["Source IP"] == src_ip_orig
        bytes_sent = int(group[sent_mask]["Length"].sum())
        bytes_recv = int(group[~sent_mask]["Length"].sum())
        pkts_sent = int(sent_mask.sum())
        pkts_recv = int((~sent_mask).sum())
        byte_ratio = round(bytes_sent / (total_bytes + 1e-5), 4)

        # Inter-Arrival Time (IAT) calculation
        if packet_count > 1:
            timestamps = group["Timestamp"].values
            iats = np.diff(timestamps)
            iat_mean = round(float(np.mean(iats)), 6)
            iat_std = round(float(np.std(iats)), 6)
        else:
            iat_mean = 0.0
            iat_std = 0.0

        sni = first_non_empty(group.get("SNI", pd.Series()))
        ja3_h = first_non_empty(group.get("JA3_Hash", pd.Series()))
        ja3s_h = first_non_empty(group.get("JA3S_Hash", pd.Series()))

        domain_entropy = float(group.get("Domain_Entropy", pd.Series([0.0])).max())
        ciphers_cnt = int(group.get("Cipher_Suite_Count", pd.Series([0])).max())
        ext_cnt = int(group.get("Extension_Count", pd.Series([0])).max())

        flows.append({
            "Flow_ID": flow_id,
            "Source IP": src_ip_orig,
            "Destination IP": dst_ip_orig,
            "Source Port": port_pair[0],
            "Destination Port": port_pair[1],
            "TLS Version": tls_ver,
            "Packet_Count": packet_count,
            "Total_Bytes": total_bytes,
            "Average_Packet_Size": avg_pkt_size,
            "Flow_Duration": duration,
            "Packets_Sent": pkts_sent,
            "Packets_Received": pkts_recv,
            "Bytes_Sent": bytes_sent,
            "Bytes_Received": bytes_recv,
            "Byte_Ratio": byte_ratio,
            "IAT_Mean": iat_mean,
            "IAT_Std": iat_std,
            "SNI": sni,
            "Domain_Entropy": domain_entropy,
            "JA3_Hash": ja3_h,
            "JA3S_Hash": ja3s_h,
            "Cipher_Suite_Count": ciphers_cnt,
            "Extension_Count": ext_cnt
        })
        flow_id += 1

    flow_df = pd.DataFrame(flows)
    return flow_df, df


def save_flow_features(flow_df, output_file="output/flow_features.csv"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    flow_df.to_csv(output_file, index=False)
    return output_file


def process_flow_features(tls_csv="output/tls_features.csv", output_csv="output/flow_features.csv"):
    """
    Direct Python function interface for Streamlit or scripts.
    """
    tls_df = load_tls_data(tls_csv)
    flow_df, tls_df_tagged = generate_flow_features(tls_df)
    save_flow_features(flow_df, output_csv)
    # Save updated tls_features with Flow_ID column
    if not tls_df_tagged.empty:
        tls_df_tagged.to_csv(tls_csv, index=False)
    return flow_df, tls_df_tagged


def display_flow_summary(flow_df):
    print("=" * 80)
    print("TLSProfiler - Flow Features Summary")
    print("=" * 80)
    print(f"Total Flows: {len(flow_df)}\n")
    if not flow_df.empty:
        cols = ["Flow_ID", "Source IP", "Destination IP", "Packet_Count", "Total_Bytes", "Flow_Duration", "Domain_Entropy"]
        c_disp = [c for c in cols if c in flow_df.columns]
        print(flow_df[c_disp].head(10).to_string(index=False))


def main():
    try:
        flow_df, _ = process_flow_features()
        display_flow_summary(flow_df)
        print("\nFlow features saved to: output/flow_features.csv")
    except FileNotFoundError:
        print("Error: output/tls_features.csv not found.")
    except Exception as error:
        print(f"Unexpected Error: {error}")


if __name__ == "__main__":
    main()
