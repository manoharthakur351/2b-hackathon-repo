import os
import pandas as pd


def load_flow_data(file_path="output/flow_features.csv"):
    """
    Load generated flow features.
    """
    if os.path.exists(file_path):
        return pd.read_csv(file_path)
    return pd.DataFrame()


def generate_report(flow_df, prediction_csv="output/predictions.csv"):
    """
    Generate summary statistics across flows and predictions.
    """
    if flow_df.empty:
        return {"Status": "No flow data available."}

    report = {
        "Total Flows": len(flow_df),
        "Total Packets": int(flow_df["Packet_Count"].sum()) if "Packet_Count" in flow_df else 0,
        "Total Bytes": int(flow_df["Total_Bytes"].sum()) if "Total_Bytes" in flow_df else 0,
        "Average Packet Size": round(flow_df["Average_Packet_Size"].mean(), 2) if "Average_Packet_Size" in flow_df else 0,
        "Average Flow Duration": round(flow_df["Flow_Duration"].mean(), 4) if "Flow_Duration" in flow_df else 0,
        "Max Domain Entropy": round(flow_df["Domain_Entropy"].max(), 4) if "Domain_Entropy" in flow_df else 0.0,
        "Unique SNIs": flow_df["SNI"].replace("", pd.NA).dropna().nunique() if "SNI" in flow_df else 0,
        "Unique JA3 Hashes": flow_df["JA3_Hash"].replace("", pd.NA).dropna().nunique() if "JA3_Hash" in flow_df else 0
    }

    if os.path.exists(prediction_csv):
        pred_df = pd.read_csv(prediction_csv)
        if "Prediction" in pred_df:
            counts = pred_df["Prediction"].value_counts().to_dict()
            report["Normal Flows"] = counts.get("Normal", 0)
            report["Suspicious Flows"] = counts.get("Suspicious", 0)

    return report


def save_report(report, report_path="output/report.txt"):
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as file:
        file.write("=" * 50 + "\n")
        file.write("TLSProfiler Behavioral Analysis Report\n")
        file.write("=" * 50 + "\n\n")
        for key, value in report.items():
            file.write(f"{key:<25}: {value}\n")
    return report_path


def display_report(report):
    print("=" * 50)
    print("TLSProfiler Behavioral Analysis Report")
    print("=" * 50)
    for key, value in report.items():
        print(f"{key:<25}: {value}")


def process_report():
    flow_df = load_flow_data()
    report = generate_report(flow_df)
    report_path = save_report(report)
    display_report(report)
    return report


def main():
    try:
        process_report()
    except Exception as error:
        print(f"Unexpected Error: {error}")


if __name__ == "__main__":
    main()