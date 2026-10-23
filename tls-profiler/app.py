import os
import pandas as pd
import streamlit as st

# Direct module imports for performance and clean error handling
from src.pcap_parser import parse_pcap
from src.tls_features import extract_tls_features, save_to_csv as save_tls_csv
from src.flow_generator import generate_flow_features, save_flow_features
from src.predict import predict_flow_behavior
from src.report_generator import generate_report, save_report
from src.decider_agent.agent import InvestigationAgent
from src.decider_agent.bedrock_client import (
    BedrockConfigurationError,
    bedrock_explainer_from_environment,
)
from src.decider_agent.config import (
    DECIDER_CONFIDENCE_THRESHOLD,
    DECIDER_URL,
)
from src.decider_agent.decider_client import DeciderError, DeciderClient
from src.decider_agent.flow_batch import investigate_flows


# ---------------------------------------------------
# Page Configuration & Header
# ---------------------------------------------------

st.set_page_config(
    page_title="TLSProfiler - Encrypted Behavioral Profiling",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 TLSProfiler")
st.caption("Behavioral Profiling via Encrypted TLS Handshakes & Network Flow Dynamics")


# ---------------------------------------------------
# Sidebar & Upload Section
# ---------------------------------------------------

st.sidebar.header("📁 Capture File Input")
uploaded_file = st.sidebar.file_uploader(
    "Upload PCAP / PCAPNG File",
    type=["pcap", "pcapng"]
)

pcap_sample_option = st.sidebar.selectbox(
    "Or select a sample capture:",
    ["(None)", "reddit.pcap", "youtube.pcap", "2026-02-28-traffic-analysis-exercise.pcap"]
)

target_pcap = None

if uploaded_file:
    os.makedirs("captures", exist_ok=True)
    target_pcap = os.path.join("captures", uploaded_file.name)
    with open(target_pcap, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.sidebar.success(f"Uploaded: {uploaded_file.name}")
elif pcap_sample_option != "(None)":
    sample_path = os.path.join("captures", pcap_sample_option)
    if os.path.exists(sample_path):
        target_pcap = sample_path
        st.sidebar.info(f"Selected: {pcap_sample_option}")


# ---------------------------------------------------
# Pipeline Execution & Main Dashboard
# ---------------------------------------------------

if target_pcap:

    start_analysis = st.sidebar.button("🚀 Start Analysis", type="primary", use_container_width=True)

    if start_analysis or "analysis_done" in st.session_state:

        if start_analysis:
            os.makedirs("output", exist_ok=True)
            st.session_state.pop("per_flow_decider_results", None)
            st.session_state.pop("decider_selected_flow_ids", None)

            try:
                # Step 1: PCAP Parsing
                with st.spinner("📦 Parsing PCAP Packets..."):
                    packets, packet_df = parse_pcap(target_pcap, "output/packet_info.csv")

                # Step 2: TLS Feature Extraction & JA3 Fingerprinting
                with st.spinner("🔑 Extracting TLS Handshakes & JA3/JA3S Fingerprints..."):
                    tls_data = extract_tls_features(packets)
                    tls_df = save_tls_csv(tls_data, "output/tls_features.csv")

                # Step 3: Flow Feature Generation
                with st.spinner("🌐 Aggregating Network Flow Dynamics..."):
                    flow_df, _ = generate_flow_features(tls_df)
                    save_flow_features(flow_df, "output/flow_features.csv")

                # Step 4: AI Behavior Classification
                with st.spinner("🤖 Running Machine Learning Behavior Predictor..."):
                    prediction_df = predict_flow_behavior("output/flow_features.csv", "output/predictions.csv")

                # Step 5: Summary Report Generation
                with st.spinner("📄 Generating Analysis Report..."):
                    report = generate_report(flow_df, "output/predictions.csv")
                    save_report(report, "output/report.txt")

                st.session_state["analysis_done"] = True
                st.session_state["packet_df"] = packet_df
                st.session_state["tls_df"] = tls_df
                st.session_state["flow_df"] = flow_df
                st.session_state["prediction_df"] = prediction_df
                st.session_state["report"] = report

                st.success("✅ TLS Behavior Profiling Completed Successfully!")

            except Exception as e:
                st.error(f"❌ Processing Error: {str(e)}")
                st.stop()

        # Load data from session state
        packet_df = st.session_state.get("packet_df", pd.DataFrame())
        tls_df = st.session_state.get("tls_df", pd.DataFrame())
        flow_df = st.session_state.get("flow_df", pd.DataFrame())
        prediction_df = st.session_state.get("prediction_df", pd.DataFrame())
        report = st.session_state.get("report", {})

        # Top Executive Metric Summary Bar
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total IP Packets", f"{len(packet_df):,}")
        m2.metric("TLS Handshakes", f"{len(tls_df):,}")
        m3.metric("Network Flows", f"{len(flow_df):,}")
        
        suspicious_cnt = (prediction_df["Prediction"] == "Suspicious").sum() if "Prediction" in prediction_df else 0
        normal_cnt = (prediction_df["Prediction"] == "Normal").sum() if "Prediction" in prediction_df else 0
        
        m4.metric("Normal Flows", normal_cnt)
        m5.metric("Suspicious Alerts", suspicious_cnt, delta=f"{suspicious_cnt} Threats" if suspicious_cnt > 0 else "Clean", delta_color="inverse")

        st.divider()

        # Tabbed Dashboard View
        tab_pred, tab_ja3, tab_flow, tab_timeline, tab_packet, tab_report, tab_agent = st.tabs([
            "🤖 AI Behavior Predictions",
            "🔑 JA3 / JA3S & Domain Entropy",
            "🌐 Flow Dynamics",
            "⏱️ Flow Timelines & Packet Details",
            "📦 Packet Metadata",
            "📄 Summary Report",
            "🧭 Per-Flow Decider Investigation"
        ])

        # ---------------------------------------------------
        # TAB 1: AI Behavior Predictions
        # ---------------------------------------------------
        with tab_pred:
            st.header("🤖 Machine Learning Behavior Profiling")
            if not prediction_df.empty:

                col_p1, col_p2 = st.columns([2, 1])

                with col_p1:
                    st.subheader("Flow Predictions & Confidence Scores")
                    
                    # Custom background color for prediction status
                    display_df = prediction_df.copy()
                    cols_to_show = ["Flow_ID", "Source IP", "Destination IP", "TLS Version", "SNI", "Packet_Count", "Total_Bytes", "Domain_Entropy", "Prediction", "Confidence"]
                    cols_to_show = [c for c in cols_to_show if c in display_df.columns]

                    st.dataframe(
                        display_df[cols_to_show].style.background_gradient(subset=["Confidence"], cmap="YlGnBu"),
                        use_container_width=True
                    )

                with col_p2:
                    st.subheader("Classification Distribution")
                    pred_counts = prediction_df["Prediction"].value_counts()
                    st.bar_chart(pred_counts)

                    avg_conf = prediction_df["Confidence"].mean() if "Confidence" in prediction_df else 0.0
                    st.metric("Average Model Confidence", f"{avg_conf:.2f}%")

                if suspicious_cnt > 0:
                    st.warning(f"⚠️ Warning: Detected {suspicious_cnt} suspicious traffic flow(s). Inspect Domain Entropy & JA3 hashes for anomaly investigation.")

                st.download_button(
                    label="📥 Download Predictions CSV",
                    data=prediction_df.to_csv(index=False),
                    file_name="predictions.csv",
                    mime="text/csv",
                    key="dl_predictions"
                )

        # ---------------------------------------------------
        # TAB 2: JA3 / JA3S & Domain Entropy
        # ---------------------------------------------------
        with tab_ja3:
            st.header("🔑 TLS Handshake Fingerprints & DGA Entropy")

            if not tls_df.empty:
                c_j1, c_j2 = st.columns([3, 2])

                with c_j1:
                    st.subheader("Extracted JA3 & JA3S Hashes")
                    ja3_cols = ["Packet No", "Source IP", "Destination IP", "TLS Version", "Record Type", "SNI", "Domain_Entropy", "JA3_Hash", "JA3S_Hash"]
                    available_jcols = [c for c in ja3_cols if c in tls_df.columns]
                    st.dataframe(tls_df[available_jcols], use_container_width=True)

                with c_j2:
                    st.subheader("Domain Entropy Distribution (SNI)")
                    if "Domain_Entropy" in tls_df and tls_df["Domain_Entropy"].max() > 0:
                        st.scatter_chart(tls_df, x="SNI", y="Domain_Entropy")
                    else:
                        st.info("No SNI extension present in TLS ClientHello packets.")

                    st.subheader("Top JA3 Fingerprints")
                    if "JA3_Hash" in tls_df:
                        ja3_counts = tls_df[tls_df["JA3_Hash"] != ""]["JA3_Hash"].value_counts()
                        if not ja3_counts.empty:
                            st.dataframe(ja3_counts.reset_index().rename(columns={"index": "JA3 Hash", "count": "Count"}))
                        else:
                            st.info("No ClientHello JA3 fingerprints captured.")

                st.download_button(
                    label="📥 Download TLS & JA3 Features CSV",
                    data=tls_df.to_csv(index=False),
                    file_name="tls_features.csv",
                    mime="text/csv",
                    key="dl_tls"
                )

        # ---------------------------------------------------
        # TAB 3: Flow Dynamics
        # ---------------------------------------------------
        with tab_flow:
            st.header("🌐 Flow Dynamics & Connection Statistics")

            if not flow_df.empty:
                st.dataframe(flow_df, use_container_width=True)

                f1, f2 = st.columns(2)
                with f1:
                    st.subheader("Packets per Flow")
                    st.bar_chart(flow_df.set_index("Flow_ID")["Packet_Count"])

                with f2:
                    st.subheader("Total Bytes per Flow")
                    st.bar_chart(flow_df.set_index("Flow_ID")["Total_Bytes"])

                st.download_button(
                    label="📥 Download Flow Features CSV",
                    data=flow_df.to_csv(index=False),
                    file_name="flow_features.csv",
                    mime="text/csv",
                    key="dl_flow"
                )

        # ---------------------------------------------------
        # TAB 4: Flow Timelines & Packet Details
        # ---------------------------------------------------
        with tab_timeline:
            st.header("⏱️ Detailed Flow Inspection & Timed Packet Stream")

            if not flow_df.empty and not tls_df.empty:
                import numpy as np

                # Merge predictions into flow_df if available
                merged_flow = flow_df.copy()
                if "Prediction" in prediction_df:
                    merged_flow = merged_flow.merge(prediction_df[["Flow_ID", "Prediction", "Confidence"]], on="Flow_ID", how="left")

                # Build descriptive options for dropdown
                flow_options = []
                for _, row in merged_flow.iterrows():
                    fid = int(row["Flow_ID"])
                    src = f"{row['Source IP']}:{row['Source Port']}"
                    dst = f"{row['Destination IP']}:{row['Destination Port']}"
                    sni_val = str(row.get('SNI', '')).strip()
                    sni_str = f" | SNI: {sni_val}" if sni_val and sni_val != "nan" else ""
                    pred_str = f" | [{row.get('Prediction', 'Normal')}]"
                    ver = row.get("TLS Version", "TLS")
                    label = f"Flow #{fid}: {src} ↔ {dst} ({ver}){sni_str}{pred_str}"
                    flow_options.append((fid, label))

                selected_flow_tuple = st.selectbox(
                    "Select a Network Flow to Inspect Timed Packets:",
                    options=flow_options,
                    format_func=lambda x: x[1]
                )

                if selected_flow_tuple:
                    selected_fid = selected_flow_tuple[0]
                    flow_info = merged_flow[merged_flow["Flow_ID"] == selected_fid].iloc[0]

                    # Metric cards for selected flow
                    col_t1, col_t2, col_t3, col_t4 = st.columns(4)
                    col_t1.metric("Flow Duration", f"{flow_info['Flow_Duration']:.4f} s")
                    col_t2.metric("Total Packets", flow_info["Packet_Count"])
                    col_t3.metric("Bytes (Sent / Recv)", f"{int(flow_info.get('Bytes_Sent', 0)):,} / {int(flow_info.get('Bytes_Received', 0)):,}")
                    col_t4.metric("IAT Mean (Spacing)", f"{float(flow_info.get('IAT_Mean', 0.0)):.6f} s")

                    # Threat Alert Status
                    pred_val = flow_info.get("Prediction", "Normal")
                    conf_val = float(flow_info.get("Confidence", 100.0))
                    if pred_val == "Suspicious":
                        st.error(f"🚨 Threat Alert: Flow #{selected_fid} classified as **SUSPICIOUS** ({conf_val:.1f}% Confidence).")
                    else:
                        st.success(f"✅ Clean Traffic: Flow #{selected_fid} classified as **NORMAL** ({conf_val:.1f}% Confidence).")

                    # Filter packets for this flow
                    if "Flow_ID" in tls_df.columns:
                        flow_packets = tls_df[tls_df["Flow_ID"] == selected_fid].copy()
                    else:
                        s_ip, d_ip = flow_info["Source IP"], flow_info["Destination IP"]
                        s_p, d_p = flow_info["Source Port"], flow_info["Destination Port"]
                        flow_packets = tls_df[
                            ((tls_df["Source IP"] == s_ip) & (tls_df["Destination IP"] == d_ip) & (tls_df["Source Port"] == s_p) & (tls_df["Destination Port"] == d_p)) |
                            ((tls_df["Source IP"] == d_ip) & (tls_df["Destination IP"] == s_ip) & (tls_df["Source Port"] == d_p) & (tls_df["Destination Port"] == s_p))
                        ].copy()

                    if not flow_packets.empty:
                        flow_packets = flow_packets.sort_values(by="Timestamp").reset_index(drop=True)
                        first_ts = float(flow_packets["Timestamp"].min())
                        flow_packets["Relative_Time_s"] = (flow_packets["Timestamp"] - first_ts).round(6)

                        client_ip = str(flow_info["Source IP"])
                        flow_packets["Direction"] = flow_packets["Source IP"].apply(
                            lambda x: "Client ➔ Server" if str(x) == client_ip else "Server ➔ Client"
                        )

                        st.subheader(f"⏱️ Timed Packet Sequence ({len(flow_packets)} Packets)")

                        disp_cols = ["Packet No", "Relative_Time_s", "Direction", "Length", "Record Type", "TLS Version", "SNI", "JA3_Hash"]
                        avail_cols = [c for c in disp_cols if c in flow_packets.columns]

                        st.dataframe(flow_packets[avail_cols], use_container_width=True)

                        # Visualization charts
                        st.subheader("📊 Flow Time-Series Visualizations")
                        c_chart1, c_chart2 = st.columns(2)

                        with c_chart1:
                            st.write("**Packet Size over Relative Time (Seconds)**")
                            st.line_chart(flow_packets.set_index("Relative_Time_s")["Length"])

                        with c_chart2:
                            st.write("**Inter-Arrival Packet Spacing (IATs in Seconds)**")
                            if len(flow_packets) > 1:
                                iat_vals = np.diff(flow_packets["Timestamp"].values)
                                iat_df = pd.DataFrame({
                                    "Packet Index": range(1, len(iat_vals) + 1),
                                    "IAT (s)": iat_vals
                                })
                                st.bar_chart(iat_df.set_index("Packet Index")["IAT (s)"])
                            else:
                                st.info("Single packet flow — no inter-arrival time available.")
                    else:
                        st.info("No packets found for this flow.")

        # ---------------------------------------------------
        # TAB 5: Packet Metadata
        # ---------------------------------------------------
        with tab_packet:
            st.header("📦 Raw Packet Metadata")
            if not packet_df.empty:
                st.dataframe(packet_df, use_container_width=True)

                st.download_button(
                    label="📥 Download Packet Metadata CSV",
                    data=packet_df.to_csv(index=False),
                    file_name="packet_info.csv",
                    mime="text/csv",
                    key="dl_packets"
                )

        # ---------------------------------------------------
        # TAB 6: Summary Report
        # ---------------------------------------------------
        with tab_report:
            st.header("📄 Executive Summary Report")
            if report:
                for key, val in report.items():
                    st.text(f"{key:<25}: {val}")

                report_txt = "\n".join([f"{k}: {v}" for k, v in report.items()])
                st.download_button(
                    label="📥 Download Report Text",
                    data=report_txt,
                    file_name="report.txt",
                    mime="text/plain",
                    key="dl_report"
                )

        # ---------------------------------------------------
        # TAB 7: Per-flow Strands Decider + Bedrock investigation
        # ---------------------------------------------------
        with tab_agent:
            st.header("🧭 Per-Flow Strands Decider Investigation")
            st.write(
                "TLSProfiler results above are unchanged. This optional stage "
                "sends each selected flow as its own Decider request, executes "
                "the selected follow-up action, and asks Bedrock to explain "
                "that flow's result."
            )
            st.caption(
                f"Decider endpoint: {DECIDER_URL} · Confidence threshold: "
                f"{DECIDER_CONFIDENCE_THRESHOLD:.2f}"
            )

            if flow_df.empty:
                st.info("No flows are available for per-flow investigation.")
            else:
                flow_ids = flow_df["Flow_ID"].tolist()
                flow_labels = {
                    row["Flow_ID"]: (
                        f"Flow {row['Flow_ID']}: "
                        f"{row.get('Source IP', '?')} → {row.get('Destination IP', '?')} "
                        f"({row.get('TLS Version', 'TLS version unavailable')})"
                    )
                    for _, row in flow_df.iterrows()
                }
                selected_flow_ids = st.multiselect(
                    "Flows to investigate",
                    options=flow_ids,
                    default=flow_ids,
                    format_func=lambda flow_id: flow_labels.get(flow_id, str(flow_id)),
                    help=(
                        "Each selected flow causes one Decider request and, if "
                        "the request succeeds, one Bedrock explanation request."
                    ),
                    key="decider_selected_flow_ids",
                )
                st.caption(
                    "A capture containing partial flows is still processed. "
                    "Unavailable fields are omitted and identified; they are "
                    "not filled with invented values. All selected flows are "
                    "attempted even if an individual flow fails."
                )

                if st.button(
                    f"Investigate {len(selected_flow_ids)} flow(s)",
                    type="primary",
                    disabled=not selected_flow_ids,
                    key="run_per_flow_decider",
                ):
                    progress = st.progress(0, text="Preparing per-flow investigation…")
                    st.session_state.pop("per_flow_decider_results", None)
                    try:
                        investigation_agent = InvestigationAgent(
                            decider=DeciderClient(),
                            bedrock=bedrock_explainer_from_environment(),
                            confidence_threshold=DECIDER_CONFIDENCE_THRESHOLD,
                        )
                        chosen_flows = flow_df[
                            flow_df["Flow_ID"].isin(selected_flow_ids)
                        ].to_dict(orient="records")
                        chosen_predictions = (
                            prediction_df[
                                prediction_df["Flow_ID"].isin(selected_flow_ids)
                            ].to_dict(orient="records")
                            if not prediction_df.empty and "Flow_ID" in prediction_df
                            else []
                        )

                        with st.status(
                            "Running one Decider decision and Bedrock explanation per flow…",
                            expanded=True,
                        ) as status:
                            def update_progress(completed, total, flow_id):
                                progress.progress(
                                    completed / total,
                                    text=f"Completed flow {flow_id} ({completed}/{total})",
                                )

                            results = investigate_flows(
                                chosen_flows,
                                chosen_predictions,
                                investigation_agent,
                                progress_callback=update_progress,
                            )
                            st.session_state["per_flow_decider_results"] = results
                            decider_failures = sum(
                                row["status"] != "complete" for row in results
                            )
                            status.update(
                                label=(
                                    f"Processed {len(results)} flow(s); "
                                    f"{decider_failures} had a Decider/flow error."
                                ),
                                state="complete",
                            )
                    except (
                        BedrockConfigurationError,
                        DeciderError,
                        ValueError,
                    ) as error:
                        st.error(f"Could not start per-flow investigation: {error}")

                results = st.session_state.get("per_flow_decider_results", [])
                if results:
                    st.subheader("Per-flow investigation results")
                    overview = [
                        {
                            "Flow ID": row["flow_id"],
                            "TLSProfiler label": row["prediction"],
                            "Investigation status": row["status"],
                            "Selected action": row.get("decision", {}).get(
                                "selected_tool", "Unavailable"
                            ),
                            "Executed action": row.get("decision", {}).get(
                                "executed_tool", "Unavailable"
                            ),
                            "Decider confidence": row.get("decision", {}).get(
                                "confidence"
                            ),
                            "Partial evidence": row.get(
                                "partial_flow_evidence", "Unavailable"
                            ),
                        }
                        for row in results
                    ]
                    st.dataframe(pd.DataFrame(overview), use_container_width=True)

                    for row in results:
                        with st.expander(
                            f"Flow {row['flow_id']} · {row['status']} · "
                            f"TLSProfiler: {row['prediction']}"
                        ):
                            if row["status"] != "complete":
                                st.error(row["error"])
                                continue
                            decision = row["decision"]
                            st.write(
                                f"Decider selected **{decision['selected_tool']}** "
                                f"and the agent executed **{decision['executed_tool']}**."
                            )
                            st.write(f"Confidence: {decision['confidence']:.1%}")
                            st.write(
                                "Decider model latency: "
                                f"{decision['model_latency_ms']} ms"
                                if decision["model_latency_ms"] is not None
                                else "Decider model latency was not included in the response."
                            )
                            st.write(
                                f"Decider HTTP latency: {decision['request_latency_ms']:.1f} ms"
                            )
                            if decision["low_confidence_fallback"]:
                                st.warning(
                                    "Low confidence triggered the "
                                    "`allow_and_monitor` fallback."
                                )
                            st.write("Choice probabilities")
                            st.json(decision["probabilities"])
                            st.write("Investigation action result")
                            st.json(row["tool_result"])
                            if row["partial_flow_evidence"]:
                                st.warning(
                                    "Partial flow evidence; unavailable fields: "
                                    + ", ".join(row["missing_core_fields"])
                                )
                            if row["explanation_error"]:
                                st.error(
                                    "Decider action completed, but Bedrock "
                                    f"explanation failed: {row['explanation_error']}"
                                )
                            elif row["explanation"]:
                                st.write("Amazon Bedrock explanation")
                                st.write(row["explanation"])

else:
    st.info("👈 Upload a PCAP file or select a sample capture from the sidebar to begin analysis.")
