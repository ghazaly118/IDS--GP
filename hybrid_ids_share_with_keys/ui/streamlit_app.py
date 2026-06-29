import streamlit as st
import requests
import pandas as pd
import plotly.express as px


st.set_page_config(page_title="Hybrid IDS Dashboard", layout="wide")

if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "last_uploaded_filename" not in st.session_state:
    st.session_state.last_uploaded_filename = None
if "soar_send_result" not in st.session_state:
    st.session_state.soar_send_result = None


CUSTOM_CSS = """
<style>
.block-container { padding-top: 1.35rem; padding-bottom: 2.2rem; }
.info-card {
    padding: 16px; border-radius: 16px; background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08); margin-bottom: 18px; min-height: 118px;
}
.info-card h4 { margin: 0 0 10px 0; font-size: 15px; opacity: 0.92; }
.info-card p { margin: 0; font-size: 16px; font-weight: 700; line-height: 1.45; word-break: break-word; overflow-wrap: anywhere; }
.metric-card-blue,.metric-card-red,.metric-card-orange,.metric-card-purple,.metric-card-green,.metric-card-gray {
    padding: 20px; border-radius: 18px; color: white; min-height: 150px; margin-bottom: 18px; box-sizing: border-box;
}
.metric-card-blue { background: linear-gradient(135deg,#1f77b4,#0d3b66); }
.metric-card-red { background: linear-gradient(135deg,#d62728,#7f1d1d); }
.metric-card-orange { background: linear-gradient(135deg,#ff9800,#8a4b00); }
.metric-card-purple { background: linear-gradient(135deg,#6f42c1,#432874); }
.metric-card-green { background: linear-gradient(135deg,#198754,#0f5132); }
.metric-card-gray { background: linear-gradient(135deg,#475569,#1e293b); }
.metric-title { font-size: 15px; margin-bottom: 14px; opacity: 0.95; }
.metric-value { font-size: 21px; font-weight: 800; line-height: 1.38; word-break: break-word; overflow-wrap: anywhere; }
.small-note { font-size: 12px; opacity: 0.85; margin-top: 12px; line-height: 1.45; }
.section-gap { height: 18px; }
.section-gap-lg { height: 28px; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def clear_results():
    st.session_state.analysis_data = None
    st.session_state.last_uploaded_filename = None
    st.session_state.soar_send_result = None


def safe_float(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def choose_endpoint(api_base, uploaded_file):
    api_base = api_base.rstrip("/")
    name = uploaded_file.name.lower()
    if name.endswith(".csv"):
        return [f"{api_base}/analyze-csv", f"{api_base}/analyze"]
    if name.endswith((".pcap", ".pcapng")):
        return [f"{api_base}/analyze-pcap", f"{api_base}/analyze"]
    return [f"{api_base}/analyze"]


def call_backend(api_base, uploaded_file):
    endpoints = choose_endpoint(api_base, uploaded_file)
    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type or "application/octet-stream")}
    last_error = None
    last_response_text = None

    for endpoint in endpoints:
        try:
            response = requests.post(endpoint, files=files, timeout=600)
            if response.status_code == 404:
                last_response_text = response.text
                continue
            if response.status_code == 200:
                return response.json()
            try:
                err_payload = response.json()
            except Exception:
                err_payload = {"detail": response.text}
            raise RuntimeError(f"{endpoint} -> {err_payload}")
        except requests.exceptions.ConnectionError as e:
            last_error = f"Could not connect to backend on {endpoint}: {e}"
        except Exception as e:
            last_error = str(e)

    if last_error:
        raise RuntimeError(last_error)
    raise RuntimeError(f"Could not find a working endpoint. Last response: {last_response_text}")


def _compact_flow_metadata_from_csv(csv_path, max_rows=50):
    """Read original CICFlowMeter flow metadata so SOAR can use real IPs/ports/stats."""
    if not csv_path:
        return []
    try:
        df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    except Exception:
        return []

    wanted_names = {
        "flowid", "sourceip", "srcip", "src", "destinationip", "dstip", "dst",
        "sourceport", "srcport", "destinationport", "dstport", "protocol", "timestamp",
        "flowduration", "totalfwdpackets", "totalbackwardpackets", "totfwdpkts", "totbwdpkts",
        "fwdpacketslengthtotal", "bwdpacketslengthtotal", "totlenfwdpkts", "totlenbwdpkts",
        "label", "benign",
    }

    selected_cols = []
    for col in df.columns:
        clean = "".join(ch for ch in str(col).lower() if ch.isalnum())
        if clean in wanted_names:
            selected_cols.append(col)

    # If the CSV has unusual column names, still forward a small first-row preview.
    if not selected_cols:
        selected_cols = list(df.columns[:25])

    compact = df[selected_cols].copy()
    compact = compact.where(pd.notna(compact), None)
    return compact.to_dict(orient="records")


def _merge_zero_day_with_flow_rows(zero_day_details, flow_rows, max_rows=20):
    """Attach original flow metadata to zero-day rows using flow_index when available."""
    flow_rows = flow_rows or []
    zero_day_details = zero_day_details or []
    merged = []
    for item in zero_day_details[:max_rows]:
        row = dict(item) if isinstance(item, dict) else {}
        idx = row.get("flow_index")
        try:
            idx = int(idx)
        except Exception:
            idx = None
        if idx is not None and 0 <= idx < len(flow_rows) and isinstance(flow_rows[idx], dict):
            row.update({f"flow_{k}": v for k, v in flow_rows[idx].items()})
            # Also expose common names directly if they exist in the flow row.
            for k, v in flow_rows[idx].items():
                key = "".join(ch for ch in str(k).lower() if ch.isalnum())
                if key in {"srcip", "sourceip"}:
                    row.setdefault("source_ip", v)
                elif key in {"dstip", "destinationip"}:
                    row.setdefault("destination_ip", v)
                elif key in {"srcport", "sourceport"}:
                    row.setdefault("source_port", v)
                elif key in {"dstport", "destinationport"}:
                    row.setdefault("destination_port", v)
                elif key == "protocol":
                    row.setdefault("protocol", v)
        merged.append(row)
    return merged



def build_soar_payload(analysis_data, uploaded_filename=None):
    """Build a payload for SOAR with real IDS output + original CICFlowMeter metadata."""
    analysis_data = analysis_data or {}
    flow_rows = _compact_flow_metadata_from_csv(analysis_data.get("generated_csv"), max_rows=60)
    zero_day_details = _merge_zero_day_with_flow_rows(
        analysis_data.get("zero_day_details", []) or [],
        flow_rows,
        max_rows=25,
    )

    return {
        "source": "hybrid_ids_dashboard",
        "filename": uploaded_filename or analysis_data.get("filename", "unknown"),
        "analysisResult": {
            "filename": analysis_data.get("filename", uploaded_filename or "unknown"),
            "generated_csv": analysis_data.get("generated_csv"),
            "flows_analyzed": analysis_data.get("flows_analyzed"),
            "attack_count": analysis_data.get("attack_count"),
            "benign_count": analysis_data.get("benign_count"),
            "attack_rate": analysis_data.get("attack_rate"),
            "official_binary_decision": analysis_data.get("official_binary_decision"),
            "binary_summary": analysis_data.get("binary_summary", {}),
            "multiclass_summary": analysis_data.get("multiclass_summary", {}),
            "attack_type_summary": analysis_data.get("attack_type_summary", {}),
            "rule_result": analysis_data.get("rule_result", {}),
            "zero_day_summary": analysis_data.get("zero_day_summary", {}),
            "zero_day_details": zero_day_details,
            "results_preview": (analysis_data.get("results", []) or [])[:25],
            "flow_metadata_preview": flow_rows[:25],
        },
    }


def send_to_soar(soar_api_base, analysis_data, uploaded_filename=None):
    endpoint = f"{soar_api_base.rstrip('/')}/api/ids-ingest"
    payload = build_soar_payload(analysis_data, uploaded_filename)
    response = requests.post(endpoint, json=payload, timeout=90)
    if response.status_code != 200:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise RuntimeError(f"{endpoint} -> {detail}")
    return response.json()

def get_status_style(decision: str):
    decision = str(decision).strip().lower()
    if "benign" in decision:
        return "success", "🟢 System Status: Normal Traffic"
    if "single model caught it" in decision:
        return "warning", "🟡 System Status: Suspicious - One Binary Model Flagged the File"
    if "attack" in decision:
        return "error", "🔴 System Status: Attack Detected"
    return "info", f"ℹ️ System Status: {decision}"


def show_status_box(decision: str):
    kind, text = get_status_style(decision)
    if kind == "success":
        st.success(text)
    elif kind == "warning":
        st.warning(text)
    elif kind == "error":
        st.error(text)
    else:
        st.info(text)


def prepare_multiclass_detail_df(results):
    df = pd.DataFrame(results).copy()
    if df.empty:
        return df

    # Map backend XGB fields to GUI CNN fields
    if "xgb_pred" in df.columns and "cnn_pred" not in df.columns:
        df["cnn_pred"] = df["xgb_pred"]

    if "xgb_conf" in df.columns and "cnn_conf" not in df.columns:
        df["cnn_conf"] = df["xgb_conf"]

    needed_cols = [
        "flow_index", "attack_type", "attack_type_confidence", "attack_type_status",
        "cnn_pred", "cnn_conf", "lstm_pred", "lstm_conf",
        "ensemble_pred", "ensemble_conf", "source_model",
    ]

    for col in needed_cols:
        if col not in df.columns:
            df[col] = None

    for col in ["attack_type_confidence", "cnn_conf", "lstm_conf", "ensemble_conf"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df
def render_metric_card(title, value, variant="blue", note=None):
    variant_class = {
        "blue": "metric-card-blue", "red": "metric-card-red", "orange": "metric-card-orange",
        "purple": "metric-card-purple", "green": "metric-card-green", "gray": "metric-card-gray",
    }.get(variant, "metric-card-blue")
    note_html = f'<div class="small-note">{note}</div>' if note else ""
    st.markdown(
        f"""
        <div class="{variant_class}">
            <div class="metric-title">{title}</div>
            <div class="metric-value">{value}</div>
            {note_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_info_card(title, value):
    st.markdown(
        f"""
        <div class="info-card">
            <h4>{title}</h4>
            <p>{value}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def dominant_attack_label(summary_dict):
    if not isinstance(summary_dict, dict) or not summary_dict:
        return "-"
    non_zero = {k: v for k, v in summary_dict.items() if int(v) > 0}
    if not non_zero:
        return "-"
    return max(non_zero, key=non_zero.get)


st.title("Hybrid IDS Dashboard")
st.caption("Rule-Based + AI Binary Classification + Conditional Multiclass + Zero-Day Autoencoder + SOAR Handoff")

with st.sidebar:
    st.header("Project Info")
    st.write("Hybrid Intrusion Detection System for Cyber Security Graduation Project.")
    st.markdown("- Packet Rules on PCAP")
    st.markdown("- AI Binary Classification")
    st.markdown("- Conditional Multiclass")
    st.markdown("- Zero-Day Autoencoder anomaly detection")
    st.markdown("- SOAR handoff to external Incident Response dashboard")

    st.divider()
    st.header("Backend")
    api_base = st.text_input("IDS API Base URL", value="http://127.0.0.1:8000")

    st.divider()
    st.header("SOAR Integration")
    soar_api_base = st.text_input("SOAR API Base URL", value="http://127.0.0.1:8001")
    soar_ui_base = st.text_input("SOAR Dashboard URL", value="http://localhost:5173")

    st.divider()
    st.header("Upload Mode")
    st.write("Supports PCAP/PCAPNG and CSV. CSV mode skips packet rules and CICFlowMeter.")

    st.divider()
    if st.button("Clear Results", use_container_width=True):
        clear_results()
        st.rerun()


uploaded_file = st.file_uploader("Upload PCAP, PCAPNG, or CICFlowMeter CSV file", type=["pcap", "pcapng", "csv"])

if uploaded_file is not None:
    if st.session_state.last_uploaded_filename and uploaded_file.name != st.session_state.last_uploaded_filename:
        st.info("A new file was selected. Click Analyze to process it.")

if st.button("Analyze", use_container_width=True):
    if uploaded_file is None:
        st.warning("Please upload a PCAP/PCAPNG/CSV file first.")
    else:
        with st.spinner("Analyzing traffic..."):
            try:
                data = call_backend(api_base, uploaded_file)
                st.session_state.analysis_data = data
                st.session_state.last_uploaded_filename = uploaded_file.name
                st.session_state.soar_send_result = None
            except Exception as e:
                st.error(str(e))

if st.session_state.analysis_data is not None:
    data = st.session_state.analysis_data

    filename = data.get("filename", "N/A")
    generated_csv = data.get("generated_csv", "-")
    flows_analyzed = int(data.get("flows_analyzed", 0))
    official_binary_decision = data.get("official_binary_decision", "UNKNOWN")

    binary_summary = data.get("binary_summary", {})
    multiclass_summary = data.get("multiclass_summary", {})
    rule_result = data.get("rule_result", {})
    attack_type_summary = data.get("attack_type_summary", {})
    results = data.get("results", [])
    incident_response = data.get("incident_response", {}) or {}
    zero_day_summary = data.get("zero_day_summary", {}) or {}
    zero_day_details = data.get("zero_day_details", []) or []

    detail_df = prepare_multiclass_detail_df(results)

    packet_summary = rule_result.get("summary", {}) if isinstance(rule_result, dict) else {}
    packet_sample_alerts = rule_result.get("sample_alerts", []) if isinstance(rule_result, dict) else []
    packet_attack_type_summary = packet_summary.get("attack_type_summary", {}) if isinstance(packet_summary, dict) else {}
    packet_top_sources = packet_summary.get("top_sources", []) if isinstance(packet_summary, dict) else []

    xgb_count = int(binary_summary.get("xgb_count", 0))
    lstm_count = int(binary_summary.get("lstm_count", 0))
    xgb_atk_percent = safe_float(binary_summary.get("xgb_atk_percent", 0.0))
    lstm_atk_percent = safe_float(binary_summary.get("lstm_atk_percent", 0.0))
    xgb_mean = safe_float(binary_summary.get("xgb_mean", 0.0))
    lstm_mean = safe_float(binary_summary.get("lstm_mean", 0.0))

    multiclass_status = str(multiclass_summary.get("status", "unknown")).lower()
    multiclass_effective = int(multiclass_summary.get("Effective_Predictions", 0))
    multiclass_avg_conf = safe_float(multiclass_summary.get("Avg_Confidence", 0.0))
    unknown_rate = multiclass_summary.get("Unknown_Rate_%", None)
    multiclass_top1 = multiclass_summary.get("Top_1_Attack", "-")

    packet_total_alerts = int(packet_summary.get("total_alerts", 0))
    packet_packets_processed = int(packet_summary.get("packets_processed", 0))
    packet_processing_time = safe_float(packet_summary.get("processing_time_sec", 0.0))
    packet_top_family = dominant_attack_label(packet_attack_type_summary)

    zero_day_status = str(zero_day_summary.get("status", "not_available"))
    zero_day_decision = str(zero_day_summary.get("decision", "UNAVAILABLE"))
    zero_day_rows = int(zero_day_summary.get("anomalous_rows", 0) or 0)
    zero_day_rate = safe_float(zero_day_summary.get("anomaly_rate_percent", 0.0))
    zero_day_threshold = zero_day_summary.get("threshold")
    zero_day_mean_error = zero_day_summary.get("mean_reconstruction_error")
    zero_day_max_error = zero_day_summary.get("max_reconstruction_error")

    st.subheader("System Status")
    if zero_day_decision == "POSSIBLE_ZERO_DAY":
        st.warning("🟠 System Status: Suspicious - Possible Zero-Day / Unknown Anomaly")
    else:
        show_status_box(official_binary_decision)

    st.subheader("Analysis Summary")
    info_row1_a, info_row1_b = st.columns(2, gap="large")
    with info_row1_a:
        render_info_card("File Name", filename)
    with info_row1_b:
        render_info_card("Generated CSV", generated_csv)

    info_row2_a, info_row2_b = st.columns(2, gap="large")
    with info_row2_a:
        render_info_card("Official Binary Decision", official_binary_decision)
    with info_row2_b:
        render_info_card("Detection Mode", "Packet Rules + Binary + Conditional Multiclass + Zero-Day + SOAR Handoff")

    st.markdown('<div class="section-gap-lg"></div>', unsafe_allow_html=True)

    st.markdown("### Detection Results Overview")
    top1, top2, top3, top4 = st.columns(4, gap="large")
    with top1:
        render_metric_card("Rules Detected", f"{packet_total_alerts}", variant="red", note=f"Top rule family: {packet_top_family}")
    with top2:
        render_metric_card("Binary Decision", official_binary_decision, variant="green", note=f"XGB mean: {xgb_mean:.4f} | LSTM mean: {lstm_mean:.4f}")
    with top3:
        if multiclass_status == "skipped":
            render_metric_card("Multiclass", "Skipped", variant="blue", note="Runs only when the official binary decision is ATTACK.")
        else:
            render_metric_card("Multiclass", multiclass_top1, variant="purple", note=f"Effective rows: {multiclass_effective}")
    with top4:
        render_metric_card("Zero-Day", zero_day_decision, variant="orange", note=f"Anomalous rows: {zero_day_rows} | Rate: {zero_day_rate:.2f}%")

    st.markdown("### SOAR Handoff")
    st.caption("The IDS stays responsible for detection. Send confirmed/suspicious detections to the separate React SOAR Incident Response dashboard.")
    soar_c1, soar_c2 = st.columns([2, 1], gap="large")
    with soar_c1:
        st.write(f"Dashboard: {soar_ui_base}")
    with soar_c2:
        if st.button("Send to SOAR Incident Response", use_container_width=True):
            with st.spinner("Sending IDS result to SOAR dashboard..."):
                try:
                    st.session_state.soar_send_result = send_to_soar(
                        soar_api_base,
                        data,
                        st.session_state.last_uploaded_filename,
                    )
                except Exception as e:
                    st.session_state.soar_send_result = None
                    st.error(str(e))

    if st.session_state.soar_send_result:
        soar_result = st.session_state.soar_send_result
        incident_id = soar_result.get("incident", {}).get("id") or soar_result.get("incident_id", "-")
        ticket_id = soar_result.get("ticket", {}).get("ticket_id", "-")
        st.success(f"Sent to SOAR successfully. Incident: {incident_id} | Ticket: {ticket_id}")
        st.markdown(f"[Open SOAR Dashboard]({soar_ui_base})")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Binary Decision", "Multiclass Insights", "Detailed Predictions", "Rules Insights", "Zero-Day Detection",
    ])

    with tab1:
        st.subheader("Binary Decision")
        b1, b2, b3 = st.columns(3, gap="large")
        with b1:
            render_metric_card("Official Binary Decision", binary_summary.get("ENSEMBLE", "UNKNOWN"), variant="green")
        with b2:
            render_metric_card("XGB Mean", f"{xgb_mean:.4f}", variant="red")
        with b3:
            render_metric_card("LSTM Mean", f"{lstm_mean:.4f}", variant="orange")

        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
        b4, b5, b6 = st.columns(3, gap="large")
        with b4:
            render_metric_card("XGB Count", f"{xgb_count}", variant="red")
        with b5:
            render_metric_card("LSTM Count", f"{lstm_count}", variant="orange")
        with b6:
            render_metric_card(
                "Rule Alerts",
                f"{packet_total_alerts}",
                variant="blue",
                note=f"Packets processed: {packet_packets_processed}"
            )

        st.markdown("### Binary Highlights")
        highlights_df = pd.DataFrame([
            {"Item": "Sequence Length", "Value": binary_summary.get("seq_len")},
            {"Item": "Stride", "Value": binary_summary.get("stride")},
            {"Item": "XGB Threshold", "Value": binary_summary.get("xgb_threshold")},
            {"Item": "LSTM Threshold", "Value": binary_summary.get("lstm_threshold")},
            {"Item": "Matched Features", "Value": binary_summary.get("matched_features")},
            {"Item": "Missing Features", "Value": binary_summary.get("missing_features")},
            {"Item": "Feature Coverage %", "Value": binary_summary.get("feature_coverage_percent")},
        ])
        st.dataframe(highlights_df, use_container_width=True, hide_index=True)

        c1, c2 = st.columns(2, gap="large")
        with c1:
            stats_df = pd.DataFrame([{"Model": "XGBoost", "Flagged Count": xgb_count}, {"Model": "LSTM", "Flagged Count": lstm_count}])
            fig_binary_counts = px.bar(stats_df, x="Model", y="Flagged Count", title="Binary Model Flagged Counts", color="Model", color_discrete_map={"XGBoost": "#d62728", "LSTM": "#ff9800"})
            fig_binary_counts.update_layout(xaxis_title="", yaxis_title="Count", margin=dict(t=55, b=20, l=20, r=20))
            st.plotly_chart(fig_binary_counts, use_container_width=True)
        with c2:
            rates_df = pd.DataFrame([{"Model": "XGBoost", "Attack Rate %": xgb_atk_percent}, {"Model": "LSTM", "Attack Rate %": lstm_atk_percent}])
            fig_binary_rates = px.bar(rates_df, x="Model", y="Attack Rate %", title="Binary Model Attack-Rate Estimates", color="Model", color_discrete_map={"XGBoost": "#d62728", "LSTM": "#ff9800"})
            fig_binary_rates.update_layout(xaxis_title="", yaxis_title="Rate %", margin=dict(t=55, b=20, l=20, r=20))
            st.plotly_chart(fig_binary_rates, use_container_width=True)

    with tab2:
        st.subheader("Multiclass Insights")
        if multiclass_status == "skipped":
            st.success(multiclass_summary.get("message", "Multiclass was skipped."))
        else:
            m1, m2, m3, m4 = st.columns(4, gap="large")
            with m1:
                render_metric_card("Mode", multiclass_summary.get("mode", "-"), variant="blue")
            with m2:
                render_metric_card("Effective Predictions", f"{multiclass_effective}", variant="purple")
            with m3:
                render_metric_card("Average Confidence", f"{multiclass_avg_conf:.4f}", variant="green")
            with m4:
                render_metric_card("Unknown Rate %", f"{0.0 if unknown_rate is None else unknown_rate}", variant="orange")

            t1, t2, t3 = st.columns(3, gap="large")
            with t1:
                render_info_card("Top 1 Attack", multiclass_summary.get("Top_1_Attack", "-"))
            with t2:
                render_info_card("Top 2 Attack", multiclass_summary.get("Top_2_Attack", "-"))
            with t3:
                render_info_card("Top 3 Attack", multiclass_summary.get("Top_3_Attack", "-"))

            if attack_type_summary:
                attack_df = pd.DataFrame([{"Attack Type": k, "Count": v} for k, v in attack_type_summary.items()]).sort_values("Count", ascending=False)
                mc1, mc2 = st.columns(2, gap="large")
                with mc1:
                    st.dataframe(attack_df, use_container_width=True, hide_index=True)
                with mc2:
                    fig_attack_pie = px.pie(attack_df, names="Attack Type", values="Count", title="Attack Type Ratio", hole=0.45)
                    fig_attack_pie.update_layout(margin=dict(t=55, b=20, l=20, r=20))
                    st.plotly_chart(fig_attack_pie, use_container_width=True)

    with tab3:
        st.subheader("Detailed Predictions")
        if multiclass_status == "skipped":
            st.info("No detailed multiclass predictions were generated because the binary decision was not ATTACK.")
        elif detail_df.empty:
            st.info("No detailed multiclass predictions returned.")
        else:
            filter_attack_status = sorted(detail_df["attack_type_status"].dropna().astype(str).unique().tolist())
            selected_status = st.multiselect("Filter by attack status", options=filter_attack_status, default=filter_attack_status)
            attack_type_options = sorted(detail_df["attack_type"].dropna().astype(str).unique().tolist())
            selected_attack_types = st.multiselect("Filter by displayed attack type", options=attack_type_options, default=attack_type_options)
            filtered_df = detail_df.copy()
            if selected_status:
                filtered_df = filtered_df[filtered_df["attack_type_status"].astype(str).isin(selected_status)]
            if selected_attack_types:
                filtered_df = filtered_df[filtered_df["attack_type"].astype(str).isin(selected_attack_types)]
            display_columns = [
                "flow_index", "attack_type", "attack_type_confidence", "attack_type_status",
                "cnn_pred", "cnn_conf", "lstm_pred", "lstm_conf",
                "ensemble_pred", "ensemble_conf", "source_model"
            ]
            display_columns = [c for c in display_columns if c in filtered_df.columns]
            st.dataframe(filtered_df[display_columns], use_container_width=True, height=520, hide_index=True)

    with tab4:
        st.subheader("Rules Insights")
        r1, r2, r3 = st.columns(3, gap="large")
        with r1:
            render_metric_card("Packet Alerts", f"{packet_total_alerts}", variant="red")
        with r2:
            render_metric_card("Packets Processed", f"{packet_packets_processed}", variant="blue")
        with r3:
            render_metric_card("Processing Time", f"{packet_processing_time:.2f} sec", variant="green")

        st.markdown("### Packet Rule Attack-Type Distribution")
        if packet_attack_type_summary:
            packet_attack_df = pd.DataFrame([{"Attack Type": k, "Count": v} for k, v in packet_attack_type_summary.items()]).sort_values("Count", ascending=False)
            pr1, pr2 = st.columns(2, gap="large")
            with pr1:
                st.dataframe(packet_attack_df, use_container_width=True, hide_index=True)
                fig_packet_attack_bar = px.bar(packet_attack_df, x="Attack Type", y="Count", title="Packet Rules Attack-Type Distribution", color="Count", color_continuous_scale="Reds")
                fig_packet_attack_bar.update_layout(xaxis_title="", yaxis_title="Count", margin=dict(t=55, b=20, l=20, r=20))
                st.plotly_chart(fig_packet_attack_bar, use_container_width=True)
            with pr2:
                fig_packet_attack_pie = px.pie(packet_attack_df, names="Attack Type", values="Count", title="Packet Rules Attack-Type Ratio", hole=0.45)
                fig_packet_attack_pie.update_layout(margin=dict(t=55, b=20, l=20, r=20))
                st.plotly_chart(fig_packet_attack_pie, use_container_width=True)
        else:
            st.info("No packet-rule alerts were returned.")

        st.markdown("### Top Source IPs from Packet Rules")
        if packet_top_sources:
            top_sources_df = pd.DataFrame(packet_top_sources).rename(columns={"src": "Source IP", "count": "Alert Count"})
            st.dataframe(top_sources_df, use_container_width=True, hide_index=True)
        else:
            st.info("No top sources were returned.")

        st.markdown("### Sample Packet Alerts")
        if packet_sample_alerts:
            sample_alerts_df = pd.DataFrame(packet_sample_alerts).rename(columns={"type": "Attack Type", "source": "Alert Source", "msg": "Message", "src": "Source IP", "dst": "Destination IP"})
            st.dataframe(sample_alerts_df, use_container_width=True, height=360, hide_index=True)
        else:
            st.info("No sample packet alerts available.")

    with tab5:
        st.subheader("Zero-Day Autoencoder Detection")
        st.caption("Detects unknown/anomalous flows using reconstruction error. If artifacts are missing, the main IDS still works.")

        z1, z2, z3, z4 = st.columns(4, gap="large")
        with z1:
            render_metric_card("Zero-Day Decision", zero_day_decision, variant="orange")
        with z2:
            render_metric_card("Anomalous Rows", str(zero_day_rows), variant="red")
        with z3:
            render_metric_card("Anomaly Rate", f"{zero_day_rate:.4f}%", variant="purple")
        with z4:
            render_metric_card("Status", zero_day_status, variant="gray")

        if zero_day_status == "not_available":
            st.warning(zero_day_summary.get("message", "Zero-day model artifacts are not installed yet."))
            st.code("models/zero_day_autoencoder/autoencoder_zero_day.keras\nmodels/zero_day_autoencoder/scaler.joblib\nmodels/zero_day_autoencoder/meta.json", language="text")
        elif zero_day_status == "error":
            st.error(zero_day_summary.get("message", "Zero-day detector failed."))
        else:
            st.markdown("### Autoencoder Metrics")
            zd_metrics_df = pd.DataFrame([
                {"Metric": "Threshold", "Value": zero_day_threshold},
                {"Metric": "Mean reconstruction error", "Value": zero_day_mean_error},
                {"Metric": "Max reconstruction error", "Value": zero_day_max_error},
                {"Metric": "Feature count", "Value": zero_day_summary.get("feature_count")},
                {"Metric": "Matched features", "Value": zero_day_summary.get("matched_features")},
                {"Metric": "Missing features", "Value": zero_day_summary.get("missing_features")},
                {"Metric": "Feature coverage %", "Value": zero_day_summary.get("feature_coverage_percent")},
            ])
            st.dataframe(zd_metrics_df, use_container_width=True, hide_index=True)

            if zero_day_details:
                zd_df = pd.DataFrame(zero_day_details)
                display_cols = [c for c in ["flow_index", "zero_day_prediction", "reconstruction_error", "above_threshold", "source_ip", "destination_ip"] if c in zd_df.columns]
                st.markdown("### Top Flows by Reconstruction Error")
                st.dataframe(zd_df[display_cols], use_container_width=True, height=420, hide_index=True)

                if "reconstruction_error" in zd_df.columns:
                    fig_zd = px.histogram(zd_df, x="reconstruction_error", title="Top Returned Reconstruction Errors")
                    fig_zd.update_layout(xaxis_title="Reconstruction Error", yaxis_title="Flow Count", margin=dict(t=55, b=20, l=20, r=20))
                    st.plotly_chart(fig_zd, use_container_width=True)
            else:
                st.info("No zero-day detail rows returned.")

        st.markdown("### How to explain it")
        st.write("- The autoencoder was trained mainly on benign flow behavior.")
        st.write("- During inference, it reconstructs each flow and calculates reconstruction error.")
        st.write("- If the error is above the saved threshold, the flow is treated as anomalous / possible zero-day.")
elif uploaded_file is not None:
    st.info("Upload completed. Click Analyze to run detection.")
else:
    st.info("Upload a PCAP/PCAPNG/CSV file to begin analysis.")
