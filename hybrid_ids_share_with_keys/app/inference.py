

from collections import Counter
from pathlib import Path
import re

import numpy as np
import pandas as pd

from app.model_loader import (
    get_binary_lstm_bundle,
    get_binary_xgb_bundle,
    get_multiclass_predictor,
    multiclass_available,
)
from app.multiclass_predictor import make_lstm_windows_for_inference
from app.zero_day_detector import predict_zero_day_dataframe


ALERT_TOLERANCE = 0

CICFLOWMETER_ALIASES = {
    # Metadata names used by CICFlowMeter output
    "Source IP": ["Src IP", "Source IP"],
    "Source Port": ["Src Port", "Source Port"],
    "Destination IP": ["Dst IP", "Destination IP"],
    "Destination Port": ["Dst Port", "Destination Port"],

    # Counts / lengths
    "Total Fwd Packets": ["Total Fwd Packet", "Total Fwd Packets", "Tot Fwd Pkts"],
    "Total Backward Packets": ["Total Bwd packets", "Total Backward Packets", "Tot Bwd Pkts"],
    "Fwd Packets Length Total": [
        "Total Length of Fwd Packet",
        "Total Length of Fwd Packets",
        "TotLen Fwd Pkts",
        "Fwd Packets Length Total",
    ],
    "Bwd Packets Length Total": [
        "Total Length of Bwd Packet",
        "Total Length of Bwd Packets",
        "TotLen Bwd Pkts",
        "Bwd Packets Length Total",
    ],

    # Packet length features
    "Fwd Packet Length Max": ["Fwd Packet Length Max"],
    "Fwd Packet Length Min": ["Fwd Packet Length Min"],
    "Fwd Packet Length Mean": ["Fwd Packet Length Mean"],
    "Fwd Packet Length Std": ["Fwd Packet Length Std"],
    "Bwd Packet Length Max": ["Bwd Packet Length Max"],
    "Bwd Packet Length Min": ["Bwd Packet Length Min"],
    "Bwd Packet Length Mean": ["Bwd Packet Length Mean"],
    "Bwd Packet Length Std": ["Bwd Packet Length Std"],
    "Packet Length Min": ["Packet Length Min"],
    "Packet Length Max": ["Packet Length Max"],
    "Packet Length Mean": ["Packet Length Mean"],
    "Packet Length Std": ["Packet Length Std"],
    "Packet Length Variance": ["Packet Length Variance"],
    "Avg Packet Size": ["Average Packet Size", "Avg Packet Size"],

    # Segment size features
    "Avg Fwd Segment Size": ["Fwd Segment Size Avg", "Avg Fwd Segment Size"],
    "Avg Bwd Segment Size": ["Bwd Segment Size Avg", "Avg Bwd Segment Size"],
    "Fwd Seg Size Min": ["Fwd Seg Size Min", "min_seg_size_forward"],

    # TCP init window / active data packet names
    "Init Fwd Win Bytes": [
        "FWD Init Win Bytes",
        "Fwd Init Win Bytes",
        "Init Fwd Win Bytes",
        "Init Fwd Win Byts",
        "Init_Win_bytes_forward",
    ],
    "Init Bwd Win Bytes": [
        "Bwd Init Win Bytes",
        "Init Bwd Win Bytes",
        "Init Bwd Win Byts",
        "Init_Win_bytes_backward",
    ],
    "Fwd Act Data Packets": [
        "Fwd Act Data Pkts",
        "Fwd Act Data Packets",
        "act_data_pkt_fwd",
    ],

    # Flags
    "CWE Flag Count": ["CWR Flag Count", "CWE Flag Count"],
    "ECE Flag Count": ["ECE Flag Count"],
    "FIN Flag Count": ["FIN Flag Count"],
    "SYN Flag Count": ["SYN Flag Count"],
    "RST Flag Count": ["RST Flag Count"],
    "PSH Flag Count": ["PSH Flag Count"],
    "ACK Flag Count": ["ACK Flag Count"],
    "URG Flag Count": ["URG Flag Count"],

    # Subflow aliases
    "Subflow Fwd Packets": ["Subflow Fwd Packets"],
    "Subflow Fwd Bytes": ["Subflow Fwd Bytes"],
    "Subflow Bwd Packets": ["Subflow Bwd Packets"],
    "Subflow Bwd Bytes": ["Subflow Bwd Bytes"],
}

HARDCODED_MAP = {
    # Original mappings
    "totallengthoffwdpacket": "Fwd Packets Length Total",
    "totallengthofbwdpacket": "Bwd Packets Length Total",
    "totalfwdpacket": "Total Fwd Packets",
    "totalbwdpackets": "Total Backward Packets",
    "fwdsegmentsizeavg": "Avg Fwd Segment Size",
    "bwdsegmentsizeavg": "Avg Bwd Segment Size",
    "cwrflagcount": "CWE Flag Count",

    # The exact missing features from your CICFlowMeter CSV
    "averagepacketsize": "Avg Packet Size",
    "fwdinitwinbytes": "Init Fwd Win Bytes",
    "fwdinitwinbyts": "Init Fwd Win Bytes",
    "initfwdwinbytes": "Init Fwd Win Bytes",
    "initfwdwinbyts": "Init Fwd Win Bytes",
    "initwinbytesforward": "Init Fwd Win Bytes",

    "bwdinitwinbytes": "Init Bwd Win Bytes",
    "bwdinitwinbyts": "Init Bwd Win Bytes",
    "initbwdwinbytes": "Init Bwd Win Bytes",
    "initbwdwinbyts": "Init Bwd Win Bytes",
    "initwinbytesbackward": "Init Bwd Win Bytes",

    "fwdactdatapkts": "Fwd Act Data Packets",
    "fwdactdatapackets": "Fwd Act Data Packets",
    "actdatapktfwd": "Fwd Act Data Packets",

    # Metadata aliases
    "srcip": "Source IP",
    "srcport": "Source Port",
    "dstip": "Destination IP",
    "dstport": "Destination Port",
}


def standardize_col_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


# Add every alias in CICFLOWMETER_ALIASES to HARDCODED_MAP.
# This makes the live CICFlowMeter output match the training feature names automatically.
for _standard_name, _aliases in CICFLOWMETER_ALIASES.items():
    for _alias in _aliases:
        HARDCODED_MAP.setdefault(standardize_col_name(_alias), _standard_name)


def _add_cicflowmeter_alias_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Your live CICFlowMeter output uses names like:
        Average Packet Size, FWD Init Win Bytes, Bwd Init Win Bytes, Fwd Act Data Pkts

    The trained model may expect names like:
        Avg Packet Size, Init Fwd Win Bytes, Init Bwd Win Bytes, Fwd Act Data Packets

    This function DOES NOT delete original columns.
    It only adds standard alias columns when they are missing.
    """
    df = df.copy()
    df.columns = df.columns.astype(str).str.strip()

    # exact-name alias creation
    for target_col, aliases in CICFLOWMETER_ALIASES.items():
        if target_col not in df.columns:
            for alias in aliases:
                if alias in df.columns:
                    df[target_col] = df[alias]
                    break

    # fuzzy alias creation using normalized names
    clean_to_original = {}
    for col in df.columns:
        clean_to_original.setdefault(standardize_col_name(col), col)

    for source_clean, target_col in HARDCODED_MAP.items():
        if target_col not in df.columns and source_clean in clean_to_original:
            df[target_col] = df[clean_to_original[source_clean]]

    return df


def standardize_col_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _positive_class_proba(prob_output):
    prob_output = np.asarray(prob_output)
    if prob_output.ndim == 1:
        return prob_output.astype(np.float32)
    if prob_output.ndim == 2 and prob_output.shape[1] == 1:
        return prob_output[:, 0].astype(np.float32)
    if prob_output.ndim == 2 and prob_output.shape[1] >= 2:
        return prob_output[:, 1].astype(np.float32)
    raise ValueError(f"Unexpected probability shape: {prob_output.shape}")


def _format_top_counts(counter_obj, top_k=3):
    items = counter_obj.most_common(top_k)
    out = [f"{label} ({count} rows)" for label, count in items]
    while len(out) < top_k:
        out.append("-")
    return out


def _apply_fuzzy_training_map(df: pd.DataFrame, train_feature_cols: list[str]):
    # Add standard columns for the exact CICFlowMeter output before feature matching.
    df = _add_cicflowmeter_alias_columns(df.copy())

    train_feature_map = {standardize_col_name(col): col for col in train_feature_cols}
    rename_dict = {}

    for col in df.columns:
        clean_col = standardize_col_name(col)
        if clean_col in HARDCODED_MAP:
            clean_col = standardize_col_name(HARDCODED_MAP[clean_col])

        if clean_col in train_feature_map:
            rename_dict[col] = train_feature_map[clean_col]

    df = df.rename(columns=rename_dict)

    duplicate_targets = df.columns[df.columns.duplicated()].tolist()
    if duplicate_targets:
        df = df.loc[:, ~df.columns.duplicated(keep="first")].copy()

    return df, rename_dict, duplicate_targets


def _build_feature_matrix(df_csv: pd.DataFrame, feature_cols: list[str], fillna_medians):
    X_inf = pd.DataFrame(index=df_csv.index)
    missing_feature_names = []

    for col in feature_cols:
        if col in df_csv.columns:
            X_inf[col] = df_csv[col]
        else:
            X_inf[col] = np.nan
            missing_feature_names.append(col)

    X_inf = (
        X_inf.apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(fillna_medians)
        .fillna(0)
    )

    missing_count = len(missing_feature_names)
    matched_count = len(feature_cols) - missing_count
    coverage = round(100.0 * matched_count / max(1, len(feature_cols)), 2)
    return X_inf, matched_count, missing_count, coverage, missing_feature_names



def _binary_predict_exact(df_csv: pd.DataFrame, file_name: str):
    xgb_bundle = get_binary_xgb_bundle()
    lstm_bundle = get_binary_lstm_bundle()

    flows_count = len(df_csv)
    if flows_count == 0:
        return {
            "file": file_name,
            "flows": 0,
            "lstm_mean": 0.0,
            "lstm_atk_percent": 0.0,
            "lstm_count": 0,
            "xgb_mean": 0.0,
            "xgb_atk_percent": 0.0,
            "xgb_count": 0,
            "ENSEMBLE": "EMPTY FILE",
            "status": "Skipped",
            "alert_tolerance": ALERT_TOLERANCE,
            "seq_len": int(lstm_bundle["seq_len"]),
            "stride": int(lstm_bundle["stride"]),
            "xgb_threshold": float(xgb_bundle["threshold"]),
            "lstm_threshold": float(lstm_bundle["threshold"]),
            "matched_features": 0,
            "missing_features": len(xgb_bundle["feature_cols"]),
            "missing_feature_names": list(xgb_bundle["feature_cols"]),
            "feature_coverage_percent": 0.0,
            "duplicate_mapped_columns": [],
            "fuzzy_renamed_columns_count": 0,
            "lstm_window_count": 0,
        }

    df_mapped, rename_dict, duplicate_targets = _apply_fuzzy_training_map(
        df_csv.copy(),
        xgb_bundle["feature_cols"],
    )

    X_inf, matched_count, missing_count, coverage, missing_feature_names = _build_feature_matrix(
        df_mapped,
        xgb_bundle["feature_cols"],
        xgb_bundle["fillna_medians"],
    )

    X_np = np.clip(X_inf.to_numpy(dtype=np.float32), -1e6, 1e6)

    xp = _positive_class_proba(xgb_bundle["model"].predict_proba(X_np))
    x_mean = float(xp.mean()) if len(xp) else 0.0
    x_malicious_count = int((xp >= xgb_bundle["threshold"]).sum())
    x_atk = float((x_malicious_count / max(1, flows_count)) * 100.0)

    X_sc = lstm_bundle["scaler"].transform(X_np).astype(np.float32)

    if flows_count < int(lstm_bundle["seq_len"]):
        l_mean = 0.0
        l_atk = 0.0
        l_malicious_count = 0
        lstm_window_count = 0

        if x_malicious_count > ALERT_TOLERANCE:
            ensemble = f"ATTACK  (XGB caught {x_malicious_count})"
        else:
            ensemble = "BENIGN"
    else:
        X_seq, _ = make_lstm_windows_for_inference(
            X_sc,
            seq_len=int(lstm_bundle["seq_len"]),
            stride=int(lstm_bundle["stride"]),
        )

        if len(X_seq) > 0:
            lp = lstm_bundle["model"].predict(X_seq, batch_size=512, verbose=0)
            lp = _positive_class_proba(lp)
            l_mean = float(np.nan_to_num(lp.mean()))
            l_malicious_count = int((lp >= lstm_bundle["threshold"]).sum())
            l_atk = float((l_malicious_count / len(X_seq)) * 100.0)
            lstm_window_count = int(len(X_seq))
        else:
            l_mean = 0.0
            l_atk = 0.0
            l_malicious_count = 0
            lstm_window_count = 0

        if l_malicious_count > ALERT_TOLERANCE and x_malicious_count > ALERT_TOLERANCE:
            ensemble = "ATTACK "
        elif l_malicious_count > ALERT_TOLERANCE or x_malicious_count > ALERT_TOLERANCE:
            ensemble = "ATTACK"
        else:
            ensemble = "BENIGN"

    return {
        "file": file_name,
        "flows": int(flows_count),
        "lstm_mean": round(l_mean, 4),
        "lstm_atk_percent": round(l_atk, 2),
        "lstm_count": int(l_malicious_count),
        "xgb_mean": round(x_mean, 4),
        "xgb_atk_percent": round(x_atk, 2),
        "xgb_count": int(x_malicious_count),
        "ENSEMBLE": ensemble,
        "status": "OK",
        "alert_tolerance": ALERT_TOLERANCE,
        "seq_len": int(lstm_bundle["seq_len"]),
        "stride": int(lstm_bundle["stride"]),
        "xgb_threshold": float(xgb_bundle["threshold"]),
        "lstm_threshold": float(lstm_bundle["threshold"]),
        "matched_features": int(matched_count),
        "missing_features": int(missing_count),
        "missing_feature_names": missing_feature_names,
        "feature_coverage_percent": float(coverage),
        "duplicate_mapped_columns": duplicate_targets,
        "fuzzy_renamed_columns_count": len(rename_dict),
        "lstm_window_count": int(lstm_window_count),
    }


def _should_run_multiclass(binary_summary: dict) -> bool:
    decision = str(binary_summary.get("ENSEMBLE", "")).strip().lower()
    return "attack" in decision


def _multiclass_predict_full_file(df_csv: pd.DataFrame, file_name: str):
    if not multiclass_available():
        return {
            "file": file_name,
            "status": "not_available",
            "mode": "-",
            "Total_Flows": int(len(df_csv)),
            "Effective_Predictions": 0,
            "Matched_Features": 0,
            "Missing_Features": 0,
            "Feature_Coverage_%": 0.0,
            "Avg_Confidence": 0.0,
            "Agreement_Rate_%": None,
            "Unknown_Rate_%": None,
            "Top_1_Attack": "-",
            "Top_2_Attack": "-",
            "Top_3_Attack": "-",
            "Error": "Multiclass artifacts not available",
            "display_attack_type_summary": {},
            "message": "Multiclass artifacts not available",
        }, pd.DataFrame()

    predictor = get_multiclass_predictor()
    detail_df, meta = predictor.predict_dataframe(df_csv.copy(), source_name=file_name)

    total_flows = int(len(df_csv))
    if detail_df.empty:
        return {
            "file": file_name,
            "status": "ok",
            "mode": meta.get("mode", "-"),
            "Total_Flows": total_flows,
            "Effective_Predictions": 0,
            "Matched_Features": int(meta.get("matched_features", 0)),
            "Missing_Features": int(meta.get("missing_features", 0)),
            "Feature_Coverage_%": float(meta.get("coverage", 0.0)),
            "Avg_Confidence": 0.0,
            "Agreement_Rate_%": None,
            "Unknown_Rate_%": None,
            "Top_1_Attack": "-",
            "Top_2_Attack": "-",
            "Top_3_Attack": "-",
            "Error": "",
            "display_attack_type_summary": {},
            "message": "No effective multiclass predictions were produced",
        }, detail_df

    final_status_series = detail_df["attack_type_status"].fillna("UNKNOWN").astype(str)
    display_label_series = detail_df["attack_type"].fillna("UNKNOWN").astype(str)

# Use attack_type for the visible top cards and table,
# so Top 1 Attack matches the Attack Type Summary table.
    display_counts = Counter(display_label_series.tolist())
    top3 = _format_top_counts(display_counts, top_k=3)
    avg_conf = round(
        float(pd.to_numeric(detail_df["attack_type_confidence"], errors="coerce").fillna(0).mean()),
        4
    )

    if "xgb_pred" in detail_df.columns and "lstm_pred" in detail_df.columns:
        agreement_mask = (
            detail_df["xgb_pred"].fillna("").astype(str)
            ==
            detail_df["lstm_pred"].fillna("").astype(str)
        )
        agreement_rate = round(100.0 * float(agreement_mask.mean()), 2) if len(detail_df) else None
    else:
        agreement_rate = None

    unknown_rate = round(
        100.0 * float(final_status_series.str.startswith("UNKNOWN").mean()),
        2
    ) if len(detail_df) else None

    summary = {
        "file": file_name,
        "status": "ok",
        "mode": meta.get("mode", "-"),
        "Total_Flows": total_flows,
        "Effective_Predictions": int(len(detail_df)),
        "Matched_Features": int(meta.get("matched_features", 0)),
        "Missing_Features": int(meta.get("missing_features", 0)),
        "Feature_Coverage_%": float(meta.get("coverage", 0.0)),
        "Avg_Confidence": avg_conf,
        "Agreement_Rate_%": agreement_rate,
        "Unknown_Rate_%": unknown_rate,
        "Top_1_Attack": top3[0],
        "Top_2_Attack": top3[1],
        "Top_3_Attack": top3[2],
        "Error": "",
        "display_attack_type_summary": dict(Counter(display_label_series.tolist())),
        "message": "Multiclass executed because the official binary decision was ATTACK.",
    }

    return summary, detail_df


def _multiclass_skipped_summary(file_name: str, total_flows: int):
    return {
        "file": file_name,
        "status": "skipped",
        "mode": "-",
        "Total_Flows": int(total_flows),
        "Effective_Predictions": 0,
        "Matched_Features": 0,
        "Missing_Features": 0,
        "Feature_Coverage_%": 0.0,
        "Avg_Confidence": 0.0,
        "Agreement_Rate_%": None,
        "Unknown_Rate_%": None,
        "Top_1_Attack": "-",
        "Top_2_Attack": "-",
        "Top_3_Attack": "-",
        "Error": "",
        "display_attack_type_summary": {},
        "message": "Multiclass was skipped because the official binary decision was not ATTACK.",
    }


def _zero_day_skipped_summary(file_name: str, total_flows: int, reason: str):
    return {
        "file": file_name,
        "status": "skipped",
        "model_type": "autoencoder",
        "decision": "SKIPPED",
        "message": reason,
        "rows": int(total_flows),
        "threshold": None,
        "mean_reconstruction_error": None,
        "max_reconstruction_error": None,
        "anomalous_rows": 0,
        "normal_rows": int(total_flows),
        "anomaly_rate_percent": 0.0,
        "feature_count": 0,
        "matched_features": 0,
        "missing_features": 0,
        "feature_coverage_percent": 0.0,
        "top_anomalous_rows": [],
    }


def _build_top_level_summary(binary_summary: dict, multiclass_summary: dict):
    flows = int(binary_summary.get("flows", 0))
    decision = str(binary_summary.get("ENSEMBLE", "UNKNOWN"))

    multiclass_effective = int(multiclass_summary.get("Effective_Predictions", 0) or 0)
    attack_type_summary = multiclass_summary.get("display_attack_type_summary", {}) or {}

    # If multiclass ran successfully, trust multiclass row count.
    # Binary only decides ATTACK/BENIGN, but multiclass gives the real attack row count.
    if "attack" in decision.lower():
        if multiclass_effective > 0:
            attack_count = multiclass_effective
            attack_count_source = "multiclass_effective_predictions"
        else:
            # fallback only if multiclass failed or unavailable
            attack_count = int(binary_summary.get("xgb_count", 0))
            attack_count_source = "binary_xgb_fallback"

        benign_count = max(0, flows - attack_count)
        attack_rate = round((attack_count / max(1, flows)) * 100.0, 2)
    else:
        attack_count = 0
        benign_count = flows
        attack_rate = 0.0
        attack_count_source = "binary_benign"

    return {
        "flows_analyzed": flows,
        "attack_count": int(attack_count),
        "benign_count": int(benign_count),
        "attack_rate": float(attack_rate),
        "attack_count_source": attack_count_source,
        "official_binary_decision": decision,
        "prediction_summary": {
            "official_binary_decision": decision,
            "binary_status": binary_summary.get("status", "UNKNOWN"),
            "multiclass_status": multiclass_summary.get("status", "UNKNOWN"),
            "xgb_attack_rows": int(binary_summary.get("xgb_count", 0)),
            "lstm_attack_windows": int(binary_summary.get("lstm_count", 0)),
            "multiclass_attack_rows": int(multiclass_effective),
        },
        "attack_type_summary": attack_type_summary,
    }
def analyze_flow_csv(csv_path: str):
    csv_path = str(Path(csv_path))
    file_name = Path(csv_path).name

    df_raw = pd.read_csv(csv_path, low_memory=False)
    # Add columns that match the training dataset/model naming.
    # This keeps the original CICFlowMeter columns and creates compatible aliases.
    df_raw = _add_cicflowmeter_alias_columns(df_raw)

    if df_raw.empty:
        empty_binary = {
            "file": file_name,
            "flows": 0,
            "lstm_mean": 0.0,
            "lstm_atk_percent": 0.0,
            "lstm_count": 0,
            "xgb_mean": 0.0,
            "xgb_atk_percent": 0.0,
            "xgb_count": 0,
            "ENSEMBLE": "EMPTY FILE",
            "status": "Skipped",
            "alert_tolerance": ALERT_TOLERANCE,
            "seq_len": 20,
            "stride": 5,
            "xgb_threshold": 0.5,
            "lstm_threshold": 0.5,
            "matched_features": 0,
            "missing_features": 0,
            "missing_feature_names": [],
            "feature_coverage_percent": 0.0,
            "duplicate_mapped_columns": [],
            "fuzzy_renamed_columns_count": 0,
            "lstm_window_count": 0,
        }

        empty_multi = _multiclass_skipped_summary(file_name, 0)
        summary = _build_top_level_summary(empty_binary, empty_multi)

        empty_zero_day = {
            "status": "skipped",
            "model_type": "autoencoder",
            "decision": "EMPTY",
            "message": "Empty file. Zero-day detector skipped.",
            "rows": 0,
            "threshold": None,
            "mean_reconstruction_error": None,
            "max_reconstruction_error": None,
            "anomalous_rows": 0,
            "normal_rows": 0,
            "anomaly_rate_percent": 0.0,
            "feature_count": 0,
            "matched_features": 0,
            "missing_features": 0,
            "missing_feature_names": [],
            "feature_coverage_percent": 0.0,
            "top_anomalous_rows": [],
        }

        return [], {
            "binary_summary": empty_binary,
            "multiclass_summary": empty_multi,
            "zero_day_summary": empty_zero_day,
            "zero_day_details": [],
            "summary": summary,
        }

    binary_summary = _binary_predict_exact(df_raw.copy(), file_name)

    # Multiclass model runs ONLY when binary says ATTACK
    if _should_run_multiclass(binary_summary):
        multiclass_summary, multiclass_detail_df = _multiclass_predict_full_file(
            df_raw.copy(),
            file_name
        )
        results = multiclass_detail_df.to_dict(orient="records") if not multiclass_detail_df.empty else []
    else:
        multiclass_summary = _multiclass_skipped_summary(file_name, len(df_raw))
        results = []

    # Zero-Day model runs ONLY when binary says BENIGN / SAFE
    # If binary says ATTACK, Zero-Day will be skipped
    if not _should_run_multiclass(binary_summary):
        zero_day_summary, zero_day_details = predict_zero_day_dataframe(
            df_raw.copy(),
            source_name=file_name
        )
    else:
        zero_day_summary = _zero_day_skipped_summary(
            file_name,
            len(df_raw),
            "Zero-day detector skipped because the official binary decision was ATTACK. Autoencoder is only executed for files classified as BENIGN/SAFE by the binary model.",
        )
        zero_day_details = []

    summary = _build_top_level_summary(binary_summary, multiclass_summary)

    return results, {
        "binary_summary": binary_summary,
        "multiclass_summary": multiclass_summary,
        "zero_day_summary": zero_day_summary,
        "zero_day_details": zero_day_details,
        "summary": summary,
    }