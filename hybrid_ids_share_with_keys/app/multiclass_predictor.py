import re
import warnings
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf


BASE_DIR = Path(__file__).resolve().parent.parent
MULTICLASS_DIR = BASE_DIR / "models" / "multiclass_stage2"

XGB_MODEL_PATH = MULTICLASS_DIR / "xgb_multiclass.joblib"
LSTM_MODEL_PATH = MULTICLASS_DIR / "lstm_multiclass.keras"
PREP_ARTIFACTS_PATH = MULTICLASS_DIR / "prep_artifacts.joblib"
SCALER_PATH = MULTICLASS_DIR / "scaler.joblib"

INFERENCE_MODE = "ENSEMBLE"
CONFIDENCE_THRESHOLD = 0.72
MARGIN_THRESHOLD = 0.12
HIGH_CONF_OVERRIDE = 0.90

AMP_UNKNOWN_LABEL = "UNKNOWN (Novel DOS_FLOOD-like Amplification)"
AMP_PORTS = {53, 123, 161, 389, 11211, 1900, 47808, 10001, 37810, 500, 4500}


EXACT_COLUMN_MAPPING = {
    "Flow duration": "Flow Duration",
    "total Fwd Packet": "Total Fwd Packets",
    "Total Fwd Packet": "Total Fwd Packets",
    "total Bwd packets": "Total Backward Packets",
    "Total Bwd packets": "Total Backward Packets",
    "total Length of Fwd Packet": "Fwd Packets Length Total",
    "Total Length of Fwd Packet": "Fwd Packets Length Total",
    "total Length of Bwd Packet": "Bwd Packets Length Total",
    "Total Length of Bwd Packet": "Bwd Packets Length Total",
    "Fwd Packet Length Min": "Fwd Packet Length Min",
    "Fwd Packet Length Max": "Fwd Packet Length Max",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Min": "Fwd IAT Min",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Total": "Fwd IAT Total",
    "Bwd IAT Min": "Bwd IAT Min",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Total": "Bwd IAT Total",
    "Fwd PSH flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "FWD Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    "Packet Length Min": "Packet Length Min",
    "Packet Length Max": "Packet Length Max",
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",
    "CWR Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Count",
    "down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Avg Packet Size",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Fwd Init Win bytes": "Init Fwd Win Bytes",
    "FWD Init Win Bytes": "Init Fwd Win Bytes",
    "Bwd Init Win bytes": "Init Bwd Win Bytes",
    "Bwd Init Win Bytes": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Active Min": "Active Min",
    "Active Mean": "Active Mean",
    "Active Max": "Active Max",
    "Active Std": "Active Std",
    "Idle Min": "Idle Min",
    "Idle Mean": "Idle Mean",
    "Idle Max": "Idle Max",
    "Idle Std": "Idle Std",
}


def standardize_col_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def detect_timestamp_column(columns):
    standardized = {standardize_col_name(c): c for c in columns}
    candidates = ["timestamp", "flowstart", "flowstarttime", "starttime", "datetime", "time"]
    for cand in candidates:
        if cand in standardized:
            return standardized[cand]
    for clean_name, original_name in standardized.items():
        if "timestamp" in clean_name or "flowstart" in clean_name or "starttime" in clean_name:
            return original_name
    return None


def parse_timestamp_series(series):
    if pd.api.types.is_datetime64_any_dtype(series):
        return pd.to_datetime(series, errors="coerce", utc=True)

    s = series.astype(str).str.strip()
    candidate_formats = [
        "%d/%m/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
    ]

    best_parsed = None
    best_count = -1
    for fmt in candidate_formats:
        parsed = pd.to_datetime(s, format=fmt, errors="coerce", utc=True)
        count = int(parsed.notna().sum())
        if count > best_count:
            best_parsed = parsed
            best_count = count

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)

        parsed_dayfirst = pd.to_datetime(s, errors="coerce", utc=True, dayfirst=True)
        if int(parsed_dayfirst.notna().sum()) > best_count:
            best_parsed = parsed_dayfirst
            best_count = int(parsed_dayfirst.notna().sum())

        parsed_monthfirst = pd.to_datetime(s, errors="coerce", utc=True, dayfirst=False)
        if int(parsed_monthfirst.notna().sum()) > best_count:
            best_parsed = parsed_monthfirst
            best_count = int(parsed_monthfirst.notna().sum())

    if best_count > 0:
        return best_parsed

    numeric = pd.to_numeric(s, errors="coerce")
    if numeric.notna().any():
        median_abs = np.nanmedian(np.abs(numeric.to_numpy(dtype=np.float64)))
        if not np.isnan(median_abs):
            if median_abs > 1e16:
                unit = "ns"
            elif median_abs > 1e13:
                unit = "us"
            elif median_abs > 1e10:
                unit = "ms"
            else:
                unit = "s"
            return pd.to_datetime(numeric, errors="coerce", utc=True, unit=unit)

    return pd.to_datetime(s, errors="coerce", utc=True)


def temporally_sort_csv(df):
    df = df.copy()
    ts_col = detect_timestamp_column(df.columns)

    if ts_col is None:
        return df, None

    df["__parsed_time__"] = parse_timestamp_series(df[ts_col])
    df["__orig_order__"] = np.arange(len(df), dtype=np.int64)

    if df["__parsed_time__"].notna().any():
        df = df.sort_values(by=["__parsed_time__", "__orig_order__"], kind="mergesort").reset_index(drop=True)
    else:
        df = df.sort_values(by="__orig_order__", kind="mergesort").reset_index(drop=True)

    return df.drop(columns=["__parsed_time__", "__orig_order__"]), ts_col


def strict_align_columns(df, mapping_dict):
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns=mapping_dict)

    duplicate_targets = df.columns[df.columns.duplicated()].tolist()
    if duplicate_targets:
        df = df.loc[:, ~df.columns.duplicated(keep="first")].copy()

    return df, duplicate_targets


def build_inference_matrix(df, feature_cols, fillna_medians):
    X_inf = pd.DataFrame(index=df.index)

    for col in feature_cols:
        X_inf[col] = df[col] if col in df.columns else np.nan

    X_inf = (
        X_inf.apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(fillna_medians)
        .fillna(0)
    )

    matched_features = sum(1 for c in feature_cols if c in df.columns)
    missing_features = len(feature_cols) - matched_features
    coverage = round(100.0 * matched_features / max(1, len(feature_cols)), 2)
    return X_inf, matched_features, missing_features, coverage


def make_lstm_windows_for_inference(X_scaled, seq_len=20, stride=1):
    if len(X_scaled) < seq_len:
        return np.empty((0, seq_len, X_scaled.shape[1]), dtype=np.float32), np.array([], dtype=int)

    windows, last_flow_indices = [], []
    for start in range(0, len(X_scaled) - seq_len + 1, stride):
        end = start + seq_len
        windows.append(X_scaled[start:end])
        last_flow_indices.append(end - 1)

    return np.asarray(windows, dtype=np.float32), np.asarray(last_flow_indices, dtype=int)


def _find_first_existing_col(df, candidates):
    standardized = {standardize_col_name(c): c for c in df.columns}
    for cand in candidates:
        key = standardize_col_name(cand)
        if key in standardized:
            return standardized[key]
    return None


def amplification_hint(df_csv, fname=""):
    fname_lower = str(fname).lower()
    name_hint = fname_lower.startswith("amp.") or ".reflection." in fname_lower or ".synack" in fname_lower

    proto_col = _find_first_existing_col(df_csv, ["Protocol"])
    bwd_col = _find_first_existing_col(df_csv, ["Total Backward Packets", "Total Bwd packets", "Subflow Bwd Packets"])
    src_port_col = _find_first_existing_col(df_csv, ["Src Port", "Source Port"])
    dst_port_col = _find_first_existing_col(df_csv, ["Dst Port", "Destination Port"])

    udp_ratio = 0.0
    tcp_ratio = 0.0
    zero_bwd_ratio = 0.0
    amp_port_hit = False

    if proto_col is not None:
        proto = pd.to_numeric(df_csv[proto_col], errors="coerce")
        udp_ratio = float((proto == 17).mean()) if len(proto) else 0.0
        tcp_ratio = float((proto == 6).mean()) if len(proto) else 0.0

    if bwd_col is not None:
        bwd = pd.to_numeric(df_csv[bwd_col], errors="coerce").fillna(0)
        zero_bwd_ratio = float((bwd <= 1).mean()) if len(bwd) else 0.0

    ports = set()
    for c in [src_port_col, dst_port_col]:
        if c is not None:
            vals = pd.to_numeric(df_csv[c], errors="coerce").dropna().astype(int)
            ports.update(vals.unique().tolist())

    amp_port_hit = len(ports.intersection(AMP_PORTS)) > 0
    udp_amp = udp_ratio >= 0.70 and zero_bwd_ratio >= 0.70 and amp_port_hit
    tcp_reflectionish = tcp_ratio >= 0.70 and zero_bwd_ratio >= 0.70 and (name_hint or amp_port_hit)

    return {
        "is_amp": bool(name_hint or udp_amp or tcp_reflectionish),
        "udp_ratio": round(udp_ratio, 4),
        "tcp_ratio": round(tcp_ratio, 4),
        "zero_bwd_ratio": round(zero_bwd_ratio, 4),
        "amp_port_hit": bool(amp_port_hit),
        "name_hint": bool(name_hint),
    }


def remap_amp_label(final_label, xgb_decision, lstm_decision, ens_decision, amp_info):
    if not amp_info.get("is_amp", False):
        return final_label

    decisions = [d for d in [xgb_decision, lstm_decision, ens_decision] if d is not None]
    top1_votes = [d["top1"] for d in decisions]
    dos_flood_votes = sum(lbl == "DOS_FLOOD" for lbl in top1_votes)
    best_conf = max([d["conf"] for d in decisions], default=0.0)

    if final_label in {"BRUTEFORCE", "BOT", "WEBATTACK", "INFILTERATION"}:
        if dos_flood_votes >= 1 and best_conf >= 0.85:
            return "DOS_FLOOD"
        return AMP_UNKNOWN_LABEL

    if final_label == "UNKNOWN (Low/Confused)":
        if dos_flood_votes >= 2 and best_conf >= 0.85:
            return "DOS_FLOOD"
        return AMP_UNKNOWN_LABEL

    if final_label == "DOS_FLOOD" and dos_flood_votes >= 1:
        return "DOS_FLOOD"

    return final_label


def probs_to_decision(prob_row, class_names):
    prob_row = np.asarray(prob_row, dtype=np.float32)
    top2 = np.argsort(prob_row)[-2:][::-1]
    top1_idx = int(top2[0])
    top2_idx = int(top2[1]) if len(top2) > 1 else int(top2[0])

    conf = float(prob_row[top1_idx])
    margin = float(prob_row[top1_idx] - prob_row[top2_idx])

    label = class_names[top1_idx] if (conf >= CONFIDENCE_THRESHOLD and margin >= MARGIN_THRESHOLD) else "UNKNOWN (Low/Confused)"
    return {
        "label": label,
        "conf": conf,
        "margin": margin,
        "top1": class_names[top1_idx],
        "top2": class_names[top2_idx],
    }


def choose_final_label(xgb_decision=None, lstm_decision=None, ens_decision=None):
    available = [d for d in [xgb_decision, lstm_decision, ens_decision] if d is not None]
    confident = [d for d in available if d["label"] != "UNKNOWN (Low/Confused)"]
    labels = [d["label"] for d in confident]

    if labels:
        for lbl in set(labels):
            if labels.count(lbl) >= 2:
                return lbl

    if ens_decision is not None and ens_decision["label"] != "UNKNOWN (Low/Confused)":
        if (
            (xgb_decision is not None and xgb_decision["top1"] == ens_decision["top1"])
            or
            (lstm_decision is not None and lstm_decision["top1"] == ens_decision["top1"])
        ):
            return ens_decision["label"]

    best = max(available, key=lambda d: d["conf"]) if available else None
    if best is not None and best["conf"] >= HIGH_CONF_OVERRIDE:
        return best["top1"]

    return "UNKNOWN (Low/Confused)"


class MultiClassPredictor:
    def __init__(self):
        if not PREP_ARTIFACTS_PATH.exists():
            raise FileNotFoundError(f"Missing multiclass preprocessing artifacts: {PREP_ARTIFACTS_PATH}")
        if not SCALER_PATH.exists():
            raise FileNotFoundError(f"Missing multiclass scaler: {SCALER_PATH}")
        if not XGB_MODEL_PATH.exists():
            raise FileNotFoundError(f"Missing multiclass XGBoost model: {XGB_MODEL_PATH}")
        if not LSTM_MODEL_PATH.exists():
            raise FileNotFoundError(f"Missing multiclass LSTM model: {LSTM_MODEL_PATH}")

        artifacts = joblib.load(PREP_ARTIFACTS_PATH)
        self.feature_cols = artifacts["feature_cols"]
        self.fillna_medians = artifacts["fillna_medians"]
        self.class_names = artifacts["class_names"]
        self.seq_len = int(artifacts.get("seq_len", 20))
        self.stride = int(artifacts.get("stride", 5))

        self.scaler = joblib.load(SCALER_PATH)
        self.xgb_model = joblib.load(XGB_MODEL_PATH)
        self.lstm_model = tf.keras.models.load_model(LSTM_MODEL_PATH, compile=False)

    def predict_dataframe(self, df_csv: pd.DataFrame, source_name: str = "input.csv"):
        if len(df_csv) == 0:
            return pd.DataFrame(), {"error": "empty dataframe"}

        df_csv, ts_col = temporally_sort_csv(df_csv)
        df_csv, duplicate_targets = strict_align_columns(df_csv, EXACT_COLUMN_MAPPING)

        X_inf_df, matched_features, missing_features, coverage = build_inference_matrix(
            df_csv,
            self.feature_cols,
            self.fillna_medians,
        )

        X_raw_inf = np.clip(X_inf_df.to_numpy(dtype=np.float32), -1e6, 1e6)
        amp_info = amplification_hint(df_csv, source_name)

        X_scaled_inf = self.scaler.transform(X_raw_inf).astype(np.float32)
        X_windows, last_flow_idx = make_lstm_windows_for_inference(
            X_scaled_inf,
            seq_len=self.seq_len,
            stride=self.stride,
        )

        rows = []

        if len(X_windows) == 0:
            xgb_probs = self.xgb_model.predict_proba(X_raw_inf)
            for i, prob_row in enumerate(xgb_probs):
                xgb_decision = probs_to_decision(prob_row, self.class_names)
                final_label = remap_amp_label(
                    xgb_decision["label"],
                    xgb_decision,
                    None,
                    None,
                    amp_info,
                )
                rows.append({
                    "flow_index": i,
                    "attack_type": final_label if not str(final_label).startswith("UNKNOWN") else xgb_decision["top1"],
                    "attack_type_confidence": round(float(xgb_decision["conf"]), 4),
                    "attack_type_status": final_label,
                    "xgb_pred": xgb_decision["top1"],
                    "xgb_conf": round(float(xgb_decision["conf"]), 4),
                    "source_model": "xgboost_fallback",
                })

            return pd.DataFrame(rows), {
                "file": source_name,
                "mode": "XGBOOST_FALLBACK",
                "timestamp_col": ts_col,
                "matched_features": matched_features,
                "missing_features": missing_features,
                "coverage": coverage,
                "duplicate_mapped_columns": duplicate_targets,
                "amp_info": amp_info,
            }

        lstm_probs = self.lstm_model.predict(X_windows, batch_size=256, verbose=0)
        xgb_probs = self.xgb_model.predict_proba(X_raw_inf[last_flow_idx])
        ensemble_probs = 0.55 * xgb_probs + 0.45 * lstm_probs

        for j, flow_i in enumerate(last_flow_idx):
            xgb_decision = probs_to_decision(xgb_probs[j], self.class_names)
            lstm_decision = probs_to_decision(lstm_probs[j], self.class_names)
            ens_decision = probs_to_decision(ensemble_probs[j], self.class_names)

            raw_final_label = choose_final_label(xgb_decision, lstm_decision, ens_decision)
            final_label = remap_amp_label(
                raw_final_label,
                xgb_decision,
                lstm_decision,
                ens_decision,
                amp_info,
            )

            best_conf = max(
                float(xgb_decision["conf"]),
                float(lstm_decision["conf"]),
                float(ens_decision["conf"]),
            )

            rows.append({
                "flow_index": int(flow_i),
                "attack_type": final_label if not str(final_label).startswith("UNKNOWN") else ens_decision["top1"],
                "attack_type_confidence": round(best_conf, 4),
                "attack_type_status": final_label,
                "xgb_pred": xgb_decision["top1"],
                "xgb_conf": round(float(xgb_decision["conf"]), 4),
                "lstm_pred": lstm_decision["top1"],
                "lstm_conf": round(float(lstm_decision["conf"]), 4),
                "ensemble_pred": ens_decision["top1"],
                "ensemble_conf": round(float(ens_decision["conf"]), 4),
                "source_model": "ensemble",
            })

        pred_df = pd.DataFrame(rows).sort_values("flow_index").reset_index(drop=True)
        return pred_df, {
            "file": source_name,
            "mode": "ENSEMBLE",
            "timestamp_col": ts_col,
            "matched_features": matched_features,
            "missing_features": missing_features,
            "coverage": coverage,
            "duplicate_mapped_columns": duplicate_targets,
            "amp_info": amp_info,
        }

    def summarize_attack_types(self, pred_df: pd.DataFrame):
        if pred_df is None or pred_df.empty or "attack_type" not in pred_df.columns:
            return {}
        counts = Counter(pred_df["attack_type"].astype(str).tolist())
        return dict(counts)