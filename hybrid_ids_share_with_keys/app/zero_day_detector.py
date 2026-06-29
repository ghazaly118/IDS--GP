"""
Zero-Day Autoencoder detector for the Hybrid IDS project.

Expected artifacts:
    models/zero_day_autoencoder/autoencoder_zero_day.keras
    models/zero_day_autoencoder/scaler.joblib
    models/zero_day_autoencoder/meta.json

The model is treated as optional. If the artifacts are not available yet, the
pipeline keeps running and returns status='not_available' instead of crashing.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_ZERO_DAY_DIR = BASE_DIR / "models" / "zero_day_autoencoder"


TON_MAP = {
    "fl_dur": "Flow Duration", "tot_fw_pk": "Total Fwd Packets", "tot_bw_pk": "Total Backward Packets",
    "tot_l_fw_pkt": "Fwd Packets Length Total", "tot_l_bw_pkt": "Bwd Packets Length Total",
    "fw_pkt_l_max": "Fwd Packet Length Max", "fw_pkt_l_min": "Fwd Packet Length Min",
    "fw_pkt_l_avg": "Fwd Packet Length Mean", "fw_pkt_l_std": "Fwd Packet Length Std",
    "Bw_pkt_l_max": "Bwd Packet Length Max", "Bw_pkt_l_min": "Bwd Packet Length Min",
    "Bw_pkt_l_avg": "Bwd Packet Length Mean", "Bw_pkt_l_std": "Bwd Packet Length Std",
    "fl_byt_s": "Flow Bytes/s", "fl_pkt_s": "Flow Packets/s", "fl_iat_avg": "Flow IAT Mean",
    "fl_iat_std": "Flow IAT Std", "fl_iat_max": "Flow IAT Max", "fl_iat_min": "Flow IAT Min",
    "fw_iat_tot": "Fwd IAT Total", "fw_iat_avg": "Fwd IAT Mean", "fw_iat_std": "Fwd IAT Std",
    "fw_iat_max": "Fwd IAT Max", "fw_iat_min": "Fwd IAT Min", "bw_iat_tot": "Bwd IAT Total",
    "bw_iat_avg": "Bwd IAT Mean", "bw_iat_std": "Bwd IAT Std", "bw_iat_max": "Bwd IAT Max",
    "bw_iat_min": "Bwd IAT Min", "fw_psh_flag": "Fwd PSH Flags", "bw_psh_flag": "Bwd PSH Flags",
    "fw_urg_flag": "Fwd URG Flags", "bw_urg_flag": "Bwd URG Flags", "fw_hdr_len": "Fwd Header Length",
    "bw_hdr_len": "Bwd Header Length", "fw_pkt_s": "Fwd Packets/s", "bw_pkt_s": "Bwd Packets/s",
    "pkt_len_min": "Packet Length Min", "pkt_len_max": "Packet Length Max",
    "pkt_len_avg": "Packet Length Mean", "pkt_len_std": "Packet Length Std",
    "pkt_len_va": "Packet Length Variance", "fin_cnt": "FIN Flag Count", "syn_cnt": "SYN Flag Count",
    "rst_cnt": "RST Flag Count", "pst_cnt": "PSH Flag Count", "ack_cnt": "ACK Flag Count",
    "urg_cnt": "URG Flag Count", "cwe_cnt": "CWE Flag Count", "ece_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Avg Packet Size",
    "fw_seg_avg": "Avg Fwd Segment Size", "bw_seg_avg": "Avg Bwd Segment Size",
    "subfl_fw_pk": "Subflow Fwd Packets", "subfl_fw_byt": "Subflow Fwd Bytes",
    "subfl_bw_pkt": "Subflow Bwd Packets", "subfl_bw_byt": "Subflow Bwd Bytes",
    "fw_win_byt": "Init Fwd Win Bytes", "bw_win_byt": "Init Bwd Win Bytes",
    "Fw_act_pkt": "Fwd Act Data Packets", "fw_seg_min": "Fwd Seg Size Min",
    "atv_avg": "Active Mean", "atv_std": "Active Std", "atv_max": "Active Max", "atv_min": "Active Min",
    "idl_avg": "Idle Mean", "idl_std": "Idle Std", "idl_max": "Idle Max", "idl_min": "Idle Min",
}

DDOS2019_MAP = {
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "FWD Init Win Bytes": "Init Fwd Win Bytes",
    "Bwd Init Win Bytes": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
    "CWR Flag Count": "CWE Flag Count",
}

HARDCODED_MAP = {
    "totallengthoffwdpacket": "Fwd Packets Length Total",
    "totallengthofbwdpacket": "Bwd Packets Length Total",
    "totalfwdpacket": "Total Fwd Packets",
    "totalbwdpackets": "Total Backward Packets",
    "fwdsegmentsizeavg": "Avg Fwd Segment Size",
    "bwdsegmentsizeavg": "Avg Bwd Segment Size",
    "cwrflagcount": "CWE Flag Count",
}


def standardize_col_name(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _artifact_dir() -> Path:
    return Path(os.getenv("ZERO_DAY_MODEL_DIR", str(DEFAULT_ZERO_DAY_DIR))).resolve()


def _missing_summary(message: str, artifact_dir: Path | None = None) -> dict[str, Any]:
    return {
        "status": "not_available",
        "model_type": "autoencoder",
        "decision": "UNAVAILABLE",
        "message": message,
        "artifact_dir": str(artifact_dir or _artifact_dir()),
        "required_files": ["autoencoder_zero_day.keras", "scaler.joblib", "meta.json"],
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
        "feature_coverage_percent": 0.0,
        "top_anomalous_rows": [],
    }


def _check_artifacts(artifact_dir: Path) -> tuple[bool, list[str]]:
    required = [
        artifact_dir / "autoencoder_zero_day.keras",
        artifact_dir / "scaler.joblib",
        artifact_dir / "meta.json",
    ]
    missing = [str(p) for p in required if not p.exists()]
    return len(missing) == 0, missing


@lru_cache(maxsize=1)
def _load_bundle() -> dict[str, Any]:
    artifact_dir = _artifact_dir()
    ok, missing = _check_artifacts(artifact_dir)
    if not ok:
        raise FileNotFoundError("Missing zero-day artifacts: " + ", ".join(missing))

    try:
        import tensorflow as tf  # imported lazily so the app can run even before TensorFlow is installed
        import joblib
    except Exception as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(f"Required zero-day dependencies are missing: {exc}") from exc

    model = tf.keras.models.load_model(artifact_dir / "autoencoder_zero_day.keras")
    scaler = joblib.load(artifact_dir / "scaler.joblib")
    with open(artifact_dir / "meta.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    return {
        "model": model,
        "scaler": scaler,
        "meta": meta,
        "artifact_dir": artifact_dir,
        "feature_cols": list(meta.get("feature_cols", [])),
        "fillna_medians": meta.get("fillna_medians", {}) or {},
        "threshold": float(meta.get("threshold", 0.0)),
    }


def zero_day_available() -> bool:
    ok, _ = _check_artifacts(_artifact_dir())
    return ok


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns=TON_MAP)
    df = df.rename(columns=DDOS2019_MAP)
    return df


def _apply_fuzzy_feature_map(df: pd.DataFrame, feature_cols: list[str]) -> tuple[pd.DataFrame, int, list[str]]:
    df = _normalize_columns(df)
    train_feature_map = {standardize_col_name(col): col for col in feature_cols}
    rename_dict: dict[str, str] = {}

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

    return df, len(rename_dict), duplicate_targets


def _build_matrix(df: pd.DataFrame, feature_cols: list[str], fillna_medians: dict[str, Any]) -> tuple[np.ndarray, int, int, float]:
    X = pd.DataFrame(index=df.index)
    missing_count = 0

    for col in feature_cols:
        if col in df.columns:
            X[col] = df[col]
        else:
            X[col] = np.nan
            missing_count += 1

    X = (
        X.apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(fillna_medians)
        .fillna(0)
    )

    matched_count = len(feature_cols) - missing_count
    coverage = round(100.0 * matched_count / max(1, len(feature_cols)), 2)
    X_np = np.clip(X.to_numpy(dtype=np.float32), -1e6, 1e6)
    return X_np, matched_count, missing_count, coverage


def _source_value(row: pd.Series, candidates: list[str]) -> Any:
    for col in candidates:
        if col in row.index:
            value = row[col]
            if pd.notna(value) and str(value).strip():
                return value
    return None


def predict_zero_day_dataframe(df_raw: pd.DataFrame, source_name: str = "uploaded.csv", max_detail_rows: int = 500) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run autoencoder anomaly detection on an already-loaded flow dataframe."""
    if df_raw is None or df_raw.empty:
        summary = _missing_summary("Empty file. Zero-day detector skipped.")
        summary.update({"status": "skipped", "decision": "EMPTY", "rows": 0})
        return summary, []

    artifact_dir = _artifact_dir()
    ok, missing = _check_artifacts(artifact_dir)
    if not ok:
        return _missing_summary("Zero-day model artifacts are not installed yet.", artifact_dir), []

    try:
        bundle = _load_bundle()
        feature_cols = bundle["feature_cols"]
        if not feature_cols:
            return _missing_summary("meta.json does not contain feature_cols.", artifact_dir), []

        df_mapped, renamed_count, duplicate_targets = _apply_fuzzy_feature_map(df_raw.copy(), feature_cols)
        X_np, matched_count, missing_count, coverage = _build_matrix(
            df_mapped,
            feature_cols,
            bundle["fillna_medians"],
        )
        X_sc = bundle["scaler"].transform(X_np)
        reconstructed = bundle["model"].predict(X_sc, batch_size=2048, verbose=0)
        reconstruction_error = np.mean(np.square(X_sc - reconstructed), axis=1)

        threshold = float(bundle["threshold"])
        pred_binary = (reconstruction_error > threshold).astype(int)
        anomalous_rows = int(pred_binary.sum())
        rows = int(len(df_raw))
        anomaly_rate = float(100.0 * anomalous_rows / max(1, rows))
        decision = "POSSIBLE_ZERO_DAY" if anomalous_rows > 0 else "NORMAL"

        detail_df = pd.DataFrame({
            "flow_index": list(range(rows)),
            "reconstruction_error": reconstruction_error,
            "zero_day_prediction": np.where(pred_binary == 1, "POSSIBLE_ZERO_DAY", "NORMAL"),
            "above_threshold": pred_binary.astype(bool),
        })

        # Preserve common IP columns when present; this helps the IR agent and UI.
        for out_col, candidates in {
            "source_ip": ["Source IP", "Src IP", "src", "source_ip"],
            "destination_ip": ["Destination IP", "Dst IP", "dst", "destination_ip"],
        }.items():
            detail_df[out_col] = [
                _source_value(df_raw.iloc[i], candidates) for i in range(rows)
            ]

        top_df = detail_df.sort_values("reconstruction_error", ascending=False).head(max_detail_rows)
        detail_rows = top_df.to_dict(orient="records")
        top_anomalous_rows = [
            {
                "flow_index": int(row["flow_index"]),
                "reconstruction_error": float(row["reconstruction_error"]),
                "zero_day_prediction": row["zero_day_prediction"],
                "source_ip": row.get("source_ip"),
                "destination_ip": row.get("destination_ip"),
            }
            for _, row in top_df.head(10).iterrows()
        ]

        summary = {
            "status": "ok",
            "model_type": "autoencoder",
            "decision": decision,
            "message": "Zero-day autoencoder executed successfully.",
            "file": source_name,
            "artifact_dir": str(artifact_dir),
            "rows": rows,
            "threshold": threshold,
            "mean_reconstruction_error": float(np.mean(reconstruction_error)) if rows else 0.0,
            "max_reconstruction_error": float(np.max(reconstruction_error)) if rows else 0.0,
            "anomalous_rows": anomalous_rows,
            "normal_rows": int(rows - anomalous_rows),
            "anomaly_rate_percent": round(anomaly_rate, 4),
            "feature_count": int(len(feature_cols)),
            "matched_features": int(matched_count),
            "missing_features": int(missing_count),
            "feature_coverage_percent": float(coverage),
            "fuzzy_renamed_columns_count": int(renamed_count),
            "duplicate_mapped_columns": duplicate_targets,
            "top_anomalous_rows": top_anomalous_rows,
        }
        return summary, detail_rows
    except Exception as exc:
        summary = _missing_summary(f"Zero-day detector failed: {exc}", artifact_dir)
        summary["status"] = "error"
        return summary, []


def predict_zero_day_csv(csv_path: str, max_detail_rows: int = 500) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = Path(csv_path)
    df = pd.read_csv(path, low_memory=False)
    return predict_zero_day_dataframe(df, source_name=path.name, max_detail_rows=max_detail_rows)
