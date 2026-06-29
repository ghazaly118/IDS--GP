import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
import tensorflow as tf

from app.multiclass_predictor import MultiClassPredictor


BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

BINARY_XGB_DIR = MODELS_DIR / "cicids_xgb_flow_v1"
BINARY_LSTM_DIR = MODELS_DIR / "cicids_lstm_out_v2"
MULTICLASS_DIR = MODELS_DIR / "multiclass_stage2"


def _first_existing(directory: Path, patterns: list[str]):
    for pattern in patterns:
        files = sorted(directory.glob(pattern))
        if files:
            return files[0]
    return None


def _load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def get_binary_xgb_bundle():
    if not BINARY_XGB_DIR.exists():
        raise FileNotFoundError(f"Missing binary XGBoost directory: {BINARY_XGB_DIR}")

    joblib_files = sorted(BINARY_XGB_DIR.glob("*.joblib"))
    if not joblib_files:
        raise FileNotFoundError(f"No .joblib files found inside {BINARY_XGB_DIR}")

    last_error = None
    for path in joblib_files:
        try:
            obj = joblib.load(path)

            if isinstance(obj, dict):
                model = obj.get("model") or obj.get("xgb_model") or obj.get("classifier")
                feature_cols = obj.get("feature_cols")
                fillna_medians = obj.get("fillna_medians") or obj.get("medians") or {}
                threshold = float(obj.get("best_threshold", obj.get("threshold", 0.5)))

                if model is not None and feature_cols is not None:
                    return {
                        "path": str(path),
                        "model": model,
                        "feature_cols": feature_cols,
                        "fillna_medians": pd.Series(fillna_medians),
                        "threshold": threshold,
                    }
        except Exception as e:
            last_error = e

    raise RuntimeError(f"Could not load a valid binary XGBoost bundle from {BINARY_XGB_DIR}. Last error: {last_error}")


@lru_cache(maxsize=1)
def get_binary_lstm_bundle():
    if not BINARY_LSTM_DIR.exists():
        raise FileNotFoundError(f"Missing binary LSTM directory: {BINARY_LSTM_DIR}")

    model_path = _first_existing(BINARY_LSTM_DIR, ["*.keras"])
    scaler_path = _first_existing(BINARY_LSTM_DIR, ["scaler.joblib", "*.joblib"])
    meta_path = _first_existing(BINARY_LSTM_DIR, ["meta.json", "*.json"])

    if model_path is None:
        raise FileNotFoundError(f"No LSTM .keras model found in {BINARY_LSTM_DIR}")
    if scaler_path is None:
        raise FileNotFoundError(f"No scaler.joblib found in {BINARY_LSTM_DIR}")
    if meta_path is None:
        raise FileNotFoundError(f"No meta.json found in {BINARY_LSTM_DIR}")

    meta = _load_json(meta_path)
    model = tf.keras.models.load_model(model_path, compile=False)
    scaler = joblib.load(scaler_path)

    return {
        "path": str(model_path),
        "model": model,
        "scaler": scaler,
        "feature_cols": meta["feature_cols"],
        "seq_len": int(meta.get("seq_len", 20)),
        "stride": int(meta.get("stride", 5)),
        "threshold": float(meta.get("best_threshold", 0.5)),
        "meta": meta,
    }


@lru_cache(maxsize=1)
def get_multiclass_predictor():
    return MultiClassPredictor()


def multiclass_available():
    required = [
        MULTICLASS_DIR / "xgb_multiclass.joblib",
        MULTICLASS_DIR / "lstm_multiclass.keras",
        MULTICLASS_DIR / "prep_artifacts.joblib",
        MULTICLASS_DIR / "scaler.joblib",
    ]
    return all(p.exists() for p in required)