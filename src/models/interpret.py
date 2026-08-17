"""SHAP-based interpretability for a trained pipeline: global importance and per-CVE explanations."""

import numpy as np
import pandas as pd
import shap

from src.models.dataset import get_X_y

TOP_N_CONTRIBUTIONS = 10


def build_explainer(pipeline) -> shap.TreeExplainer:
    return shap.TreeExplainer(pipeline.named_steps["classifier"])


def get_feature_names(pipeline) -> list[str]:
    return list(pipeline.named_steps["preprocess"].get_feature_names_out())


def compute_shap_values(pipeline, X: pd.DataFrame) -> np.ndarray:
    explainer = build_explainer(pipeline)
    X_transformed = pipeline.named_steps["preprocess"].transform(X)
    return explainer.shap_values(X_transformed)


def global_importance(pipeline, X: pd.DataFrame) -> pd.DataFrame:
    shap_values = compute_shap_values(pipeline, X)
    feature_names = get_feature_names(pipeline)
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    return (
        pd.DataFrame({"feature": feature_names, "mean_abs_shap": mean_abs_shap})
        .sort_values("mean_abs_shap", ascending=False)
        .reset_index(drop=True)
    )


def explain_row(pipeline, X_row: pd.DataFrame) -> dict:
    """Explain a single-row DataFrame of raw (untransformed) model features."""
    shap_values = compute_shap_values(pipeline, X_row)
    feature_names = get_feature_names(pipeline)
    proba = pipeline.predict_proba(X_row)[0, 1]

    contributions = sorted(zip(feature_names, shap_values[0]), key=lambda kv: -abs(kv[1]))
    return {
        "predicted_probability": float(proba),
        "top_contributions": [
            {"feature": name, "shap_value": float(value)} for name, value in contributions[:TOP_N_CONTRIBUTIONS]
        ],
    }


def explain_cve(cve_id: str, features_df: pd.DataFrame, pipeline) -> dict:
    row = features_df[features_df["cve_id"] == cve_id]
    if row.empty:
        raise ValueError(f"CVE {cve_id} not found in the feature table")

    X_row, _ = get_X_y(row)
    result = explain_row(pipeline, X_row)
    result["cve_id"] = cve_id
    return result
