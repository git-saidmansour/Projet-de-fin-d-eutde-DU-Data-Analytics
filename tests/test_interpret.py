import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from src.models.dataset import build_preprocessor, get_X_y
from src.models.interpret import explain_cve, explain_row, global_importance


def make_df(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    is_exploited = rng.binomial(1, 0.2, size=n)
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2024-{i:04d}" for i in range(n)],
            "cvss_base_score": rng.uniform(0, 10, n),
            "cvss_impact_score": rng.uniform(0, 6, n),
            "cvss_exploitability_score": rng.uniform(0, 4, n),
            "cvss_attack_vector": rng.integers(0, 4, n).astype(float),
            "cvss_attack_complexity": rng.integers(0, 2, n).astype(float),
            "cvss_privileges_required": rng.integers(0, 3, n).astype(float),
            "cvss_user_interaction": rng.integers(0, 2, n).astype(float),
            "cvss_scope": rng.integers(0, 2, n).astype(float),
            "reference_count": rng.integers(0, 10, n),
            "days_since_publication": rng.integers(0, 3000, n),
            "epss_score": rng.uniform(0, 1, n),
            "epss_percentile": rng.uniform(0, 1, n),
            "cwe_category": rng.choice(["injection", "memory", "none"], n),
            "vendor_category": rng.choice(["os", "web", "other"], n),
            "has_cwe": rng.choice([True, False], n),
            "has_exploit_keyword": rng.choice([True, False], n),
            "is_exploited": is_exploited,
        }
    )


def make_fitted_pipeline(df: pd.DataFrame) -> Pipeline:
    X, y = get_X_y(df)
    pipeline = Pipeline(
        steps=[("preprocess", build_preprocessor()), ("classifier", XGBClassifier(n_estimators=20, random_state=42))]
    )
    pipeline.fit(X, y)
    return pipeline


def test_global_importance_sorted_and_nonnegative():
    df = make_df(150, seed=1)
    pipeline = make_fitted_pipeline(df)
    X, _ = get_X_y(df)

    importance = global_importance(pipeline, X)

    assert list(importance.columns) == ["feature", "mean_abs_shap"]
    assert (importance["mean_abs_shap"] >= 0).all()
    assert importance["mean_abs_shap"].is_monotonic_decreasing


def test_explain_row_returns_probability_and_contributions():
    df = make_df(150, seed=1)
    pipeline = make_fitted_pipeline(df)
    X, _ = get_X_y(df)

    result = explain_row(pipeline, X.iloc[[0]])

    assert 0.0 <= result["predicted_probability"] <= 1.0
    assert 0 < len(result["top_contributions"]) <= 10
    assert all("feature" in c and "shap_value" in c for c in result["top_contributions"])


def test_explain_cve_by_id():
    df = make_df(150, seed=1)
    pipeline = make_fitted_pipeline(df)

    result = explain_cve("CVE-2024-0005", df, pipeline)
    assert result["cve_id"] == "CVE-2024-0005"
    assert "predicted_probability" in result


def test_explain_cve_unknown_raises():
    df = make_df(10, seed=1)
    pipeline = make_fitted_pipeline(df)

    with pytest.raises(ValueError):
        explain_cve("CVE-9999-9999", df, pipeline)
