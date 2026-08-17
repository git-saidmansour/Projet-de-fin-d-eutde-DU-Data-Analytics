import numpy as np
import pandas as pd

from src.models.train import epss_baseline_metrics, train_and_evaluate

MODEL_NAMES = ["logistic_regression", "random_forest", "xgboost", "lightgbm"]


def make_synthetic_df(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    is_exploited = rng.binomial(1, 0.15, size=n)
    return pd.DataFrame(
        {
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
            "epss_score": np.clip(is_exploited * 0.6 + rng.uniform(0, 0.3, n), 0, 1),
            "epss_percentile": rng.uniform(0, 1, n),
            "cwe_category": rng.choice(["injection", "memory", "none", "other"], n),
            "vendor_category": rng.choice(["os", "web", "other"], n),
            "has_cwe": rng.choice([True, False], n),
            "has_exploit_keyword": rng.choice([True, False], n),
            "is_exploited": is_exploited,
        }
    )


def test_epss_baseline_metrics_handles_missing_scores():
    df = make_synthetic_df(50, seed=1)
    df.loc[0, "epss_score"] = None
    result = epss_baseline_metrics(df)
    assert 0.0 <= result["roc_auc"] <= 1.0


def test_train_and_evaluate_smoke(tmp_path):
    train_df = make_synthetic_df(200, seed=1)
    test_df = make_synthetic_df(60, seed=2)

    results = train_and_evaluate(train_df, test_df, save_dir=tmp_path)

    assert "epss_baseline" in results
    for name in MODEL_NAMES:
        assert name in results
        assert 0.0 <= results[name]["roc_auc"] <= 1.0
        assert "beats_epss_baseline" in results[name]
        assert (tmp_path / f"{name}.joblib").exists()
