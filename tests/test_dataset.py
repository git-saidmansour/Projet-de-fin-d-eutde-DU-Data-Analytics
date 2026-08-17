import pandas as pd

from src.models.dataset import get_X_y, temporal_split


def make_df(n: int) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "published_date": pd.date_range("2024-01-01", periods=n, freq="D", tz="UTC"),
            "cvss_base_score": range(n),
            "cvss_impact_score": range(n),
            "cvss_exploitability_score": range(n),
            "cvss_attack_vector": [0] * n,
            "cvss_attack_complexity": [0] * n,
            "cvss_privileges_required": [0] * n,
            "cvss_user_interaction": [0] * n,
            "cvss_scope": [0] * n,
            "reference_count": [1] * n,
            "days_since_publication": range(n),
            "epss_score": [0.1] * n,
            "epss_percentile": [0.1] * n,
            "cwe_category": ["injection"] * n,
            "vendor_category": ["web"] * n,
            "has_cwe": [True] * n,
            "has_exploit_keyword": [False] * n,
            "is_exploited": [0, 1] * (n // 2),
        }
    )


def test_temporal_split_is_chronological_not_random():
    df = make_df(10)
    train, test = temporal_split(df, test_frac=0.3)

    assert len(train) == 7
    assert len(test) == 3
    assert train["published_date"].max() < test["published_date"].min()


def test_get_X_y_casts_booleans_to_int():
    df = make_df(4)
    X, y = get_X_y(df)

    assert X["has_cwe"].dtype.kind in "iu"
    assert list(y) == [0, 1, 0, 1]
    assert "published_date" not in X.columns
    assert "cve_id" not in X.columns
