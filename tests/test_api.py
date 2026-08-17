import numpy as np
import pandas as pd
from fastapi.testclient import TestClient
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from src.dashboard import api
from src.models.dataset import build_preprocessor, get_X_y


def make_df(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    is_exploited = rng.binomial(1, 0.2, size=n)
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2024-{i:04d}" for i in range(n)],
            "published_date": pd.to_datetime("2024-01-01", utc=True),
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


def setup_state(n: int = 50, seed: int = 3) -> pd.DataFrame:
    df = make_df(n, seed)
    X, y = get_X_y(df)
    pipeline = Pipeline(
        steps=[("preprocess", build_preprocessor()), ("classifier", XGBClassifier(n_estimators=10, random_state=42))]
    )
    pipeline.fit(X, y)
    df = df.copy()
    df["predicted_probability"] = pipeline.predict_proba(X)[:, 1]

    api._state.clear()
    api._state.update({"pipeline": pipeline, "df": df})
    return df


def test_health():
    setup_state()
    client = TestClient(api.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "n_cves": 50}


def test_list_cves_sorted_by_predicted_probability():
    setup_state()
    client = TestClient(api.app)

    resp = client.get("/cves", params={"limit": 5})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 5
    probs = [row["predicted_probability"] for row in body]
    assert probs == sorted(probs, reverse=True)


def test_list_cves_filters_by_vendor_category():
    df = setup_state()
    client = TestClient(api.app)

    vendor = df.iloc[0]["vendor_category"]
    resp = client.get("/cves", params={"vendor_category": vendor, "limit": 500})
    assert resp.status_code == 200
    assert all(row["vendor_category"] == vendor for row in resp.json())


def test_get_cve_detail_includes_shap_contributions():
    df = setup_state()
    client = TestClient(api.app)

    cve_id = df.iloc[0]["cve_id"]
    resp = client.get(f"/cves/{cve_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["cve_id"] == cve_id
    assert 0.0 <= body["predicted_probability"] <= 1.0
    assert len(body["top_contributions"]) > 0


def test_get_cve_detail_unknown_returns_404():
    setup_state()
    client = TestClient(api.app)

    resp = client.get("/cves/CVE-9999-9999")
    assert resp.status_code == 404
