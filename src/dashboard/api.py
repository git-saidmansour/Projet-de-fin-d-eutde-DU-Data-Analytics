"""FastAPI backend serving CVE exploitability predictions.

Loads the trained XGBoost pipeline and the feature table once at startup,
precomputes predicted probabilities for the whole dataset, and serves
filtered/sorted listings plus per-CVE SHAP explanations.
"""

from contextlib import asynccontextmanager
from typing import Optional

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from src.config import PROCESSED_DIR, get_logger
from src.models.dataset import get_X_y, load_features
from src.models.interpret import explain_cve

logger = get_logger(__name__)

MODEL_PATH = PROCESSED_DIR / "models" / "xgboost.joblib"

_state: dict = {}


def load_state() -> dict:
    pipeline = joblib.load(MODEL_PATH)
    df = load_features()
    X, _ = get_X_y(df)
    df = df.copy()
    df["predicted_probability"] = pipeline.predict_proba(X)[:, 1]
    return {"pipeline": pipeline, "df": df}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading model and feature table...")
    _state.update(load_state())
    logger.info("Loaded %s CVEs", len(_state["df"]))
    yield
    _state.clear()


app = FastAPI(title="CVE Exploitability Prediction API", lifespan=lifespan)


class Contribution(BaseModel):
    feature: str
    shap_value: float


class CVESummary(BaseModel):
    cve_id: str
    published_date: Optional[str]
    cvss_base_score: Optional[float]
    epss_score: Optional[float]
    vendor_category: str
    cwe_category: str
    predicted_probability: float
    is_exploited: int


class CVEDetail(CVESummary):
    description: Optional[str]
    top_contributions: list[Contribution]


def _row_to_summary(row) -> CVESummary:
    return CVESummary(
        cve_id=row.cve_id,
        published_date=row.published_date.isoformat() if pd.notna(row.published_date) else None,
        cvss_base_score=row.cvss_base_score if pd.notna(row.cvss_base_score) else None,
        epss_score=row.epss_score if pd.notna(row.epss_score) else None,
        vendor_category=row.vendor_category,
        cwe_category=row.cwe_category,
        predicted_probability=row.predicted_probability,
        is_exploited=int(row.is_exploited),
    )


@app.get("/health")
def health():
    return {"status": "ok", "n_cves": len(_state["df"]) if "df" in _state else 0}


@app.get("/meta/vendor-categories")
def vendor_categories() -> list[str]:
    return sorted(_state["df"]["vendor_category"].dropna().unique().tolist())


@app.get("/meta/cwe-categories")
def cwe_categories() -> list[str]:
    return sorted(_state["df"]["cwe_category"].dropna().unique().tolist())


@app.get("/cves", response_model=list[CVESummary])
def list_cves(
    vendor_category: Optional[str] = None,
    cwe_category: Optional[str] = None,
    cvss_min: Optional[float] = None,
    cvss_max: Optional[float] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
):
    df = _state["df"]
    mask = pd.Series(True, index=df.index)
    if vendor_category:
        mask &= df["vendor_category"] == vendor_category
    if cwe_category:
        mask &= df["cwe_category"] == cwe_category
    if cvss_min is not None:
        mask &= df["cvss_base_score"] >= cvss_min
    if cvss_max is not None:
        mask &= df["cvss_base_score"] <= cvss_max
    if date_from:
        mask &= df["published_date"] >= pd.Timestamp(date_from, tz="UTC")
    if date_to:
        mask &= df["published_date"] <= pd.Timestamp(date_to, tz="UTC")

    filtered = df[mask].sort_values("predicted_probability", ascending=False)
    page = filtered.iloc[offset : offset + limit]

    return [_row_to_summary(row) for row in page.itertuples()]


@app.get("/cves/{cve_id}", response_model=CVEDetail)
def get_cve(cve_id: str):
    df = _state["df"]
    row = df[df["cve_id"] == cve_id]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in the collected dataset")

    explanation = explain_cve(cve_id, df, _state["pipeline"])
    summary = _row_to_summary(row.iloc[0])
    description = row.iloc[0]["description"] if pd.notna(row.iloc[0]["description"]) else None

    return CVEDetail(
        **summary.model_dump(),
        description=description,
        top_contributions=[Contribution(**c) for c in explanation["top_contributions"]],
    )
