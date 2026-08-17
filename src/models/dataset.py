"""Load the feature table and split it chronologically for training/evaluation."""

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.config import PROCESSED_DIR

NUMERIC_FEATURES = [
    "cvss_base_score",
    "cvss_impact_score",
    "cvss_exploitability_score",
    "cvss_attack_vector",
    "cvss_attack_complexity",
    "cvss_privileges_required",
    "cvss_user_interaction",
    "cvss_scope",
    "reference_count",
    "days_since_publication",
    "epss_score",
    "epss_percentile",
]
CATEGORICAL_FEATURES = ["cwe_category", "vendor_category"]
BOOLEAN_FEATURES = ["has_cwe", "has_exploit_keyword"]
ALL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES
TARGET = "is_exploited"


def load_features(path=None) -> pd.DataFrame:
    path = path or (PROCESSED_DIR / "features.csv")
    df = pd.read_csv(path)
    df["published_date"] = pd.to_datetime(df["published_date"], utc=True, errors="coerce")
    return df.dropna(subset=["published_date"]).sort_values("published_date").reset_index(drop=True)


def temporal_split(df: pd.DataFrame, test_frac: float = 0.2) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split chronologically: the earliest (1 - test_frac) rows are train, the rest test."""
    cutoff = int(len(df) * (1 - test_frac))
    return df.iloc[:cutoff].copy(), df.iloc[cutoff:].copy()


def get_X_y(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    X = df[ALL_FEATURES].copy()
    for col in BOOLEAN_FEATURES:
        X[col] = X[col].astype(int)
    y = df[TARGET].astype(int)
    return X, y


def build_preprocessor() -> ColumnTransformer:
    numeric_pipeline = Pipeline(
        steps=[("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("impute", SimpleImputer(strategy="constant", fill_value="none")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, NUMERIC_FEATURES),
            ("categorical", categorical_pipeline, CATEGORICAL_FEATURES),
            ("boolean", "passthrough", BOOLEAN_FEATURES),
        ]
    )
