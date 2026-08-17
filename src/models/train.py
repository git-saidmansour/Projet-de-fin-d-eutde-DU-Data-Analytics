"""Train and evaluate the exploitability models, and compare them against the EPSS baseline."""

import argparse
import json

import joblib
import mlflow
import mlflow.sklearn
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from src.config import MLRUNS_DIR, PROCESSED_DIR, get_logger
from src.models.dataset import build_preprocessor, get_X_y, load_features, temporal_split
from src.models.metrics import evaluate_predictions

logger = get_logger(__name__)

MODELS_DIR = PROCESSED_DIR / "models"
EXPERIMENT_NAME = "cve-exploitability-prediction"

_SIMPLE_TYPES = (int, float, str, bool, type(None))


def _init_mlflow() -> None:
    # MLflow's plain filesystem store is in maintenance mode as of 2.x; use a local
    # SQLite-backed store instead (still no server required).
    MLRUNS_DIR.mkdir(parents=True, exist_ok=True)
    mlflow.set_tracking_uri(f"sqlite:///{MLRUNS_DIR / 'mlflow.db'}")
    mlflow.set_experiment(EXPERIMENT_NAME)


def _loggable_params(classifier) -> dict:
    return {k: v for k, v in classifier.get_params().items() if isinstance(v, _SIMPLE_TYPES)}


def _scale_pos_weight(y: pd.Series) -> float:
    positives = y.sum()
    negatives = len(y) - positives
    return negatives / positives if positives else 1.0


def build_models(y_train: pd.Series) -> dict:
    spw = _scale_pos_weight(y_train)
    return {
        "logistic_regression": LogisticRegression(class_weight="balanced", max_iter=1000),
        "random_forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "xgboost": XGBClassifier(
            n_estimators=300,
            scale_pos_weight=spw,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        ),
        # No imbalance reweighting here: with a ~200:1 ratio, is_unbalance/scale_pos_weight
        # destabilizes LightGBM's leaf-wise growth and *hurts* ranking (test AUC 0.69 vs 0.95
        # unweighted, verified empirically) -- unlike XGBoost/RandomForest, which handle it well.
        "lightgbm": LGBMClassifier(n_estimators=300, random_state=42, n_jobs=-1, verbosity=-1),
    }


def epss_baseline_metrics(test_df: pd.DataFrame) -> dict:
    y_true = test_df["is_exploited"]
    y_score = test_df["epss_score"].fillna(0.0)
    return evaluate_predictions(y_true, y_score)


def train_and_evaluate(train_df: pd.DataFrame, test_df: pd.DataFrame, save_dir=None, track: bool = True) -> dict:
    save_dir = save_dir or MODELS_DIR
    save_dir.mkdir(parents=True, exist_ok=True)

    if track:
        _init_mlflow()

    X_train, y_train = get_X_y(train_df)
    X_test, y_test = get_X_y(test_df)
    dataset_params = {
        "n_train": len(train_df),
        "n_test": len(test_df),
        "train_positive_rate": float(y_train.mean()),
        "test_positive_rate": float(y_test.mean()),
    }

    results = {"epss_baseline": epss_baseline_metrics(test_df)}
    if track:
        with mlflow.start_run(run_name="epss_baseline"):
            mlflow.set_tag("model_type", "baseline")
            mlflow.log_params(dataset_params)
            mlflow.log_metrics(results["epss_baseline"])

    for name, classifier in build_models(y_train).items():
        logger.info("Training %s...", name)
        pipeline = Pipeline(steps=[("preprocess", build_preprocessor()), ("classifier", classifier)])
        pipeline.fit(X_train, y_train)

        y_score = pipeline.predict_proba(X_test)[:, 1]
        results[name] = evaluate_predictions(y_test, y_score)
        results[name]["beats_epss_baseline"] = results[name]["roc_auc"] > results["epss_baseline"]["roc_auc"]

        joblib.dump(pipeline, save_dir / f"{name}.joblib")
        logger.info("%s: %s", name, results[name])

        if track:
            with mlflow.start_run(run_name=name):
                mlflow.set_tag("model_type", "trained")
                mlflow.log_params(dataset_params)
                mlflow.log_params(_loggable_params(classifier))
                mlflow.log_metrics({k: v for k, v in results[name].items() if k != "beats_epss_baseline"})
                mlflow.log_metric("beats_epss_baseline", int(results[name]["beats_epss_baseline"]))
                mlflow.sklearn.log_model(pipeline, name="model")

    return results


def run(test_frac: float = 0.2, track: bool = True) -> dict:
    df = load_features()
    train_df, test_df = temporal_split(df, test_frac=test_frac)
    logger.info(
        "Train: %s rows (%s exploited) | Test: %s rows (%s exploited)",
        len(train_df),
        train_df["is_exploited"].sum(),
        len(test_df),
        test_df["is_exploited"].sum(),
    )

    results = train_and_evaluate(train_df, test_df, track=track)

    metrics_path = PROCESSED_DIR / "model_metrics.json"
    metrics_path.write_text(json.dumps(results, indent=2))
    logger.info("Saved metrics to %s", metrics_path)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate CVE exploitability models")
    parser.add_argument("--test-frac", type=float, default=0.2, help="Fraction of the most recent CVEs held out for testing")
    parser.add_argument("--no-mlflow", action="store_true", help="Disable MLflow experiment tracking")
    args = parser.parse_args()
    run(test_frac=args.test_frac, track=not args.no_mlflow)


if __name__ == "__main__":
    main()
