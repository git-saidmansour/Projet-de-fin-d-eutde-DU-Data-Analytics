"""Evaluation metrics, focused on the positive (exploited) class of an imbalanced target."""

from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score


def evaluate_predictions(y_true, y_score, threshold: float = 0.5) -> dict:
    y_pred = [1 if score >= threshold else 0 for score in y_score]
    return {
        "roc_auc": roc_auc_score(y_true, y_score),
        "pr_auc": average_precision_score(y_true, y_score),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
