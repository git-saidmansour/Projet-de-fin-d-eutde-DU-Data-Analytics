from src.models.metrics import evaluate_predictions


def test_evaluate_predictions_perfect_separation():
    y_true = [0, 0, 0, 1, 1]
    y_score = [0.1, 0.05, 0.2, 0.9, 0.8]
    result = evaluate_predictions(y_true, y_score)

    assert result["roc_auc"] == 1.0
    assert result["pr_auc"] == 1.0
    assert result["f1"] == 1.0


def test_evaluate_predictions_threshold_affects_precision_recall():
    y_true = [0, 1, 1, 1]
    y_score = [0.4, 0.3, 0.6, 0.9]

    low_threshold = evaluate_predictions(y_true, y_score, threshold=0.2)
    high_threshold = evaluate_predictions(y_true, y_score, threshold=0.8)

    assert low_threshold["recall"] >= high_threshold["recall"]
