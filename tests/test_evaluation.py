"""Tests for Model Evaluation Metrics."""
import pytest
import numpy as np
from app.evaluation.metrics import ModelEvaluator

def test_model_evaluator_metrics():
    # 100 samples, 10 true anomalies
    y_true = np.zeros(100, dtype=int)
    y_true[:10] = 1

    # Perfect prediction
    y_pred = y_true.copy()
    scores = np.where(y_true == 1, 90.0, 15.0)

    res = ModelEvaluator.evaluate(y_true, y_pred, anomaly_scores=scores)
    assert res["has_ground_truth"] is True
    assert res["precision"] == 1.0
    assert res["recall"] == 1.0
    assert res["f1_score"] == 1.0
    assert res["false_positive_rate"] == 0.0
    assert res["roc_auc"] == 1.0
    assert res["confusion_matrix"]["true_positive"] == 10
    assert res["confusion_matrix"]["true_negative"] == 90

def test_no_ground_truth_handling():
    y_true = np.zeros(50, dtype=int)
    y_pred = np.zeros(50, dtype=int)
    res = ModelEvaluator.evaluate(y_true, y_pred)
    assert res["has_ground_truth"] is False
    assert "Supervised metrics cannot be computed" in res["message"]
