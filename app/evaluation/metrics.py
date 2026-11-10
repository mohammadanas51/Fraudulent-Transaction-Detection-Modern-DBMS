"""Evaluation Module: Computes Precision, Recall, F1, FPR, ROC-AUC, PR-AUC, and Confusion Matrix."""
from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc
)

class ModelEvaluator:
    """Evaluates anomaly detection performance against verified ground-truth labels."""

    @staticmethod
    def evaluate(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        anomaly_scores: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """Calculates comprehensive classification metrics for anomaly detection."""
        y_true = np.asarray(y_true, dtype=int)
        y_pred = np.asarray(y_pred, dtype=int)

        # Handle case where ground truth has no positive labels
        unique_labels = np.unique(y_true)
        if len(unique_labels) < 2 and 1 not in unique_labels:
            return {
                "has_ground_truth": False,
                "message": "Ground-truth labels contain no anomaly examples. Supervised metrics cannot be computed."
            }

        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = 0, 0, 0, 0
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        elif cm.shape == (1, 1):
            if unique_labels[0] == 0:
                tn = cm[0, 0]
            else:
                tp = cm[0, 0]

        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        roc_auc = None
        pr_auc = None

        if anomaly_scores is not None and len(unique_labels) > 1:
            try:
                # anomaly_scores should be higher for anomalies (0-100 risk score is ideal)
                roc_auc = float(roc_auc_score(y_true, anomaly_scores))
                precisions, recalls, _ = precision_recall_curve(y_true, anomaly_scores)
                pr_auc = float(auc(recalls, precisions))
            except Exception:
                roc_auc = None
                pr_auc = None

        # Score distributions
        score_distribution = {}
        if anomaly_scores is not None:
            score_distribution = {
                "normal_mean": float(np.mean(anomaly_scores[y_true == 0])) if np.sum(y_true == 0) > 0 else None,
                "normal_std": float(np.std(anomaly_scores[y_true == 0])) if np.sum(y_true == 0) > 0 else None,
                "anomaly_mean": float(np.mean(anomaly_scores[y_true == 1])) if np.sum(y_true == 1) > 0 else None,
                "anomaly_std": float(np.std(anomaly_scores[y_true == 1])) if np.sum(y_true == 1) > 0 else None
            }

        return {
            "has_ground_truth": True,
            "total_samples": int(len(y_true)),
            "true_anomalies_count": int(np.sum(y_true == 1)),
            "predicted_anomalies_count": int(np.sum(y_pred == 1)),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "false_positive_rate": round(float(fpr), 4),
            "roc_auc": round(float(roc_auc), 4) if roc_auc is not None else None,
            "pr_auc": round(float(pr_auc), 4) if pr_auc is not None else None,
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            },
            "score_distribution": score_distribution
        }

    @staticmethod
    def time_based_split(
        df,
        timestamp_col: str = "login_timestamp",
        split_ratio: float = 0.75
    ):
        """Splits data chronologically to evaluate generalization without temporal leakage."""
        sorted_df = df.sort_values(timestamp_col).reset_index(drop=True)
        split_idx = int(len(sorted_df) * split_ratio)
        train_df = sorted_df.iloc[:split_idx].copy()
        test_df = sorted_df.iloc[split_idx:].copy()
        return train_df, test_df
