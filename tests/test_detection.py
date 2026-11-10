"""Tests for Isolation Forest Detection, Scoring, Explanations, and Preprocessing."""
import pytest
import numpy as np
import pandas as pd
from app.detection.preprocessing import AnomalyPreprocessor
from app.detection.isolation_forest import AnomalyDetector
from app.detection.scoring import ScoreNormalizer
from app.detection.explanations import AlertExplainer

def test_score_normalizer():
    # Normal score (+0.2) should be low risk (< 30)
    normal_risk = ScoreNormalizer.raw_to_risk_score(np.array([0.2]))[0]
    assert normal_risk < 30.0

    # Decision boundary (0.0) should map to 50.0
    boundary_risk = ScoreNormalizer.raw_to_risk_score(np.array([0.0]))[0]
    assert abs(boundary_risk - 50.0) < 0.1

    # Deep anomaly score (-0.2) should be high risk (> 80)
    anomaly_risk = ScoreNormalizer.raw_to_risk_score(np.array([-0.2]))[0]
    assert anomaly_risk > 80.0

    # Severity tiers
    assert ScoreNormalizer.get_severity(85.0) == "CRITICAL"
    assert ScoreNormalizer.get_severity(65.0) == "HIGH"
    assert ScoreNormalizer.get_severity(50.0) == "MEDIUM"
    assert ScoreNormalizer.get_severity(20.0) == "LOW"

def test_isolation_forest_workflow(tmp_path):
    # Create synthetic test features
    np.random.seed(42)
    n = 200
    df = pd.DataFrame({
        "f1": np.random.normal(10, 2, n),
        "f2": np.random.normal(5, 1, n),
        "f3": np.random.choice([0, 1], n)
    })
    
    # Inject 5 extreme outliers
    df.iloc[0:5, 0] = 50.0
    
    detector = AnomalyDetector(n_estimators=50, contamination=0.03, random_state=42)
    feature_names = ["f1", "f2", "f3"]
    detector.fit(df, feature_names=feature_names)
    
    preds = detector.predict(df)
    scores = detector.decision_function(df)
    
    assert len(preds) == n
    assert len(scores) == n
    assert preds[0] == 1  # Outlier should be flagged as anomaly (1)
    
    # Save & reload model
    save_path = tmp_path / "test_iso.joblib"
    detector.save(save_path)
    assert save_path.exists()
    
    reloaded = AnomalyDetector.load(save_path)
    reloaded_preds = reloaded.predict(df)
    np.testing.assert_array_equal(preds, reloaded_preds)

def test_alert_explainer():
    event = {
        "user_id": "emp_12",
        "role": "Associate",
        "resource": "file_400",
        "ip_address": "198.51.100.44"
    }
    features = {
        "login_hour": 3,
        "is_off_hours": 1,
        "is_new_ip": 1,
        "file_access_count": 28,
        "user_hist_file_mean": 3.8,
        "file_volume_zscore": 4.5,
        "high_sensitivity_count": 6
    }
    
    result = AlertExplainer.explain_event(
        event_dict=event,
        features_dict=features,
        risk_score=88.5,
        severity="CRITICAL",
        dataset_source="original"
    )
    
    assert result["severity"] == "CRITICAL"
    assert len(result["contributing_factors"]) >= 3
    assert len(result["recommended_actions"]) >= 1
    assert "emp_12" in result["explanation"]
    assert "baseline_comparison" in result
