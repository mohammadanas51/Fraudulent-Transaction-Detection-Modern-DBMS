"""Tests for Sessionization, Behavioral Baseline Extraction, and Feature Fusion."""
import pytest
import pandas as pd
from app.config import settings
from app.ingestion.repository_loader import RepositoryLoader
from app.processing.sessionization import Sessionizer
from app.processing.behavioral_features import BehavioralFeatureExtractor
from app.processing.feature_fusion import FeatureFusionEngine

def test_original_db_feature_extraction():
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    conn = loader.get_connection()
    extractor = BehavioralFeatureExtractor()
    df = extractor.extract_from_original_db(conn)
    conn.close()

    assert not df.empty
    assert len(df) == 2905
    assert "login_hour" in df.columns
    assert "is_off_hours" in df.columns
    assert "is_new_ip" in df.columns
    assert "file_access_count" in df.columns
    assert "file_volume_zscore" in df.columns
    assert "is_anomaly" in df.columns
    assert df["is_anomaly"].sum() == 87

def test_feature_fusion_original():
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    conn = loader.get_connection()
    extractor = BehavioralFeatureExtractor()
    df = extractor.extract_from_original_db(conn)
    conn.close()

    engine = FeatureFusionEngine()
    X, active_groups, feature_names = engine.fuse_original_features(df)

    assert isinstance(X, pd.DataFrame)
    assert len(X) == 2905
    assert "temporal" in active_groups
    assert "frequency" in active_groups
    assert "user_behavior" in active_groups
    assert "sql_semantics" not in active_groups
    assert X.isnull().sum().sum() == 0

def test_sessionization():
    events_data = [
        {"user_id": "u1", "timestamp": "2026-01-01T09:00:00", "resource": "res1", "action": "read", "sensitivity": "low"},
        {"user_id": "u1", "timestamp": "2026-01-01T09:10:00", "resource": "res2", "action": "write", "sensitivity": "high"},
        {"user_id": "u1", "timestamp": "2026-01-01T14:00:00", "resource": "res3", "action": "read", "sensitivity": "low"}
    ]
    df = pd.DataFrame(events_data)
    sessionizer = Sessionizer(inactivity_timeout_minutes=30)
    sessions = sessionizer.sessionize_events(df)

    assert len(sessions) == 2  # Morning session and afternoon session separated by 4+ hours
    assert sessions.iloc[0]["total_events"] == 2
    assert sessions.iloc[1]["total_events"] == 1
