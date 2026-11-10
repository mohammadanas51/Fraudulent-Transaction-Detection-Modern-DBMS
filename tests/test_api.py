"""Tests for FastAPI Endpoints."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"

def test_list_datasets():
    res = client.get("/api/datasets")
    assert res.status_code == 200
    data = res.json()
    assert "datasets" in data
    assert len(data["datasets"]) >= 2

def test_dataset_metadata():
    res = client.get("/api/datasets/metadata?source=original")
    assert res.status_code == 200
    data = res.json()
    assert "schema_audit" in data
    assert "field_verification" in data

def test_generate_synthetic_sql():
    req_body = {
        "n_events": 200,
        "anomaly_rate": 0.05,
        "random_seed": 42
    }
    res = client.post("/api/datasets/generate-synthetic", json=req_body)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["generated_events"] == 200
    assert data["anomalies_injected"] > 0

def test_run_analysis_and_alerts():
    req_body = {
        "dataset_source": "original",
        "alert_threshold": 60.0,
        "contamination": 0.03,
        "n_estimators": 50
    }
    res = client.post("/api/analysis/run", json=req_body)
    assert res.status_code == 200
    data = res.json()
    assert data["records_analyzed"] == 2905
    assert data["anomalies_detected"] > 0
    assert "evaluation_metrics" in data

    # Test listing alerts
    alerts_res = client.get("/api/alerts?source=original&limit=10")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert alerts_data["total"] > 0
    assert len(alerts_data["alerts"]) > 0

    first_alert = alerts_data["alerts"][0]
    alert_id = first_alert["id"]

    # Test alert detail
    detail_res = client.get(f"/api/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert "contributing_factors" in detail
    assert "explanation" in detail
    assert "recommended_action" in detail

    # Test update status
    patch_res = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "investigating"})
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "investigating"

    # Test adding note
    note_res = client.post(f"/api/alerts/{alert_id}/notes", json={"note_text": "Examining access logs for this session."})
    assert note_res.status_code == 200
    assert note_res.json()["status"] == "success"

    # Test CSV export
    csv_res = client.get("/api/alerts/export/csv?source=original")
    assert csv_res.status_code == 200
    assert "Alert ID" in csv_res.text
