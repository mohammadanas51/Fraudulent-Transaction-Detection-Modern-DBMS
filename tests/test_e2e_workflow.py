"""End-to-End Workflow Integration Test."""
import pytest
from app.config import settings
from app.database.connection import SessionLocal, init_db
from app.services.analysis_service import AnalysisService
from app.services.alert_service import AlertService

def test_full_end_to_end_workflow():
    init_db()
    db = SessionLocal()
    try:
        analysis_service = AnalysisService(db)
        alert_service = AlertService(db)

        # 1. Run Original Dataset Pipeline
        orig_res = analysis_service.run_original_analysis(
            contamination=0.03,
            n_estimators=100,
            alert_threshold=60.0
        )
        assert orig_res["dataset"] == "original"
        assert orig_res["records_analyzed"] == 2905
        assert orig_res["anomalies_detected"] > 0
        assert orig_res["evaluation_metrics"]["has_ground_truth"] is True
        assert orig_res["evaluation_metrics"]["roc_auc"] > 0.80

        # Query alerts generated from original run
        orig_alerts = alert_service.list_alerts(dataset_source="original", limit=10)
        assert orig_alerts["total"] > 0
        first_orig = orig_alerts["alerts"][0]
        assert first_orig["anomaly_score"] >= 60.0
        assert len(first_orig["explanation"]) > 20

        # Update alert status
        updated_alert = alert_service.update_status(first_orig["id"], "investigating")
        assert updated_alert.status == "investigating"

        # Add investigation note
        note = alert_service.add_note(first_orig["id"], "Verified login timestamp and user IP pool.", "SecAnalystSpecialist")
        assert note.id is not None

        # Verify alert detail has the note and explanations
        detail = alert_service.get_alert_detail(first_orig["id"])
        assert detail["status"] == "investigating"
        assert len(detail["notes"]) >= 1
        assert any("SecAnalystSpecialist" in n["author"] for n in detail["notes"])

        # 2. Run Synthetic SQL Extension Pipeline
        sql_res = analysis_service.run_synthetic_sql_analysis(
            n_events=500,
            anomaly_rate=0.05,
            contamination=0.04,
            n_estimators=100,
            alert_threshold=60.0
        )
        assert sql_res["dataset"] == "synthetic_sql"
        assert sql_res["records_analyzed"] == 500
        assert "sql_semantics" in sql_res["active_feature_groups"]
        assert "data_volume" in sql_res["active_feature_groups"]
        assert sql_res["anomalies_detected"] > 0
        assert sql_res["evaluation_metrics"]["has_ground_truth"] is True

        # Query alerts generated from synthetic SQL run
        sql_alerts = alert_service.list_alerts(dataset_source="synthetic_sql", limit=10)
        assert sql_alerts["total"] > 0
        first_sql = sql_alerts["alerts"][0]
        assert first_sql["dataset_source"] == "synthetic_sql"

        # Export CSV
        csv_out = alert_service.export_csv(dataset_source="original")
        assert "Alert ID" in csv_out
        assert "orig_sess_" in csv_out

    finally:
        db.close()
