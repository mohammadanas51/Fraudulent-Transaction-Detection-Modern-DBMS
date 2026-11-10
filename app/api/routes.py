"""FastAPI REST API Routes for Anomaly Detection, Triage, and Evaluation."""
import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.database.connection import get_db
from app.database.models import DatasetMetadata, ModelMetadata, AnalysisRun, AnomalyAlert
from app.ingestion.repository_loader import RepositoryLoader
from app.services.analysis_service import AnalysisService
from app.services.alert_service import AlertService

router = APIRouter(prefix="/api")

# Pydantic Request/Response Schemas
class StatusUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(open|investigating|resolved|false_positive)$")

class NoteCreateRequest(BaseModel):
    note_text: str = Field(..., min_length=1, max_length=2000)
    author: Optional[str] = "Security Analyst"

class TrainRequest(BaseModel):
    dataset_source: str = Field(default="original", pattern="^(original|synthetic_sql)$")
    contamination: float = Field(default=0.03, ge=0.001, le=0.5)
    n_estimators: int = Field(default=200, ge=10, le=1000)
    random_state: int = Field(default=42)

class AnalysisRunRequest(BaseModel):
    dataset_source: str = Field(default="original", pattern="^(original|synthetic_sql)$")
    alert_threshold: float = Field(default=60.0, ge=0.0, le=100.0)
    contamination: float = Field(default=0.03, ge=0.001, le=0.5)
    n_estimators: int = Field(default=200, ge=10, le=1000)

class SyntheticGenRequest(BaseModel):
    n_events: int = Field(default=2500, ge=100, le=10000)
    anomaly_rate: float = Field(default=0.04, ge=0.005, le=0.20)
    random_seed: int = Field(default=42)

# --- 1. Health Check ---
@router.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": json.dumps(None)
    }

# --- 2. Dataset Metadata & Inspection ---
@router.get("/datasets", tags=["Datasets"])
def list_available_datasets():
    return {
        "datasets": [
            {
                "id": "original",
                "name": "Original Access Logs (SQLite)",
                "path": str(settings.ORIGINAL_DB_PATH),
                "is_present": settings.ORIGINAL_DB_PATH.exists(),
                "supported_dimensions": ["User Behavior", "File Access", "Temporal", "Frequency", "Baseline Deviations"],
                "unsupported_dimensions": ["SQL Semantics", "Rows Returned", "Rows Affected"],
                "has_ground_truth": True
            },
            {
                "id": "synthetic_sql",
                "name": "Synthetic SQL Audit Logs (Extension)",
                "path": str(settings.SYNTHETIC_DB_PATH),
                "is_present": settings.SYNTHETIC_DB_PATH.exists(),
                "supported_dimensions": ["SQL Semantics", "Data Volume", "Temporal", "Frequency", "Role Behavior"],
                "unsupported_dimensions": [],
                "has_ground_truth": True
            }
        ]
    }

@router.get("/datasets/metadata", tags=["Datasets"])
def get_dataset_metadata(source: str = Query(default="original")):
    if source == "original":
        try:
            loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
            audit = loader.audit_schema()
            presence = loader.field_presence_summary()
            return {
                "source": "original",
                "schema_audit": audit,
                "field_verification": presence
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to inspect original dataset: {str(e)}")
    else:
        return {
            "source": "synthetic_sql",
            "table_name": "sql_audit_logs",
            "supported_fields": [
                "event_id", "timestamp", "user_id", "role", "sql_query",
                "query_type", "resource", "rows_returned", "rows_affected",
                "session_id", "transaction_id", "ground_truth_label"
            ]
        }

# --- 3. Synthetic SQL Generation ---
@router.post("/datasets/generate-synthetic", tags=["Datasets"])
def generate_synthetic_sql(req: SyntheticGenRequest):
    try:
        from app.ingestion.synthetic_sql_generator import SyntheticSQLGenerator
        gen = SyntheticSQLGenerator(random_seed=req.random_seed)
        df = gen.generate(n_events=req.n_events, anomaly_rate=req.anomaly_rate)
        saved_path = gen.save_to_sqlite(df)
        return {
            "status": "success",
            "generated_events": len(df),
            "anomalies_injected": int(df["is_ground_truth_anomaly"].sum()),
            "output_path": str(saved_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Synthetic generation failed: {str(e)}")

# --- 4. Event Listing & Filtering ---
@router.get("/events", tags=["Events"])
def list_events(
    source: str = Query(default="original"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0)
):
    if source == "original":
        loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
        logins = loader.load_login_events()
        total = len(logins)
        subset = logins.iloc[offset:offset+limit].to_dict(orient="records")
        return {"total": total, "limit": limit, "offset": offset, "events": subset}
    else:
        if not settings.SYNTHETIC_DB_PATH.exists():
            return {"total": 0, "events": [], "message": "Synthetic SQL database not yet generated."}
        import sqlite3
        import pandas as pd
        conn = sqlite3.connect(settings.SYNTHETIC_DB_PATH)
        df = pd.read_sql_query("SELECT * FROM sql_audit_logs LIMIT ? OFFSET ?", conn, params=(limit, offset))
        total = conn.execute("SELECT count(*) FROM sql_audit_logs").fetchone()[0]
        conn.close()
        return {"total": total, "limit": limit, "offset": offset, "events": df.to_dict(orient="records")}

# --- 5. Model Training & Anomaly Analysis ---
@router.post("/analysis/run", tags=["Detection"])
def run_anomaly_analysis(req: AnalysisRunRequest, db: Session = Depends(get_db)):
    service = AnalysisService(db)
    try:
        if req.dataset_source == "original":
            result = service.run_original_analysis(
                contamination=req.contamination,
                n_estimators=req.n_estimators,
                alert_threshold=req.alert_threshold
            )
        else:
            result = service.run_synthetic_sql_analysis(
                contamination=req.contamination,
                n_estimators=req.n_estimators,
                alert_threshold=req.alert_threshold
            )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis run failed: {str(e)}")

# --- 6. Alerts Management & Triage ---
@router.get("/alerts", tags=["Alerts"])
def get_alerts(
    source: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    user_identifier: Optional[str] = Query(default=None),
    resource: Optional[str] = Query(default=None),
    min_score: Optional[float] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    service = AlertService(db)
    return service.list_alerts(
        dataset_source=source,
        severity=severity,
        status=status,
        user_identifier=user_identifier,
        resource=resource,
        min_score=min_score,
        limit=limit,
        offset=offset
    )

@router.get("/alerts/{alert_id}", tags=["Alerts"])
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    service = AlertService(db)
    detail = service.get_alert_detail(alert_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return detail

@router.patch("/alerts/{alert_id}/status", tags=["Alerts"])
def update_alert_status(alert_id: int, req: StatusUpdateRequest, db: Session = Depends(get_db)):
    service = AlertService(db)
    updated = service.update_status(alert_id, req.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"status": "success", "alert_id": alert_id, "new_status": updated.status}

@router.post("/alerts/{alert_id}/notes", tags=["Alerts"])
def add_investigation_note(alert_id: int, req: NoteCreateRequest, db: Session = Depends(get_db)):
    service = AlertService(db)
    note = service.add_note(alert_id, req.note_text, req.author or "Security Analyst")
    if not note:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"status": "success", "note_id": note.id, "alert_id": alert_id}

@router.get("/alerts/export/csv", tags=["Alerts"])
def export_alerts_csv(source: Optional[str] = Query(default=None), db: Session = Depends(get_db)):
    service = AlertService(db)
    csv_content = service.export_csv(dataset_source=source)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_export.csv"}
    )

# --- 7. Evaluation & Metrics ---
@router.get("/evaluation/metrics", tags=["Evaluation"])
def get_evaluation_metrics(db: Session = Depends(get_db)):
    # Fetch most recent runs for each dataset
    orig_model = db.query(ModelMetadata).filter(ModelMetadata.dataset_source == "original").order_by(ModelMetadata.id.desc()).first()
    sql_model = db.query(ModelMetadata).filter(ModelMetadata.dataset_source == "synthetic_sql").order_by(ModelMetadata.id.desc()).first()

    return {
        "original_dataset": {
            "model_name": orig_model.model_name if orig_model else None,
            "metrics": json.loads(orig_model.metrics_json) if orig_model and orig_model.metrics_json else None
        },
        "synthetic_sql_dataset": {
            "model_name": sql_model.model_name if sql_model else None,
            "metrics": json.loads(sql_model.metrics_json) if sql_model and sql_model.metrics_json else None
        }
    }

# --- 8. Model Status ---
@router.get("/models/status", tags=["Models"])
def get_model_status(db: Session = Depends(get_db)):
    models = db.query(ModelMetadata).order_by(ModelMetadata.id.desc()).all()
    res = []
    for m in models:
        res.append({
            "id": m.id,
            "name": m.model_name,
            "dataset_source": m.dataset_source,
            "contamination": m.contamination,
            "n_estimators": m.n_estimators,
            "feature_groups": json.loads(m.feature_groups) if m.feature_groups else [],
            "trained_at": m.trained_at.isoformat()
        })
    return {"models": res}

# --- 9. SOC Dashboard Overview Stats ---
@router.get("/stats/overview", tags=["Dashboard"])
def get_soc_overview_stats(source: Optional[str] = Query(default=None), db: Session = Depends(get_db)):
    query = db.query(AnomalyAlert)
    if source and source != "all":
        query = query.filter(AnomalyAlert.dataset_source == source)

    total_alerts = query.count()
    critical_alerts = query.filter(AnomalyAlert.severity == "CRITICAL").count()
    high_alerts = query.filter(AnomalyAlert.severity == "HIGH").count()
    open_alerts = query.filter(AnomalyAlert.status == "open").count()
    investigating_alerts = query.filter(AnomalyAlert.status == "investigating").count()
    resolved_alerts = query.filter(AnomalyAlert.status == "resolved").count()

    # Score distribution buckets: [0-20, 21-40, 41-60, 61-80, 81-100]
    all_scores = [a[0] for a in query.with_entities(AnomalyAlert.anomaly_score).all()]
    buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for s in all_scores:
        if s <= 20:
            buckets["0-20"] += 1
        elif s <= 40:
            buckets["21-40"] += 1
        elif s <= 60:
            buckets["41-60"] += 1
        elif s <= 80:
            buckets["61-80"] += 1
        else:
            buckets["81-100"] += 1

    # Severity distribution
    severities = {"LOW": 0, "MEDIUM": 0, "HIGH": high_alerts, "CRITICAL": critical_alerts}
    for a in query.all():
        if a.severity in ["LOW", "MEDIUM"]:
            severities[a.severity] += 1

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "open_alerts": open_alerts,
        "investigating_alerts": investigating_alerts,
        "resolved_alerts": resolved_alerts,
        "score_distribution": buckets,
        "severity_distribution": severities
    }
