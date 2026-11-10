"""Alert Management Service: Querying, Filtering, Triage Status Updates, Notes, and CSV Export."""
import csv
import io
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.models import AnomalyAlert, InvestigationNote

class AlertService:
    def __init__(self, db_session: Session):
        self.db = db_session

    def list_alerts(
        self,
        dataset_source: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        user_identifier: Optional[str] = None,
        resource: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Lists and filters anomaly alerts with pagination."""
        query = self.db.query(AnomalyAlert)

        if dataset_source and dataset_source != "all":
            query = query.filter(AnomalyAlert.dataset_source == dataset_source)
        if severity and severity != "all":
            query = query.filter(AnomalyAlert.severity == severity.upper())
        if status and status != "all":
            query = query.filter(AnomalyAlert.status == status)
        if user_identifier:
            query = query.filter(AnomalyAlert.user_identifier.ilike(f"%{user_identifier}%"))
        if resource:
            query = query.filter(AnomalyAlert.resource_accessed.ilike(f"%{resource}%"))
        if min_score is not None:
            query = query.filter(AnomalyAlert.anomaly_score >= min_score)

        total_count = query.count()
        alerts = query.order_by(desc(AnomalyAlert.anomaly_score)).offset(offset).limit(limit).all()

        results = []
        for a in alerts:
            results.append({
                "id": a.id,
                "event_id": a.event_id,
                "timestamp": a.timestamp,
                "user_identifier": a.user_identifier,
                "user_role": a.user_role,
                "department": a.department,
                "resource_accessed": a.resource_accessed,
                "query_type": a.query_type,
                "anomaly_score": a.anomaly_score,
                "severity": a.severity,
                "explanation": a.explanation,
                "status": a.status,
                "ground_truth_label": a.ground_truth_label,
                "ground_truth_type": a.ground_truth_type,
                "dataset_source": a.dataset_source,
                "notes_count": len(a.notes)
            })

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "alerts": results
        }

    def get_alert_detail(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves complete details, contributing factors, baseline comparisons, and notes for an alert."""
        alert = self.db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
        if not alert:
            return None

        factors = json.loads(alert.contributing_factors) if alert.contributing_factors else []
        baseline = json.loads(alert.baseline_comparison) if alert.baseline_comparison else {}
        notes = [
            {
                "id": n.id,
                "author": n.author,
                "note_text": n.note_text,
                "created_at": n.created_at.isoformat()
            }
            for n in alert.notes
        ]

        return {
            "id": alert.id,
            "event_id": alert.event_id,
            "timestamp": alert.timestamp,
            "user_identifier": alert.user_identifier,
            "user_role": alert.user_role,
            "department": alert.department,
            "resource_accessed": alert.resource_accessed,
            "query_type": alert.query_type,
            "anomaly_score": alert.anomaly_score,
            "severity": alert.severity,
            "explanation": alert.explanation,
            "contributing_factors": factors,
            "baseline_comparison": baseline,
            "recommended_action": alert.recommended_action,
            "status": alert.status,
            "ground_truth_label": alert.ground_truth_label,
            "ground_truth_type": alert.ground_truth_type,
            "dataset_source": alert.dataset_source,
            "notes": notes
        }

    def update_status(self, alert_id: int, new_status: str) -> Optional[AnomalyAlert]:
        """Updates triage status: open, investigating, resolved, or false_positive."""
        alert = self.db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
        if not alert:
            return None
        alert.status = new_status
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def add_note(self, alert_id: int, note_text: str, author: str = "Security Analyst") -> Optional[InvestigationNote]:
        """Adds an analyst investigation note to the alert."""
        alert = self.db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
        if not alert:
            return None
        note = InvestigationNote(alert_id=alert_id, note_text=note_text, author=author)
        self.db.add(note)
        self.db.commit()
        self.db.refresh(note)
        return note

    def export_csv(self, dataset_source: Optional[str] = None) -> str:
        """Exports alerts to CSV string for external analyst reporting."""
        query = self.db.query(AnomalyAlert)
        if dataset_source and dataset_source != "all":
            query = query.filter(AnomalyAlert.dataset_source == dataset_source)
        alerts = query.order_by(desc(AnomalyAlert.anomaly_score)).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Alert ID", "Event ID", "Timestamp", "User", "Role", "Department",
            "Resource", "Query Type", "Risk Score", "Severity", "Status",
            "Ground Truth", "Dataset Source", "Explanation"
        ])

        for a in alerts:
            writer.writerow([
                a.id, a.event_id, a.timestamp, a.user_identifier, a.user_role, a.department,
                a.resource_accessed, a.query_type, a.anomaly_score, a.severity, a.status,
                a.ground_truth_type or "Normal", a.dataset_source, a.explanation
            ])

        return output.getvalue()
