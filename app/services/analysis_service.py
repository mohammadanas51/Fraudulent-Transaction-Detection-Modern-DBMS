"""Analysis Service: Orchestrates pipeline execution, model training, scoring, and persistence."""
import time
import uuid
import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List
import pandas as pd
from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import DatasetMetadata, ModelMetadata, AnalysisRun, AnomalyAlert
from app.ingestion.repository_loader import RepositoryLoader
from app.ingestion.synthetic_sql_generator import SyntheticSQLGenerator
from app.processing.behavioral_features import BehavioralFeatureExtractor
from app.processing.feature_fusion import FeatureFusionEngine
from app.detection.isolation_forest import AnomalyDetector
from app.detection.scoring import ScoreNormalizer
from app.detection.explanations import AlertExplainer
from app.evaluation.metrics import ModelEvaluator

class AnalysisService:
    def __init__(self, db_session: Session):
        self.db = db_session
        self.feature_extractor = BehavioralFeatureExtractor()
        self.fusion_engine = FeatureFusionEngine()

    def run_original_analysis(
        self,
        contamination: float = settings.DEFAULT_CONTAMINATION,
        n_estimators: int = settings.DEFAULT_ESTIMATORS,
        random_state: int = settings.DEFAULT_RANDOM_STATE,
        alert_threshold: float = settings.DEFAULT_ALERT_THRESHOLD
    ) -> Dict[str, Any]:
        """Runs the complete anomaly detection pipeline on the original access_logs.db dataset."""
        start_time = time.time()
        uid = uuid.uuid4().hex[:8]
        loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
        conn = loader.get_connection()
        
        # 1. Feature extraction
        raw_features_df = self.feature_extractor.extract_from_original_db(conn)
        conn.close()

        # 2. Feature Fusion
        X, active_groups, feature_names = self.fusion_engine.fuse_original_features(
            raw_features_df, include_baseline_features=True
        )

        # 3. Model Training (unsupervised - NO labels used as input)
        detector = AnomalyDetector(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        detector.fit(X, feature_names=feature_names)
        
        # Save model artifact
        model_filename = f"iso_forest_original_{int(time.time())}_{uid}.joblib"
        model_path = settings.MODEL_DIR / model_filename
        detector.save(model_path)

        # 4. Inference & Scoring
        raw_scores = detector.decision_function(X)
        risk_scores = ScoreNormalizer.raw_to_risk_score(raw_scores)
        raw_features_df["risk_score"] = risk_scores
        raw_features_df["severity"] = [ScoreNormalizer.get_severity(s) for s in risk_scores]
        raw_features_df["is_alert"] = (risk_scores >= alert_threshold).astype(int)

        # 5. Evaluation against ground truth if present
        eval_metrics = {}
        if "is_anomaly" in raw_features_df.columns:
            y_true = raw_features_df["is_anomaly"].values
            y_pred = raw_features_df["is_alert"].values
            eval_metrics = ModelEvaluator.evaluate(y_true, y_pred, risk_scores)

        # 6. Persist Metadata & Run in Application DB
        model_rec = ModelMetadata(
            model_name=f"IsolationForest-Original-{int(time.time())}-{uid}",
            algorithm="IsolationForest",
            dataset_source="original",
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            feature_names=json.dumps(feature_names),
            feature_groups=json.dumps(active_groups),
            file_path=str(model_path),
            metrics_json=json.dumps(eval_metrics)
        )
        self.db.add(model_rec)
        self.db.flush()

        run_rec = AnalysisRun(
            dataset_name="original_access_logs",
            model_id=model_rec.id,
            records_analyzed=len(raw_features_df),
            anomalies_detected=int(raw_features_df["is_alert"].sum()),
            alert_threshold=alert_threshold,
            feature_groups_active=json.dumps(active_groups),
            execution_time_seconds=round(time.time() - start_time, 2),
            status="COMPLETED"
        )
        self.db.add(run_rec)
        self.db.flush()

        # 7. Generate Explanations & Save Flagged Alerts
        flagged_df = raw_features_df[raw_features_df["is_alert"] == 1]
        for _, row in flagged_df.iterrows():
            event_dict = {
                "user_id": str(row["employee_id"]),
                "role": row.get("role", "Associate"),
                "department": row.get("department", "General"),
                "ip_address": row.get("ip_address"),
                "resource": f"DailyFiles-{row.get('distinct_files_count', 0)}"
            }
            feat_dict = row.to_dict()
            explanation_data = AlertExplainer.explain_event(
                event_dict=event_dict,
                features_dict=feat_dict,
                risk_score=row["risk_score"],
                severity=row["severity"],
                dataset_source="original"
            )

            alert = AnomalyAlert(
                run_id=run_rec.id,
                event_id=f"orig_sess_{row['login_id']}_{uid}",
                timestamp=str(row["login_timestamp"]),
                user_identifier=str(row["employee_id"]),
                user_role=row.get("role", "Associate"),
                department=row.get("department", "General"),
                resource_accessed=f"Files: {int(row.get('file_access_count', 0))}",
                query_type="FILE_ACCESS",
                anomaly_score=row["risk_score"],
                severity=row["severity"],
                explanation=explanation_data["explanation"],
                contributing_factors=json.dumps(explanation_data["contributing_factors"]),
                baseline_comparison=json.dumps(explanation_data["baseline_comparison"]),
                recommended_action="; ".join(explanation_data["recommended_actions"]),
                status="open",
                ground_truth_label=int(row.get("is_anomaly", 0)),
                ground_truth_type=str(row.get("anomaly_type")) if pd.notna(row.get("anomaly_type")) else None,
                dataset_source="original"
            )
            self.db.add(alert)

        self.db.commit()

        return {
            "run_id": run_rec.id,
            "dataset": "original",
            "records_analyzed": len(raw_features_df),
            "anomalies_detected": int(raw_features_df["is_alert"].sum()),
            "execution_time_seconds": run_rec.execution_time_seconds,
            "active_feature_groups": active_groups,
            "evaluation_metrics": eval_metrics
        }

    def run_synthetic_sql_analysis(
        self,
        n_events: int = 2500,
        anomaly_rate: float = 0.04,
        contamination: float = settings.DEFAULT_CONTAMINATION,
        n_estimators: int = settings.DEFAULT_ESTIMATORS,
        random_state: int = settings.DEFAULT_RANDOM_STATE,
        alert_threshold: float = settings.DEFAULT_ALERT_THRESHOLD
    ) -> Dict[str, Any]:
        """Generates synthetic SQL logs and runs multi-dimensional detection including SQL semantics & data volumes."""
        start_time = time.time()
        uid = uuid.uuid4().hex[:8]
        gen = SyntheticSQLGenerator(random_seed=random_state)
        sql_df = gen.generate(n_events=n_events, anomaly_rate=anomaly_rate)
        gen.save_to_sqlite(sql_df)

        # 1. Feature Fusion
        X, active_groups, feature_names = self.fusion_engine.fuse_synthetic_sql_features(sql_df)

        # 2. Model Training (unsupervised)
        detector = AnomalyDetector(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        detector.fit(X, feature_names=feature_names)

        # Save model artifact
        model_filename = f"iso_forest_sql_{int(time.time())}_{uid}.joblib"
        model_path = settings.MODEL_DIR / model_filename
        detector.save(model_path)

        # 3. Inference & Scoring
        raw_scores = detector.decision_function(X)
        risk_scores = ScoreNormalizer.raw_to_risk_score(raw_scores)
        sql_df["risk_score"] = risk_scores
        sql_df["severity"] = [ScoreNormalizer.get_severity(s) for s in risk_scores]
        sql_df["is_alert"] = (risk_scores >= alert_threshold).astype(int)

        # 4. Evaluation against synthetic ground-truth
        y_true = sql_df["is_ground_truth_anomaly"].values
        y_pred = sql_df["is_alert"].values
        eval_metrics = ModelEvaluator.evaluate(y_true, y_pred, risk_scores)

        # 5. Persist Run & Model in App DB
        model_rec = ModelMetadata(
            model_name=f"IsolationForest-SQL-{int(time.time())}-{uid}",
            algorithm="IsolationForest",
            dataset_source="synthetic_sql",
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            feature_names=json.dumps(feature_names),
            feature_groups=json.dumps(active_groups),
            file_path=str(model_path),
            metrics_json=json.dumps(eval_metrics)
        )
        self.db.add(model_rec)
        self.db.flush()

        run_rec = AnalysisRun(
            dataset_name="synthetic_sql_logs",
            model_id=model_rec.id,
            records_analyzed=len(sql_df),
            anomalies_detected=int(sql_df["is_alert"].sum()),
            alert_threshold=alert_threshold,
            feature_groups_active=json.dumps(active_groups),
            execution_time_seconds=round(time.time() - start_time, 2),
            status="COMPLETED"
        )
        self.db.add(run_rec)
        self.db.flush()

        # 6. Save Alerts
        flagged_df = sql_df[sql_df["is_alert"] == 1]
        for _, row in flagged_df.iterrows():
            event_dict = {
                "user_id": row["user_id"],
                "role": row["role"],
                "department": row["department"],
                "resource": row["resource"],
                "action": row["action"],
                "rows_returned": row.get("rows_returned"),
                "ip_address": row.get("ip_address")
            }
            feat_dict = row.to_dict()
            explanation_data = AlertExplainer.explain_event(
                event_dict=event_dict,
                features_dict=feat_dict,
                risk_score=row["risk_score"],
                severity=row["severity"],
                dataset_source="synthetic_sql"
            )

            alert = AnomalyAlert(
                run_id=run_rec.id,
                event_id=f"{row['event_id']}_{uid}",
                timestamp=str(row["timestamp"]),
                user_identifier=row["user_id"],
                user_role=row["role"],
                department=row["department"],
                resource_accessed=row["resource"],
                query_type=row["action"],
                anomaly_score=row["risk_score"],
                severity=row["severity"],
                explanation=explanation_data["explanation"],
                contributing_factors=json.dumps(explanation_data["contributing_factors"]),
                baseline_comparison=json.dumps(explanation_data["baseline_comparison"]),
                recommended_action="; ".join(explanation_data["recommended_actions"]),
                status="open",
                ground_truth_label=int(row["is_ground_truth_anomaly"]),
                ground_truth_type=str(row["anomaly_type"]) if pd.notna(row["anomaly_type"]) else None,
                dataset_source="synthetic_sql"
            )
            self.db.add(alert)

        self.db.commit()

        return {
            "run_id": run_rec.id,
            "dataset": "synthetic_sql",
            "records_analyzed": len(sql_df),
            "anomalies_detected": int(sql_df["is_alert"].sum()),
            "execution_time_seconds": run_rec.execution_time_seconds,
            "active_feature_groups": active_groups,
            "evaluation_metrics": eval_metrics
        }
