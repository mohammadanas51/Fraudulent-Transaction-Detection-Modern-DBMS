"""SQLAlchemy Database Models for Application State & Alerts."""
import datetime
from sqlalchemy import Column, Integer, Float, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class DatasetMetadata(Base):
    __tablename__ = "dataset_metadata"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    source_type = Column(String(50), nullable=False)  # "original", "synthetic_sql", "combined"
    file_path = Column(String(255), nullable=False)
    row_count = Column(Integer, default=0)
    user_count = Column(Integer, default=0)
    time_range_start = Column(String(50), nullable=True)
    time_range_end = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    has_ground_truth = Column(Boolean, default=False)
    created_at = Column(DateTime, default=get_utc_now)


class ModelMetadata(Base):
    __tablename__ = "model_metadata"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_name = Column(String(100), unique=True, nullable=False)
    algorithm = Column(String(50), default="IsolationForest")
    dataset_source = Column(String(50), nullable=False)
    contamination = Column(Float, default=0.03)
    n_estimators = Column(Integer, default=200)
    random_state = Column(Integer, default=42)
    feature_names = Column(Text, nullable=False)  # JSON array
    feature_groups = Column(Text, nullable=False)  # JSON array
    file_path = Column(String(255), nullable=False)
    metrics_json = Column(Text, nullable=True)  # JSON evaluation metrics
    trained_at = Column(DateTime, default=get_utc_now)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_timestamp = Column(DateTime, default=get_utc_now)
    dataset_name = Column(String(100), nullable=False)
    model_id = Column(Integer, ForeignKey("model_metadata.id"), nullable=True)
    records_analyzed = Column(Integer, default=0)
    anomalies_detected = Column(Integer, default=0)
    alert_threshold = Column(Float, default=60.0)
    feature_groups_active = Column(Text, nullable=False)  # JSON list
    execution_time_seconds = Column(Float, default=0.0)
    status = Column(String(50), default="COMPLETED")
    
    alerts = relationship("AnomalyAlert", back_populates="analysis_run", cascade="all, delete-orphan")


class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("analysis_runs.id"), nullable=False)
    event_id = Column(String(100), nullable=False)
    timestamp = Column(String(50), nullable=False)
    user_identifier = Column(String(100), nullable=False)
    user_role = Column(String(100), nullable=True)
    department = Column(String(100), nullable=True)
    resource_accessed = Column(String(255), nullable=True)
    query_type = Column(String(50), nullable=True)
    anomaly_score = Column(Float, nullable=False)  # 0 to 100
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=False)
    contributing_factors = Column(Text, nullable=True)  # JSON array of factors
    baseline_comparison = Column(Text, nullable=True)   # JSON object
    recommended_action = Column(Text, nullable=True)
    status = Column(String(30), default="open")  # open, investigating, resolved, false_positive
    ground_truth_label = Column(Integer, nullable=True)  # 0 or 1 if known
    ground_truth_type = Column(String(100), nullable=True)
    dataset_source = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
    
    analysis_run = relationship("AnalysisRun", back_populates="alerts")
    notes = relationship("InvestigationNote", back_populates="alert", cascade="all, delete-orphan")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("anomaly_alerts.id"), nullable=False)
    author = Column(String(100), default="Security Analyst")
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
    
    alert = relationship("AnomalyAlert", back_populates="notes")
