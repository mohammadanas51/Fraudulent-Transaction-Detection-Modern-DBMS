"""Tests for Repository and Dataset Loader."""
import hashlib
from pathlib import Path
import pytest
from app.config import settings
from app.ingestion.repository_loader import RepositoryLoader

def get_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def test_loader_schema_audit():
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    audit = loader.audit_schema()
    
    assert "tables" in audit
    tables = audit["tables"]
    assert "employees" in tables
    assert "login_events" in tables
    assert "file_access_events" in tables
    assert "session_labels" in tables
    
    assert tables["employees"]["row_count"] == 50
    assert tables["login_events"]["row_count"] == 2905
    assert tables["file_access_events"]["row_count"] == 12317
    assert tables["session_labels"]["row_count"] == 87

def test_loader_load_dataframes():
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    emp_df = loader.load_employees()
    login_df = loader.load_login_events()
    file_df = loader.load_file_access_events()
    labels_df = loader.load_session_labels()
    
    assert len(emp_df) == 50
    assert len(login_df) == 2905
    assert len(file_df) == 12317
    assert len(labels_df) == 87
    assert "employee_id" in emp_df.columns
    assert "login_timestamp" in login_df.columns

def test_field_presence_summary():
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    summary = loader.field_presence_summary()
    assert summary["Event ID"]["present"] is True
    assert summary["SQL Query Text"]["present"] is False
    assert summary["Rows Returned"]["present"] is False
    assert summary["Ground-Truth Anomaly Label"]["present"] is True

def test_dataset_immutability():
    """Confirms reading data does not alter file content hash."""
    initial_hash = get_file_hash(settings.ORIGINAL_DB_PATH)
    loader = RepositoryLoader(settings.ORIGINAL_DB_PATH)
    _ = loader.audit_schema()
    _ = loader.load_employees()
    after_hash = get_file_hash(settings.ORIGINAL_DB_PATH)
    assert initial_hash == after_hash, "Original database file was modified!"
