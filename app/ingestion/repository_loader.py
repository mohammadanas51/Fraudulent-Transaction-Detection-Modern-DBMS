"""Repository and Dataset Loader for access_logs.db."""
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd
from app.config import settings

class RepositoryLoader:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else settings.ORIGINAL_DB_PATH
        if not self.db_path.exists():
            raise FileNotFoundError(f"Original access logs database not found at: {self.db_path}")

    def get_connection(self) -> sqlite3.Connection:
        """Returns a read-only SQLite connection."""
        uri = f"file:{self.db_path.resolve().as_posix()}?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def audit_schema(self) -> Dict[str, Any]:
        """Inspects table names, column schemas, row counts, and missing values."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
        
        audit: Dict[str, Any] = {"database_path": str(self.db_path), "tables": {}}
        for t in tables:
            row_count = cursor.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            cols = cursor.execute(f"PRAGMA table_info({t})").fetchall()
            col_list = [{"cid": c[0], "name": c[1], "type": c[2], "notnull": bool(c[3]), "pk": bool(c[5])} for c in cols]
            
            null_counts = {}
            for col in col_list:
                c_name = col["name"]
                n_nulls = cursor.execute(f"SELECT COUNT(*) FROM {t} WHERE {c_name} IS NULL").fetchone()[0]
                null_counts[c_name] = n_nulls
                
            time_range = {}
            for col in col_list:
                c_name = col["name"]
                if "timestamp" in c_name.lower() or "date" in c_name.lower():
                    min_max = cursor.execute(f"SELECT MIN({c_name}), MAX({c_name}) FROM {t}").fetchone()
                    time_range[c_name] = {"min": min_max[0], "max": min_max[1]}
                    
            audit["tables"][t] = {
                "row_count": row_count,
                "columns": col_list,
                "null_counts": null_counts,
                "time_range": time_range
            }
        
        conn.close()
        return audit

    def load_employees(self) -> pd.DataFrame:
        conn = self.get_connection()
        df = pd.read_sql_query("SELECT * FROM employees", conn)
        conn.close()
        return df

    def load_login_events(self) -> pd.DataFrame:
        conn = self.get_connection()
        df = pd.read_sql_query("SELECT * FROM login_events ORDER BY login_timestamp ASC", conn)
        conn.close()
        return df

    def load_file_access_events(self) -> pd.DataFrame:
        conn = self.get_connection()
        df = pd.read_sql_query("SELECT * FROM file_access_events ORDER BY access_timestamp ASC", conn)
        conn.close()
        return df

    def load_session_labels(self) -> pd.DataFrame:
        conn = self.get_connection()
        df = pd.read_sql_query("SELECT * FROM session_labels", conn)
        conn.close()
        return df

    def field_presence_summary(self) -> Dict[str, Any]:
        """Returns standard verification checklist of required project dimensions."""
        return {
            "Event ID": {"present": True, "source": "login_id, access_id"},
            "Timestamp": {"present": True, "source": "login_timestamp, access_timestamp"},
            "User or Employee ID": {"present": True, "source": "employee_id in all tables"},
            "User Role": {"present": True, "source": "role & department in employees"},
            "Accessed Resource or File": {"present": True, "source": "file_id in file_access_events"},
            "SQL Query Text": {"present": False, "note": "Original dataset is OS/App file access log. Available in Synthetic SQL workflow."},
            "Query Type": {"present": False, "note": "Available in Synthetic SQL workflow."},
            "Database Table": {"present": False, "note": "Available in Synthetic SQL workflow."},
            "Database Columns": {"present": False, "note": "Available in Synthetic SQL workflow."},
            "Session ID": {"present": False, "note": "Derived via time-window sessionizer."},
            "Transaction ID": {"present": False, "note": "Available in Synthetic SQL workflow."},
            "Rows Returned": {"present": False, "note": "Available in Synthetic SQL workflow; marked unavailable for original dataset."},
            "Rows Affected": {"present": False, "note": "Available in Synthetic SQL workflow; marked unavailable for original dataset."},
            "Ground-Truth Anomaly Label": {"present": True, "source": "session_labels (87 anomalous sessions)"}
        }
