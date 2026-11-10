"""Standardized schema and normalization for heterogeneous security events."""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import pandas as pd

class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    user_id: str
    user_name: Optional[str] = None
    role: Optional[str] = "Unknown"
    department: Optional[str] = "General"
    event_type: str  # "LOGIN", "FILE_ACCESS", "SQL_QUERY"
    resource: str    # File ID or DB Table
    action: str      # read, write, delete, SELECT, UPDATE, etc.
    sensitivity: str # low, medium, high, critical
    ip_address: Optional[str] = None
    query_text: Optional[str] = None
    rows_returned: Optional[int] = None
    rows_affected: Optional[int] = None
    session_id: Optional[str] = None
    is_ground_truth_anomaly: Optional[int] = None
    anomaly_type: Optional[str] = None
    dataset_source: str = "original"

def normalize_original_events(
    employees_df: pd.DataFrame,
    login_events_df: pd.DataFrame,
    file_events_df: pd.DataFrame,
    session_labels_df: Optional[pd.DataFrame] = None
) -> pd.DataFrame:
    """Combines and normalizes original repository logs into a unified DataFrame."""
    # Build employee lookup dict
    emp_map = employees_df.set_index("employee_id").to_dict(orient="index")
    
    # Session label lookup
    label_map = {}
    if session_labels_df is not None and not session_labels_df.empty:
        for _, row in session_labels_df.iterrows():
            key = (int(row["employee_id"]), str(row["session_date"]))
            label_map[key] = (int(row["is_anomaly"]), str(row["anomaly_type"]))
            
    records: List[Dict[str, Any]] = []
    
    # Process login events
    for _, row in login_events_df.iterrows():
        emp_id = int(row["employee_id"])
        emp_info = emp_map.get(emp_id, {})
        ts = str(row["login_timestamp"])
        date_str = ts.split("T")[0] if "T" in ts else ts.split(" ")[0]
        
        is_anom, anom_type = label_map.get((emp_id, date_str), (0, None))
        
        records.append({
            "event_id": f"login_{row['login_id']}",
            "raw_id": int(row["login_id"]),
            "timestamp": ts,
            "date": date_str,
            "user_id": str(emp_id),
            "user_name": emp_info.get("name", f"Emp-{emp_id}"),
            "role": emp_info.get("role", "Associate"),
            "department": emp_info.get("department", "General"),
            "event_type": "LOGIN",
            "resource": "system_portal",
            "action": "login",
            "sensitivity": "low",
            "ip_address": row.get("ip_address"),
            "query_text": None,
            "rows_returned": None,
            "rows_affected": None,
            "session_id": f"sess_{emp_id}_{date_str}",
            "is_ground_truth_anomaly": is_anom,
            "anomaly_type": anom_type,
            "dataset_source": "original"
        })
        
    # Process file access events
    for _, row in file_events_df.iterrows():
        emp_id = int(row["employee_id"])
        emp_info = emp_map.get(emp_id, {})
        ts = str(row["access_timestamp"])
        date_str = ts.split("T")[0] if "T" in ts else ts.split(" ")[0]
        
        is_anom, anom_type = label_map.get((emp_id, date_str), (0, None))
        
        records.append({
            "event_id": f"file_{row['access_id']}",
            "raw_id": int(row["access_id"]),
            "timestamp": ts,
            "date": date_str,
            "user_id": str(emp_id),
            "user_name": emp_info.get("name", f"Emp-{emp_id}"),
            "role": emp_info.get("role", "Associate"),
            "department": emp_info.get("department", "General"),
            "event_type": "FILE_ACCESS",
            "resource": f"file_{row['file_id']}",
            "action": row["action"],
            "sensitivity": row["sensitivity_level"],
            "ip_address": None,
            "query_text": None,
            "rows_returned": None,
            "rows_affected": None,
            "session_id": f"sess_{emp_id}_{date_str}",
            "is_ground_truth_anomaly": is_anom,
            "anomaly_type": anom_type,
            "dataset_source": "original"
        })
        
    df = pd.DataFrame(records)
    df["datetime"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("datetime").reset_index(drop=True)
    return df
