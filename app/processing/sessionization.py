"""Sessionization Engine: Reconstructs logical sessions using inactivity timeouts and user context."""
import datetime
from typing import List, Dict, Any, Optional
import pandas as pd
from app.config import settings

class Sessionizer:
    def __init__(self, inactivity_timeout_minutes: int = 30):
        self.inactivity_timeout = datetime.timedelta(minutes=inactivity_timeout_minutes)

    def sessionize_events(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Groups chronological events into logical sessions per user with session-level metrics."""
        if events_df.empty:
            return pd.DataFrame()

        df = events_df.copy()
        if "datetime" not in df.columns:
            df["datetime"] = pd.to_datetime(df["timestamp"])
            
        df = df.sort_values(["user_id", "datetime"]).reset_index(drop=True)
        
        # Calculate time difference between consecutive events for each user
        df["prev_datetime"] = df.groupby("user_id")["datetime"].shift(1)
        df["time_diff"] = df["datetime"] - df["prev_datetime"]
        
        # Flag new session if first event or gap exceeds inactivity timeout
        df["is_new_session"] = (df["prev_datetime"].isna()) | (df["time_diff"] > self.inactivity_timeout)
        df["session_idx"] = df.groupby("user_id")["is_new_session"].cumsum()
        
        # Generate clean session ID
        df["inferred_session_id"] = df["user_id"].astype(str) + "_s" + df["session_idx"].astype(str)
        
        # Aggregate sessions via direct group iteration (fast and warning-free)
        session_rows: List[Dict[str, Any]] = []
        for (user_id, sess_idx), group in df.groupby(["user_id", "session_idx"]):
            start_ts = group["datetime"].min()
            end_ts = group["datetime"].max()
            duration_sec = (end_ts - start_ts).total_seconds()
            
            role = group["role"].iloc[0] if "role" in group.columns else "Unknown"
            dept = group["department"].iloc[0] if "department" in group.columns else "General"
            
            total_events = len(group)
            distinct_resources = group["resource"].nunique() if "resource" in group.columns else 0
            
            # Action counts
            action_counts = group["action"].value_counts().to_dict() if "action" in group.columns else {}
            reads = action_counts.get("read", 0) + action_counts.get("SELECT", 0)
            writes = action_counts.get("write", 0) + action_counts.get("UPDATE", 0) + action_counts.get("INSERT", 0)
            deletes = action_counts.get("delete", 0) + action_counts.get("DELETE", 0)
            
            # Sensitivity
            high_sens = 0
            if "sensitivity" in group.columns:
                high_sens = int((group["sensitivity"].isin(["high", "critical"])).sum())
                
            # Ground truth anomaly label if present
            is_anomaly = 0
            anomaly_type = None
            if "is_ground_truth_anomaly" in group.columns:
                is_anomaly = int(group["is_ground_truth_anomaly"].max() > 0)
                anom_rows = group[group["is_ground_truth_anomaly"] == 1]
                if not anom_rows.empty and "anomaly_type" in anom_rows.columns:
                    anomaly_type = anom_rows["anomaly_type"].dropna().iloc[0] if not anom_rows["anomaly_type"].dropna().empty else None

            # Volume if present
            rows_ret = group["rows_returned"].sum() if "rows_returned" in group.columns and not group["rows_returned"].isna().all() else None
            rows_aff = group["rows_affected"].sum() if "rows_affected" in group.columns and not group["rows_affected"].isna().all() else None
            
            session_rows.append({
                "session_id": group["inferred_session_id"].iloc[0],
                "user_id": user_id,
                "role": role,
                "department": dept,
                "start_timestamp": start_ts.isoformat(),
                "end_timestamp": end_ts.isoformat(),
                "duration_seconds": duration_sec,
                "total_events": total_events,
                "distinct_resources": distinct_resources,
                "read_count": reads,
                "write_count": writes,
                "delete_count": deletes,
                "high_sensitivity_count": high_sens,
                "rows_returned": rows_ret,
                "rows_affected": rows_aff,
                "is_anomaly": is_anomaly,
                "anomaly_type": anomaly_type
            })

        return pd.DataFrame(session_rows)
