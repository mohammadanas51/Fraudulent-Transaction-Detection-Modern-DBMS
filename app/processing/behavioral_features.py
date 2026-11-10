"""Behavioral, Temporal, and Baseline Deviation Feature Engineering."""
import datetime
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from app.config import settings

class BehavioralFeatureExtractor:
    """Extracts chronological, leakage-free temporal and behavioral baseline features."""

    def __init__(
        self,
        working_start_hour: int = settings.WORKING_START_HOUR,
        working_end_hour: int = settings.WORKING_END_HOUR,
        off_hours_buffer: int = settings.OFF_HOURS_BUFFER_HOURS
    ):
        self.working_start_hour = working_start_hour
        self.working_end_hour = working_end_hour
        self.off_hours_buffer = off_hours_buffer

    def extract_from_original_db(self, conn) -> pd.DataFrame:
        """Executes the upstream SQL feature extraction query chaining 6 CTEs."""
        feature_query = """
        WITH login_with_emp AS (
            SELECT 
                l.login_id,
                l.employee_id,
                l.login_timestamp,
                DATE(l.login_timestamp) AS login_date,
                CAST(strftime('%H', l.login_timestamp) AS INTEGER) AS login_hour,
                l.ip_address,
                e.name,
                e.department,
                e.role,
                e.typical_start_hour,
                e.typical_end_hour
            FROM login_events l
            JOIN employees e ON l.employee_id = e.employee_id
        ),
        off_hours_flag AS (
            SELECT *,
                CASE 
                    WHEN login_hour < typical_start_hour - 1 OR login_hour > typical_end_hour + 1 
                    THEN 1 ELSE 0 
                END AS is_off_hours
            FROM login_with_emp
        ),
        ip_history AS (
            SELECT *,
                CASE
                    WHEN ip_address IN (
                        SELECT ip_address FROM login_events l2
                        WHERE l2.employee_id = off_hours_flag.employee_id
                        AND l2.login_timestamp < off_hours_flag.login_timestamp
                    ) THEN 0 ELSE 1
                END AS is_new_ip
            FROM off_hours_flag
        ),
        login_gaps AS (
            SELECT *,
                LAG(login_timestamp) OVER (
                    PARTITION BY employee_id ORDER BY login_timestamp
                ) AS prev_login_timestamp
            FROM ip_history
        ),
        with_gap_days AS (
            SELECT *,
                CASE 
                    WHEN prev_login_timestamp IS NULL THEN NULL
                    ELSE (julianday(login_timestamp) - julianday(prev_login_timestamp))
                END AS days_since_last_login
            FROM login_gaps
        ),
        file_stats AS (
            SELECT 
                employee_id,
                DATE(access_timestamp) AS access_date,
                COUNT(*) AS file_access_count,
                COUNT(DISTINCT file_id) AS distinct_files_count,
                SUM(CASE WHEN sensitivity_level = 'high' THEN 1 ELSE 0 END) AS high_sensitivity_count,
                SUM(CASE WHEN action = 'delete' THEN 1 ELSE 0 END) AS delete_count
            FROM file_access_events
            GROUP BY employee_id, DATE(access_timestamp)
        )
        SELECT 
            w.login_id,
            w.employee_id,
            w.name,
            w.department,
            w.role,
            w.login_timestamp,
            w.login_date,
            w.login_hour,
            w.is_off_hours,
            w.is_new_ip,
            w.days_since_last_login,
            COALESCE(f.file_access_count, 0) AS file_access_count,
            COALESCE(f.distinct_files_count, 0) AS distinct_files_count,
            COALESCE(f.high_sensitivity_count, 0) AS high_sensitivity_count,
            COALESCE(f.delete_count, 0) AS delete_count
        FROM with_gap_days w
        LEFT JOIN file_stats f 
            ON w.employee_id = f.employee_id AND w.login_date = f.access_date
        ORDER BY w.employee_id, w.login_timestamp
        """
        df = pd.read_sql_query(feature_query, conn)
        
        # Merge ground-truth session labels if available
        labels_query = "SELECT employee_id, session_date, is_anomaly, anomaly_type FROM session_labels"
        try:
            labels_df = pd.read_sql_query(labels_query, conn)
            df = df.merge(
                labels_df,
                left_on=["employee_id", "login_date"],
                right_on=["employee_id", "session_date"],
                how="left"
            )
            df["is_anomaly"] = df["is_anomaly"].fillna(0).astype(int)
            df = df.drop(columns=["session_date"], errors="ignore")
        except Exception:
            df["is_anomaly"] = 0
            df["anomaly_type"] = None

        # Clean days_since_last_login nulls with median
        median_gap = df["days_since_last_login"].median()
        if pd.isna(median_gap):
            median_gap = 1.0
        df["days_since_last_login"] = df["days_since_last_login"].fillna(median_gap)
        
        # Enrich with behavioral baseline deviations
        df = self._enrich_user_baselines(df)
        return df

    def _enrich_user_baselines(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enriches dataframe with user-specific rolling behavioral baseline features without lookahead leakage."""
        df = df.copy()
        
        # Historical running mean and std of file accesses per user
        df["user_hist_file_mean"] = df.groupby("employee_id")["file_access_count"].transform(
            lambda x: x.expanding(min_periods=1).mean().shift(1)
        ).fillna(df["file_access_count"].mean())

        df["user_hist_file_std"] = df.groupby("employee_id")["file_access_count"].transform(
            lambda x: x.expanding(min_periods=2).std().shift(1)
        ).fillna(1.0).replace(0.0, 1.0)

        # Baseline volume z-score
        df["file_volume_zscore"] = (df["file_access_count"] - df["user_hist_file_mean"]) / df["user_hist_file_std"]
        df["file_volume_zscore"] = df["file_volume_zscore"].clip(lower=-3.0, upper=10.0)

        # Sensitivity ratio
        df["sensitivity_ratio"] = df["high_sensitivity_count"] / (df["file_access_count"] + 1e-5)

        # Burst indicator: file count exceeds 3x user baseline
        df["is_burst_access"] = (df["file_access_count"] > (df["user_hist_file_mean"] * 2.5 + 5)).astype(int)

        return df

    def extract_from_event_stream(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Extracts temporal, behavioral, and baseline features from a generic normalized event stream."""
        if events_df.empty:
            return pd.DataFrame()

        df = events_df.copy()
        if "datetime" not in df.columns:
            df["datetime"] = pd.to_datetime(df["timestamp"])
            
        df = df.sort_values(["user_id", "datetime"]).reset_index(drop=True)

        # 1. Temporal features
        df["hour_of_day"] = df["datetime"].dt.hour
        df["day_of_week"] = df["datetime"].dt.dayofweek  # 0=Monday, 6=Sunday
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        
        # Off-hours calculation
        df["is_off_hours"] = (
            (df["hour_of_day"] < self.working_start_hour - self.off_hours_buffer) | 
            (df["hour_of_day"] > self.working_end_hour + self.off_hours_buffer)
        ).astype(int)

        # Time delta since previous event for user
        df["prev_timestamp"] = df.groupby("user_id")["datetime"].shift(1)
        df["time_since_prev_event_seconds"] = (df["datetime"] - df["prev_timestamp"]).dt.total_seconds().fillna(3600.0)
        df["time_since_prev_event_hours"] = df["time_since_prev_event_seconds"] / 3600.0

        # 2. Historical expanding profile per user (No lookahead leakage!)
        user_seen_ips: Dict[str, set] = {}
        user_seen_resources: Dict[str, set] = {}
        is_new_ip_list = []
        is_unusual_res_list = []

        for _, row in df.iterrows():
            u = str(row["user_id"])
            ip = row.get("ip_address")
            res = str(row.get("resource"))

            # Track IP history
            if u not in user_seen_ips:
                user_seen_ips[u] = set()
            if ip and ip != "None":
                is_new_ip = 1 if (len(user_seen_ips[u]) > 0 and ip not in user_seen_ips[u]) else 0
                user_seen_ips[u].add(ip)
            else:
                is_new_ip = 0
            is_new_ip_list.append(is_new_ip)

            # Track Resource history
            if u not in user_seen_resources:
                user_seen_resources[u] = set()
            is_unusual_res = 1 if (len(user_seen_resources[u]) >= 3 and res not in user_seen_resources[u]) else 0
            user_seen_resources[u].add(res)
            is_unusual_res_list.append(is_unusual_res)

        df["is_new_ip"] = is_new_ip_list
        df["is_unusual_resource"] = is_unusual_res_list

        # Rolling 10-minute burst count per user
        df.set_index("datetime", inplace=True)
        burst_counts = df.groupby("user_id")["event_id"].rolling("10min").count() - 1
        df.reset_index(inplace=True)
        df["burst_10min_count"] = burst_counts.values

        return df
