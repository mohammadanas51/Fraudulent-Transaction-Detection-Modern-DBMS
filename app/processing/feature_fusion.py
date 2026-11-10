"""Multi-Dimensional Feature Fusion Layer: Combines Temporal, Frequency, Behavioral, SQL, and Volume dimensions."""
from typing import List, Dict, Tuple, Any, Optional
import numpy as np
import pandas as pd
from app.processing.sql_parser import SQLSemanticParser

class FeatureFusionEngine:
    """Manages multi-dimensional feature extraction, schema validation, and fusion across diverse data sources."""

    FEATURE_GROUPS = {
        "temporal": [
            "login_hour",
            "is_off_hours",
            "days_since_last_login"
        ],
        "frequency": [
            "file_access_count",
            "distinct_files_count"
        ],
        "user_behavior": [
            "is_new_ip",
            "high_sensitivity_count",
            "delete_count",
            "file_volume_zscore"
        ],
        "sql_semantics": [
            "is_select",
            "is_dml",
            "is_ddl",
            "has_join",
            "has_where",
            "has_subquery",
            "has_wildcard",
            "query_complexity",
            "is_dangerous"
        ],
        "data_volume": [
            "rows_returned_log",
            "rows_affected_log",
            "is_massive_volume"
        ]
    }

    @classmethod
    def get_supported_groups(cls, dataset_source: str) -> List[str]:
        """Returns valid feature groups supported by the given data source."""
        if dataset_source == "original":
            return ["temporal", "frequency", "user_behavior"]
        elif dataset_source == "synthetic_sql":
            return ["temporal", "frequency", "user_behavior", "sql_semantics", "data_volume"]
        elif dataset_source == "combined":
            return ["temporal", "frequency", "user_behavior"]
        else:
            return ["temporal", "frequency", "user_behavior"]

    def fuse_original_features(
        self,
        features_df: pd.DataFrame,
        include_baseline_features: bool = True
    ) -> Tuple[pd.DataFrame, List[str], List[str]]:
        """Fuses behavioral features for the original repository dataset."""
        df = features_df.copy()
        
        active_groups = ["temporal", "frequency", "user_behavior"]
        
        # Base feature columns from the upstream notebook
        cols = [
            "login_hour",
            "is_off_hours",
            "days_since_last_login",
            "file_access_count",
            "distinct_files_count",
            "is_new_ip",
            "high_sensitivity_count",
            "delete_count"
        ]
        
        if include_baseline_features and "file_volume_zscore" in df.columns:
            cols.append("file_volume_zscore")
            
        # Ensure all columns exist and are numeric
        for c in cols:
            if c not in df.columns:
                df[c] = 0.0
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

        X = df[cols].copy()
        return X, active_groups, cols

    def fuse_synthetic_sql_features(
        self,
        sql_df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, List[str], List[str]]:
        """Extracts and fuses temporal, behavioral, SQL semantic, and volume features from SQL audit logs."""
        df = sql_df.copy()
        if "datetime" not in df.columns:
            df["datetime"] = pd.to_datetime(df["timestamp"])
            
        df["login_hour"] = df["datetime"].dt.hour
        df["is_off_hours"] = ((df["login_hour"] < 8) | (df["login_hour"] > 18)).astype(int)
        
        # Time gap per user
        df["prev_ts"] = df.groupby("user_id")["datetime"].shift(1)
        df["days_since_last_login"] = (df["datetime"] - df["prev_ts"]).dt.total_seconds().fillna(86400.0) / 86400.0
        
        # Frequency features per user-day
        df["date_str"] = df["datetime"].dt.date.astype(str)
        daily_counts = df.groupby(["user_id", "date_str"])["event_id"].transform("count")
        df["file_access_count"] = daily_counts
        daily_res = df.groupby(["user_id", "date_str"])["resource"].transform("nunique")
        df["distinct_files_count"] = daily_res

        # Behavioral features
        # User IP history
        user_seen_ips: Dict[str, set] = {}
        is_new_ip_list = []
        for _, row in df.iterrows():
            u = str(row["user_id"])
            ip = row.get("ip_address")
            if u not in user_seen_ips:
                user_seen_ips[u] = set()
            is_new = 1 if (len(user_seen_ips[u]) > 0 and ip not in user_seen_ips[u]) else 0
            user_seen_ips[u].add(ip)
            is_new_ip_list.append(is_new)
        df["is_new_ip"] = is_new_ip_list

        df["high_sensitivity_count"] = (df["sensitivity"].isin(["high", "critical"])).astype(int)
        df["delete_count"] = (df["action"].str.upper() == "DELETE").astype(int)

        # Baseline volume deviation
        mean_vol = df.groupby("user_id")["file_access_count"].transform("mean")
        std_vol = df.groupby("user_id")["file_access_count"].transform("std").fillna(1.0).replace(0.0, 1.0)
        df["file_volume_zscore"] = ((df["file_access_count"] - mean_vol) / std_vol).clip(-3.0, 10.0)

        # SQL Semantic features via SQLGlot
        sql_features = []
        for q in df["query_text"]:
            parsed = SQLSemanticParser.parse_query(q)
            sql_features.append({
                "is_select": parsed["is_select"],
                "is_dml": parsed["is_dml"],
                "is_ddl": parsed["is_ddl"],
                "has_join": parsed["has_join"],
                "has_where": parsed["has_where"],
                "has_subquery": parsed["has_subquery"],
                "has_wildcard": parsed["has_wildcard"],
                "query_complexity": parsed["query_complexity"],
                "is_dangerous": parsed["is_dangerous"]
            })
        sql_feat_df = pd.DataFrame(sql_features)
        
        # Data-volume features
        ret_log = np.log1p(df["rows_returned"].fillna(0).astype(float))
        aff_log = np.log1p(df["rows_affected"].fillna(0).astype(float))
        is_massive = (df["rows_returned"] > 10000).astype(int)

        df["rows_returned_log"] = ret_log
        df["rows_affected_log"] = aff_log
        df["is_massive_volume"] = is_massive

        # Combine all features
        for col in sql_feat_df.columns:
            df[col] = sql_feat_df[col].values

        all_cols = (
            self.FEATURE_GROUPS["temporal"] +
            self.FEATURE_GROUPS["frequency"] +
            self.FEATURE_GROUPS["user_behavior"] +
            self.FEATURE_GROUPS["sql_semantics"] +
            self.FEATURE_GROUPS["data_volume"]
        )

        active_groups = ["temporal", "frequency", "user_behavior", "sql_semantics", "data_volume"]
        X = df[all_cols].copy()
        return X, active_groups, all_cols
