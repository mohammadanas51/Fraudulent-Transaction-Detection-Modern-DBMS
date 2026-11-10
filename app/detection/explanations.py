"""Explainable Alert Engine: Transparent Behavioral Deviation Attribution & Human-Readable Narratives."""
from typing import Dict, List, Any, Optional
import pandas as pd

class AlertExplainer:
    """Generates transparent, evidence-based explanations for flagged anomaly events."""

    @staticmethod
    def explain_event(
        event_dict: Dict[str, Any],
        features_dict: Dict[str, Any],
        risk_score: float,
        severity: str,
        dataset_source: str = "original"
    ) -> Dict[str, Any]:
        """Synthesizes feature deviations into concrete behavioral indicators and recommendations."""
        contributing_factors: List[str] = []
        baseline_comparison: Dict[str, Any] = {}
        recommendations: List[str] = []
        narrative_parts: List[str] = []

        # 1. Temporal Deviations
        is_off_hours = int(features_dict.get("is_off_hours", 0))
        login_hour = int(features_dict.get("login_hour", event_dict.get("login_hour", 12)))
        
        if is_off_hours:
            factor = f"Off-hours access detected at {login_hour:02d}:00 (outside scheduled working profile)"
            contributing_factors.append(factor)
            narrative_parts.append(f"occurred outside normal operating hours ({login_hour:02d}:00)")
            recommendations.append("Verify if user submitted an authorized overtime or off-hours maintenance change request.")

        # 2. Inactivity Gaps
        days_gap = float(features_dict.get("days_since_last_login", 0.0))
        if days_gap > 3.0:
            contributing_factors.append(f"Extended inactivity gap of {days_gap:.1f} days since previous activity")

        # 3. New / Unfamiliar IP
        is_new_ip = int(features_dict.get("is_new_ip", 0))
        ip_addr = event_dict.get("ip_address")
        if is_new_ip and ip_addr:
            contributing_factors.append(f"Originating IP address ({ip_addr}) is unfamiliar and not observed in user's historical pool")
            narrative_parts.append(f"originated from an unrecognized IP address ({ip_addr})")
            recommendations.append("Inspect network perimeter logs, geo-location, and VPN session authenticity for the client IP.")

        # 4. Volume / Burst Deviations
        file_count = float(features_dict.get("file_access_count", 0.0))
        hist_mean = float(features_dict.get("user_hist_file_mean", 4.0))
        vol_zscore = float(features_dict.get("file_volume_zscore", 0.0))

        baseline_comparison["observed_events_count"] = file_count
        baseline_comparison["user_historical_mean"] = round(hist_mean, 1)
        baseline_comparison["volume_zscore"] = round(vol_zscore, 2)

        if file_count > 12 or vol_zscore > 2.5:
            factor = f"Significant access volume burst: {int(file_count)} operations (user baseline avg: {hist_mean:.1f})"
            contributing_factors.append(factor)
            narrative_parts.append(f"generated an abnormally high volume of access activity ({int(file_count)} events vs. baseline {hist_mean:.1f})")
            recommendations.append("Review whether bulk data extraction or automated script execution was conducted without authorization.")

        # 5. Sensitivity & Deletions
        high_sens = int(features_dict.get("high_sensitivity_count", 0))
        delete_count = int(features_dict.get("delete_count", 0))

        if high_sens >= 4:
            contributing_factors.append(f"Elevated interaction with high-sensitivity assets ({high_sens} high-sensitivity items accessed)")
            narrative_parts.append(f"targeted multiple restricted or high-sensitivity resources ({high_sens} events)")
            recommendations.append("Check permissions audit trail and evaluate potential insider risk or credential compromise.")

        if delete_count > 0:
            contributing_factors.append(f"File/record deletion operations detected ({delete_count} delete actions)")
            recommendations.append("Confirm validity of deletion actions to prevent data loss or destructive tampering.")

        # 6. SQL Semantic Deviations (if SQL dataset)
        if dataset_source == "synthetic_sql":
            query_type = event_dict.get("action") or event_dict.get("query_type")
            is_ddl = int(features_dict.get("is_ddl", 0))
            is_dangerous = int(features_dict.get("is_dangerous", 0))
            rows_returned = event_dict.get("rows_returned")
            target_res = event_dict.get("resource")

            baseline_comparison["rows_returned"] = rows_returned

            if is_dangerous or is_ddl:
                contributing_factors.append(f"Potentially destructive SQL command executed ({query_type} operation on table '{target_res}')")
                narrative_parts.append(f"executed a high-risk DDL/dangerous SQL statement ({query_type})")
                recommendations.append("Immediately verify whether schema modification or table alteration was pre-approved in change ticketing.")

            if rows_returned and rows_returned > 5000:
                contributing_factors.append(f"Massive data exfiltration volume indicator: {rows_returned:,} rows returned")
                narrative_parts.append(f"retrieved an exceptionally large result set ({rows_returned:,} rows)")
                recommendations.append("Audit endpoint egress traffic and investigate database export/dump logs for exfiltration.")

            if target_res in ["salaries", "credit_cards", "system_credentials", "db_master_keys"]:
                contributing_factors.append(f"Access to highly restricted table '{target_res}' not typical for role {event_dict.get('role')}")
                narrative_parts.append(f"queried confidential table '{target_res}'")
                recommendations.append("Validate role-based access control (RBAC) privileges for this user.")

        # Build Synthesis Narrative
        user_id = event_dict.get("user_id", "Unknown")
        role = event_dict.get("role", "Associate")

        if narrative_parts:
            narrative = f"This event was flagged for user {user_id} ({role}) because the activity " + "; and ".join(narrative_parts) + "."
        else:
            narrative = (
                f"This event for user {user_id} ({role}) was flagged due to a multi-dimensional behavioral combination "
                "that placed it in a sparse region of normal operational density, though individual features remain near threshold boundaries."
            )

        if not recommendations:
            recommendations.append("Review user activity timeline and contact user manager if context is unexplained.")

        return {
            "risk_score": risk_score,
            "severity": severity,
            "explanation": narrative,
            "contributing_factors": contributing_factors,
            "baseline_comparison": baseline_comparison,
            "recommended_actions": recommendations,
            "disclaimer": (
                "Isolation Forest computes multi-feature geometric isolation depth. "
                "Contributing factors are derived transparently via feature deviation thresholds and baseline comparisons."
            )
        }
