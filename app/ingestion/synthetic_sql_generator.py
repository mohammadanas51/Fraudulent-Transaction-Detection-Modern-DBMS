"""Synthetic SQL Audit Log Generator with realistic enterprise database profiles and injected anomalies."""
import sqlite3
import random
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from app.config import settings

class SyntheticSQLGenerator:
    def __init__(self, random_seed: int = 42, output_db_path: Optional[Path] = None):
        self.random_seed = random_seed
        self.output_db_path = Path(output_db_path) if output_db_path else settings.SYNTHETIC_DB_PATH
        random.seed(self.random_seed)

    def generate(self, n_events: int = 2500, anomaly_rate: float = 0.04) -> pd.DataFrame:
        """Generates synthetic database audit logs with documented behavioral patterns and injected anomalies."""
        random.seed(self.random_seed)
        
        users_roles = [
            ("analyst_sarah", "DataAnalyst", "Analytics"),
            ("analyst_david", "DataAnalyst", "Analytics"),
            ("dba_mike", "DBA", "IT Operations"),
            ("app_backend_svc", "AppService", "Engineering"),
            ("finance_clerk_anna", "FinanceClerk", "Finance"),
            ("dev_alex", "Developer", "Engineering"),
            ("auditor_rachel", "InternalAuditor", "Compliance")
        ]
        
        normal_tables_by_role = {
            "DataAnalyst": ["orders", "products", "order_items", "sales_summary", "store_inventory"],
            "DBA": ["system_metrics", "backup_logs", "connection_pool", "orders", "audit_trail"],
            "AppService": ["orders", "users", "sessions", "cart_items", "products"],
            "FinanceClerk": ["invoices", "payments", "billing_accounts", "orders"],
            "Developer": ["test_suites", "feature_flags", "products", "staging_data"],
            "InternalAuditor": ["audit_trail", "access_history", "compliance_checks"]
        }
        
        restricted_tables = ["salaries", "credit_cards", "employee_ssn", "system_credentials", "db_master_keys"]
        
        base_time = datetime.datetime(2026, 2, 1, 8, 0, 0)
        events: List[Dict[str, Any]] = []
        n_anomalies = max(10, int(n_events * anomaly_rate))
        anomaly_indices = set(random.sample(range(n_events), n_anomalies))
        
        # Anomaly types
        anomaly_types = [
            "UNUSUAL_TABLE_ACCESS",
            "DATA_EXFILTRATION_VOLUME",
            "OFF_HOURS_BURST",
            "DANGEROUS_STATEMENT",
            "SQL_INJECTION_PATTERN"
        ]
        
        for i in range(n_events):
            is_anomaly = 1 if i in anomaly_indices else 0
            u_name, u_role, u_dept = random.choice(users_roles)
            
            # Timestamp generation
            day_offset = random.randint(0, 59)
            if is_anomaly:
                anom_type = random.choice(anomaly_types)
            else:
                anom_type = None
                
            if is_anomaly and anom_type == "OFF_HOURS_BURST":
                hour = random.randint(1, 4)
                minute = random.randint(0, 59)
            else:
                # AppService runs 24/7, humans usually 8 AM to 6 PM
                if u_role == "AppService":
                    hour = random.randint(0, 23)
                else:
                    hour = random.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
                minute = random.randint(0, 59)
                
            second = random.randint(0, 59)
            event_ts = base_time + datetime.timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)
            ts_str = event_ts.isoformat()
            
            session_id = f"sql_sess_{u_name}_{event_ts.strftime('%Y%m%d_%H')}"
            tx_id = f"tx_{random.randint(100000, 999999)}"
            
            # Default normal queries
            allowed_tables = normal_tables_by_role[u_role]
            target_table = random.choice(allowed_tables)
            query_type = "SELECT"
            rows_returned = random.randint(1, 200)
            rows_affected = 0
            
            if is_anomaly:
                if anom_type == "UNUSUAL_TABLE_ACCESS":
                    target_table = random.choice(restricted_tables)
                    query = f"SELECT * FROM {target_table} WHERE active = 1"
                    rows_returned = random.randint(50, 500)
                    query_type = "SELECT"
                    
                elif anom_type == "DATA_EXFILTRATION_VOLUME":
                    target_table = random.choice(["customers", "orders", "users"])
                    query = f"SELECT * FROM {target_table} -- Full dump exfiltration"
                    rows_returned = random.randint(50000, 250000)
                    query_type = "SELECT"
                    
                elif anom_type == "OFF_HOURS_BURST":
                    target_table = random.choice(allowed_tables)
                    query = f"SELECT * FROM {target_table} WHERE status = 'pending' ORDER BY id DESC"
                    rows_returned = random.randint(2000, 15000)
                    query_type = "SELECT"
                    
                elif anom_type == "DANGEROUS_STATEMENT":
                    action_choice = random.choice(["DROP", "TRUNCATE", "UNRESTRICTED_DELETE"])
                    if action_choice == "DROP":
                        query = f"DROP TABLE {target_table};"
                        query_type = "DROP"
                        rows_affected = 0
                        rows_returned = 0
                    elif action_choice == "TRUNCATE":
                        query = f"TRUNCATE TABLE {target_table};"
                        query_type = "TRUNCATE"
                        rows_affected = 0
                        rows_returned = 0
                    else:
                        query = f"DELETE FROM {target_table} WHERE 1=1;"
                        query_type = "DELETE"
                        rows_affected = random.randint(5000, 50000)
                        rows_returned = 0
                        
                elif anom_type == "SQL_INJECTION_PATTERN":
                    query = f"SELECT * FROM users WHERE username = 'admin' OR '1'='1' UNION SELECT table_name, column_name, 1, 2 FROM information_schema.columns;"
                    target_table = "users"
                    query_type = "SELECT"
                    rows_returned = random.randint(100, 1500)
                    
            else:
                # Normal pattern
                q_rand = random.random()
                if q_rand < 0.70:
                    query_type = "SELECT"
                    where_clause = f"WHERE id = {random.randint(1, 1000)}" if random.random() > 0.3 else ""
                    query = f"SELECT id, created_at, status FROM {target_table} {where_clause} LIMIT {random.randint(10, 100)};"
                    rows_returned = random.randint(1, 100)
                    rows_affected = 0
                elif q_rand < 0.85:
                    query_type = "INSERT"
                    query = f"INSERT INTO {target_table} (created_at, status) VALUES ('{ts_str}', 'active');"
                    rows_returned = 0
                    rows_affected = 1
                elif q_rand < 0.95:
                    query_type = "UPDATE"
                    query = f"UPDATE {target_table} SET status = 'processed' WHERE id = {random.randint(1, 5000)};"
                    rows_returned = 0
                    rows_affected = random.randint(1, 3)
                else:
                    query_type = "DELETE"
                    query = f"DELETE FROM {target_table} WHERE id = {random.randint(1, 5000)};"
                    rows_returned = 0
                    rows_affected = 1

            events.append({
                "event_id": f"sql_{i+1:05d}",
                "timestamp": ts_str,
                "user_id": u_name,
                "user_name": u_name.replace("_", " ").title(),
                "role": u_role,
                "department": u_dept,
                "event_type": "SQL_QUERY",
                "resource": target_table,
                "query_text": query,
                "action": query_type,
                "sensitivity": "critical" if target_table in restricted_tables else ("high" if target_table in ["orders", "invoices"] else "low"),
                "ip_address": f"192.168.1.{random.randint(20, 99)}",
                "rows_returned": rows_returned,
                "rows_affected": rows_affected,
                "session_id": session_id,
                "transaction_id": tx_id,
                "is_ground_truth_anomaly": is_anomaly,
                "anomaly_type": anom_type,
                "dataset_source": "synthetic_sql"
            })
            
        df = pd.DataFrame(events)
        df["datetime"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("datetime").reset_index(drop=True)
        return df

    def save_to_sqlite(self, df: pd.DataFrame) -> Path:
        """Saves generated synthetic SQL audit logs to SQLite database."""
        self.output_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.output_db_path)
        
        # Save table
        df_to_save = df.drop(columns=["datetime"], errors="ignore")
        df_to_save.to_sql("sql_audit_logs", conn, if_exists="replace", index=False)
        
        # Create indices for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sql_timestamp ON sql_audit_logs(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sql_user ON sql_audit_logs(user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sql_resource ON sql_audit_logs(resource);")
        conn.commit()
        conn.close()
        return self.output_db_path
