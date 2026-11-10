import sqlite3
import json

db_path = "upstream_repo/access_logs.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]

report = {}
for t in tables:
    count = cursor.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
    cols = cursor.execute(f"PRAGMA table_info({t})").fetchall()
    col_info = [{"cid": c[0], "name": c[1], "type": c[2], "notnull": c[3], "pk": c[5]} for c in cols]
    
    # check nulls
    null_counts = {}
    for c in cols:
        col_name = c[1]
        n_nulls = cursor.execute(f"SELECT count(*) FROM {t} WHERE {col_name} IS NULL").fetchone()[0]
        null_counts[col_name] = n_nulls
        
    # check time ranges if timestamp exists
    time_range = {}
    for c in cols:
        if "timestamp" in c[1].lower() or "date" in c[1].lower():
            min_ts = cursor.execute(f"SELECT MIN({c[1]}), MAX({c[1]}) FROM {t}").fetchone()
            time_range[c[1]] = {"min": min_ts[0], "max": min_ts[1]}

    report[t] = {
        "row_count": count,
        "columns": col_info,
        "null_counts": null_counts,
        "time_range": time_range
    }

print(json.dumps(report, indent=2))

# Check employees roles / departments
print("\n--- Departments ---")
print(cursor.execute("SELECT department, COUNT(*) FROM employees GROUP BY department").fetchall())

print("\n--- Roles ---")
print(cursor.execute("SELECT role, COUNT(*) FROM employees GROUP BY role").fetchall())

print("\n--- Session labels anomaly types ---")
print(cursor.execute("SELECT anomaly_type, COUNT(*) FROM session_labels GROUP BY anomaly_type").fetchall())

print("\n--- Duplicate check ---")
print("Duplicates in employees:", cursor.execute("SELECT employee_id, COUNT(*) FROM employees GROUP BY employee_id HAVING COUNT(*) > 1").fetchall())
print("Duplicates in login_events (same emp, ts):", cursor.execute("SELECT employee_id, login_timestamp, COUNT(*) FROM login_events GROUP BY employee_id, login_timestamp HAVING COUNT(*) > 1").fetchall())
print("Duplicates in session_labels (same emp, date):", cursor.execute("SELECT employee_id, session_date, COUNT(*) FROM session_labels GROUP BY employee_id, session_date HAVING COUNT(*) > 1").fetchall())

conn.close()
