# Dataset Audit & Implementation Plan

**Project Title:** Explainable Multi-Dimensional Database Anomaly Detection Using Behavioral Feature Fusion  
**Repository Inspected:** `https://github.com/moretomonika/sql-access-anomaly-detection`  
**Inspected Date:** October 20, 2026  

---

## 1. Dataset Audit Report: `access_logs.db`

The primary dataset in the upstream repository is an SQLite database located at `access_logs.db`.

### 1.1 Tables and Schemas

| Table Name | Records | Columns (Type) | Missing Values | Time Range | Primary Keys |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`employees`** | 50 | `employee_id` (INT), `name` (TEXT), `department` (TEXT), `role` (TEXT), `typical_start_hour` (INT), `typical_end_hour` (INT) | 0 | N/A | `employee_id` |
| **`login_events`** | 2,905 | `login_id` (INT), `employee_id` (INT), `login_timestamp` (TEXT ISO-8601), `ip_address` (TEXT), `success` (INT) | 0 | `2026-01-01T06:12:00` to `2026-03-31T11:09:00` (90 days, weekdays) | `login_id` |
| **`file_access_events`** | 12,317 | `access_id` (INT), `employee_id` (INT), `file_id` (INT), `access_timestamp` (TEXT ISO-8601), `action` (TEXT: read/write/delete), `sensitivity_level` (TEXT: low/medium/high) | 0 | `2026-01-01T07:36:00` to `2026-03-31T16:20:00` | `access_id` |
| **`session_labels`** | 87 | `label_id` (INT), `employee_id` (INT), `session_date` (TEXT YYYY-MM-DD), `is_anomaly` (INT: 1), `anomaly_type` (TEXT) | 0 | `2026-01-05` to `2026-03-31` | `label_id` |

### 1.2 Anomaly Types in Ground-Truth Labels (`session_labels`)
There are 87 injected anomalous sessions (~3.0% of total 2,905 login events):
- `volume_spike`: 29 sessions (bursts of 15–30 file accesses right after login)
- `off_hours`: 24 sessions (logins forced to 01:00–04:00 AM)
- `unfamiliar_ip`: 19 sessions (logins using external IP outside typical employee pool)
- `sensitivity_spike`: 15 sessions (bursts of 5–10 high-sensitivity file reads)

### 1.3 Field Presence Matrix (Requirement Verification)

| Field Name | Status in Original `access_logs.db` | Notes / Implementation Strategy |
| :--- | :--- | :--- |
| **Event ID** | **EXISTS** | `login_id` in `login_events`, `access_id` in `file_access_events`. |
| **Timestamp** | **EXISTS** | ISO-8601 strings (`login_timestamp`, `access_timestamp`). |
| **User / Employee ID** | **EXISTS** | `employee_id` across all tables (50 distinct employees). |
| **User Role** | **EXISTS** | `role` (5 distinct: Analyst, Associate, Director, Manager, Senior Associate) and `department` (6 distinct) in `employees`. |
| **Accessed Resource / File** | **EXISTS** | `file_id` (integer IDs 1–500) with actions and sensitivity levels. |
| **SQL Query Text** | **DOES NOT EXIST** | Original dataset tracks enterprise login & file access, not raw DBMS query text. Supported via the separate Synthetic SQL Audit-Log Extension. |
| **Query Type** | **DOES NOT EXIST** | In original data, action is file action (`read`, `write`, `delete`). SQL query verbs (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`) supported via Synthetic SQL Extension. |
| **Database Table** | **DOES NOT EXIST** | In original data, file entities are tracked. Real DBMS tables (`customers`, `transactions`, `audit_logs`, etc.) provided in Synthetic SQL Extension. |
| **Database Columns** | **DOES NOT EXIST** | Extracted via SQLGlot parser in the Synthetic SQL Extension. |
| **Session ID** | **DOES NOT EXIST EXPLICITLY** | Linked implicitly by employee + date/login window. In this project, an explicit sessionizer will bind file accesses to logins and compute session intervals. |
| **Transaction ID** | **DOES NOT EXIST** | Provided in Synthetic SQL Extension. |
| **Rows Returned** | **DOES NOT EXIST** | Provided in Synthetic SQL Extension; explicitly marked unavailable for original dataset. |
| **Rows Affected** | **DOES NOT EXIST** | Provided in Synthetic SQL Extension; explicitly marked unavailable for original dataset. |
| **Ground-Truth Anomaly Label** | **EXISTS** | `session_labels` table contains 87 verified ground-truth labels for evaluation. |

---

## 2. Notebook Analysis & Reuse Strategy

The upstream notebook (`Anomaly Detection.ipynb`) demonstrates:
1. Generation of synthetic employees, logins, and file accesses, with 4 injected anomaly categories.
2. A single SQL query with 6 Common Table Expressions (CTEs) extracting:
   - `login_hour`, `is_off_hours` (relative to employee's typical schedule)
   - `is_new_ip` (correlated subquery on employee IP history)
   - `days_since_last_login` (`LAG()` window function)
   - `file_access_count`, `distinct_files_count`, `high_sensitivity_count`, `delete_count`
3. Training an `IsolationForest` (`n_estimators=200, contamination=0.03, random_state=42`) with `StandardScaler`.
4. Comparing against a supervised `LogisticRegression(class_weight='balanced')`.

### Improvements & Refactoring for This Project
1. **Preserve Database Immutability:** Never modify `access_logs.db`. The application reads from it safely, and stores all application state, model artifacts, and alerts in a separate `data/app_metadata.db`.
2. **True Behavioral Baseline Fusion:** Compute per-user running baselines (mean file accesses, usual hour range, typical sensitivity distribution) rather than only global counts.
3. **Sessionization Engine:** Explicitly sessionize events with configurable inactivity timeouts (e.g., 30-minute windows) and linking file access events to login sessions.
4. **Normalized 0–100 Anomaly Scoring:** Convert scikit-learn's `decision_function` raw values to a human-interpretable 0–100 risk score with calibrated risk tiers (Low, Medium, High, Critical).
5. **Explainability Engine:** Provide rule-assisted behavioral deviation breakdowns and SHAP/surrogate attribution explaining *why* an event was flagged.
6. **Synthetic SQL Extension with SQLGlot:** Implement full SQL AST parsing (query type, tables, columns, JOINs, WHERE clauses, subqueries, wildcard projection) and data-volume metrics for database audit logs.
7. **Production Architecture:** FastAPI REST API, SQLite SQLAlchemy persistence, automated tests, and a modern Security Analyst Dashboard with CSV export and triage capabilities.
