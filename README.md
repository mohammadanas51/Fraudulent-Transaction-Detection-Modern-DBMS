# Explainable Multi-Dimensional Database Anomaly Detection Using Behavioral Feature Fusion

**Academic Project Demonstration | Modern DBMS & Cyber Security Specialization**  
**Repository Source:** Adapted and extended from [moretomonika/sql-access-anomaly-detection](https://github.com/moretomonika/sql-access-anomaly-detection)

---

## 1. Executive Summary

This project implements an end-to-end, production-grade cybersecurity system that detects anomalous database and employee access activities. Rather than relying on simple static thresholds or black-box models, it fuses **five behavioral and database dimensions**:

1. **SQL Semantics:** Structural AST analysis using SQLGlot (query type, referenced tables/columns, JOINs, WHERE clauses, subqueries, wildcards, dangerous DDL).
2. **Temporal Behavior:** Working hours policies, off-hours activity, weekend operations, and inactivity gaps.
3. **Frequency & Bursts:** Daily/session event rates, distinct resources accessed, rolling 10-minute bursts.
4. **Data-Access Volume:** Result set size (rows returned) and impact (rows affected).
5. **User and Role Baseline Profiling:** Leakage-free expanding historical baselines (mean, standard deviation, volume Z-scores, unfamiliar IP pool detection, and role-based access norms).

The system pairs unsupervised **Isolation Forest** anomaly detection with a **calibrated 0–100 risk scoring engine** and an **Explainable AI (XAI) Attribution Layer** that generates plain-English narratives and recommended SOC investigation actions.

---

## 2. Dataset Strategy & Actual Audit Findings

The system supports **three data sources**:

### A. Original Repository Dataset (`access_logs.db`)
- **Immutability Guaranteed:** Read-only access prevents alteration of the original data.
- **Audit Findings:**
  - `employees` (50 records): Profile metadata (name, department, role, typical working hours).
  - `login_events` (2,905 records): 90-day weekday login events (timestamps, IP addresses).
  - `file_access_events` (12,317 records): Individual file accesses (read, write, delete) with sensitivity levels (low, medium, high).
  - `session_labels` (87 records): Ground-truth anomalies across 4 categories:
    - `volume_spike`: 29 sessions (bursts of 15–30 file accesses)
    - `off_hours`: 24 sessions (logins forced to 01:00–04:00 AM)
    - `unfamiliar_ip`: 19 sessions (logins from external/unknown IPs)
    - `sensitivity_spike`: 15 sessions (bursts of high-sensitivity file reads)

### B. Derived Behavioral Features
- Extracted using SQL Common Table Expressions (CTEs) and Python expanding windows:
  - `login_hour`, `is_off_hours`
  - `is_new_ip` (historical expanding IP pool check)
  - `days_since_last_login` (`LAG()` window function)
  - `file_access_count`, `distinct_files_count`
  - `high_sensitivity_count`, `delete_count`
  - `file_volume_zscore` (standardized baseline deviation without lookahead leakage)

### C. Synthetic SQL Audit-Log Extension (`synthetic_sql.db`)
Because the original access logs represent file/OS-level enterprise access without raw SQL statements or database row counts, an optional **Synthetic SQL Audit-Log Generator** is provided to demonstrate the full multi-dimensional SQL semantic and data-volume architecture:
- Generates 2,500+ realistic DBMS audit records across 7 roles (`DataAnalyst`, `DBA`, `AppService`, `FinanceClerk`, `Developer`, `Auditor`).
- Simulates normal queries and 5 distinct injected SQL threat scenarios:
  1. `UNUSUAL_TABLE_ACCESS` (e.g., unauthorized role querying `salaries` or `credit_cards`)
  2. `DATA_EXFILTRATION_VOLUME` (massive `SELECT *` returning 50,000–250,000 rows)
  3. `OFF_HOURS_BURST` (suspicious queries at 02:00 AM on weekends)
  4. `DANGEROUS_STATEMENT` (`DROP TABLE`, `TRUNCATE`, unrestricted `DELETE`)
  5. `SQL_INJECTION_PATTERN` (`' OR '1'='1'`, `UNION SELECT ...`)

---

## 3. Architecture & Repository Structure

```
project/
├── app/
│   ├── main.py                  # FastAPI application entrypoint & static mounting
│   ├── config.py                # Environment configuration & working hours policy
│   ├── api/
│   │   └── routes.py            # REST API endpoints (detection, alerts, triage, export)
│   ├── database/
│   │   ├── connection.py        # SQLAlchemy engine & SQLite session management
│   │   └── models.py            # Models for runs, models, alerts, and analyst notes
│   ├── ingestion/
│   │   ├── repository_loader.py # Read-only loader & schema auditor for access_logs.db
│   │   ├── normalization.py     # Standardized event schema across sources
│   │   └── synthetic_sql_generator.py # SQL audit generator with realistic threats
│   ├── processing/
│   │   ├── sessionization.py    # Time-window session grouping & inactivity timeouts
│   │   ├── behavioral_features.py # Temporal, frequency, and expanding user baselines
│   │   ├── sql_parser.py        # SQLGlot AST parser (tables, columns, joins, DDL)
│   │   └── feature_fusion.py    # Multi-dimensional feature fusion engine
│   ├── detection/
│   │   ├── preprocessing.py     # Scaler pipeline & serialization
│   │   ├── isolation_forest.py  # Unsupervised Isolation Forest wrapper
│   │   ├── scoring.py           # Calibrated 0–100 risk scoring & severity tiers
│   │   └── explanations.py      # Explainable AI (XAI) deviation attribution layer
│   ├── evaluation/
│   │   └── metrics.py           # Precision, Recall, F1, FPR, ROC-AUC, PR-AUC, CM
│   ├── services/
│   │   ├── analysis_service.py  # Pipeline orchestrator
│   │   └── alert_service.py     # Alert triage, status updates, notes, CSV export
│   ├── templates/
│   │   └── index.html           # Security Analyst SOC Dashboard HTML
│   └── static/
│       ├── css/style.css        # Responsive modern SOC dark console styles
│       └── js/app.js            # Frontend logic & Chart.js visualizations
├── tests/                       # Automated Pytest suite (24 passing tests)
├── data/                        # Local databases (access_logs.db, app_metadata.db)
├── models/                      # Serialized Isolation Forest model artifacts (.joblib)
├── scripts/                     # Helper verification and audit scripts
├── main.py                      # Root launcher: python main.py
├── requirements.txt             # Project dependencies
├── .env.example                 # Environment variables template
└── README.md                    # Documentation
```

---

## 4. Anomaly Scoring & Explainability Methodology

### 4.1 Calibrated 0–100 Anomaly Score
Scikit-learn's `IsolationForest.decision_function(X)` outputs negative values for isolated outliers and positive values for typical normal points. We transform this using a calibrated sigmoid function:

$$z = -12.0 \times s$$
$$\text{Risk Score} = \frac{100.0}{1.0 + e^{-z}}$$

| Raw Score ($s$) | Risk Score (0–100) | Severity Tier | Operational Meaning |
| :--- | :--- | :--- | :--- |
| $\ge +0.10$ | $< 25$ | **LOW** | Routine, dense behavioral pattern |
| $0.00 \text{ to } +0.10$ | $25 - 50$ | **MEDIUM** | Slight deviation, baseline border |
| $-0.08 \text{ to } 0.00$ | $50 - 75$ | **HIGH** | Significant behavioral outlier |
| $< -0.08$ | $\ge 75$ | **CRITICAL** | Severe multi-dimensional anomaly |

> **Important Note:** This score measures multi-dimensional behavioral divergence; it is not a Bayesian probability of an active cyber attack.

### 4.2 Transparent Attribution Layer
Because tree-based isolation detects geometric sparsity rather than explicit business rules, our explainability layer evaluates:
- Specific baseline deviations ($Z$-score relative to user's historical volume).
- Working hours schedule divergence (e.g., login at 03:20 AM).
- First-time IP address or unfamiliar resource interaction.
- SQL semantic dangers (unindexed dumps, DDL, injections).
- Generates an actionable analyst narrative and recommended SOC containment steps.

---

## 5. Quickstart & Demonstration Guide

### 5.1 Prerequisites & Installation
Ensure Python 3.10+ is installed:

```bash
git clone https://github.com/moretomonika/sql-access-anomaly-detection.git upstream_repo
pip install -r requirements.txt
```

### 5.2 Start the Application
Run the root launcher:
```bash
python main.py
```
Outputs:
```
======================================================================
  EXPLAINABLE MULTI-DIMENSIONAL DATABASE ANOMALY DETECTION
  Using Behavioral Feature Fusion & Isolation Forest
======================================================================
Starting server on http://localhost:8000 ...
Interactive Swagger Documentation: http://localhost:8000/docs
Security Analyst SOC Dashboard: http://localhost:8000/
======================================================================
```

### 5.3 Interactive Dashboard Walkthrough
1. **Open Console:** Navigate to `http://localhost:8000/` in your browser.
2. **Select Dataset:**
   - Choose **"Original Repository (access_logs.db)"** to analyze employee logins and file accesses.
   - Choose **"Synthetic SQL Audit Log (Extension)"** to demonstrate raw SQL AST parsing and data-volume exfiltration dimensions.
3. **Execute Detection:** Click **"Run Anomaly Detection"**. The backend fits the unsupervised Isolation Forest, computes 0–100 risk scores, generates explainable narratives, and evaluates against ground-truth labels.
4. **Inspect Metrics:** Review Precision, Recall, F1, False Positive Rate (FPR), and ROC-AUC.
5. **Investigate Alerts:** Click **"Investigate"** on any flagged event to view:
   - Event metadata & risk score
   - Explainable AI narrative
   - Contributing behavioral indicators
   - Baseline comparison ($Z$-score vs. user mean)
   - Recommended actions
   - Update triage status (`open` $\to$ `investigating` $\to$ `resolved` / `false_positive`)
   - Add analyst investigation notes.
6. **Export Data:** Click **"Export CSV"** to download the filtered triage report.

---

## 6. Automated Testing

Run the full automated test suite:
```bash
python -m pytest tests -v
```

### Test Coverage Highlights:
- `test_loader.py`: Verifies schema audit, record counts (50 employees, 2905 logins, 12317 file accesses, 87 labels), and database immutability hash checks.
- `test_sql_parser.py`: Tests SQLGlot AST parsing on SELECT, JOIN, subqueries, DDL (`DROP`, `TRUNCATE`), wildcards, and malformed queries.
- `test_processing.py`: Validates 6-CTE query execution, sessionization inactivity windows, and leakage-free user baselines.
- `test_detection.py`: Tests Isolation Forest fitting without labels, score normalization (0–100), severity tiers, model persistence, and XAI explanations.
- `test_evaluation.py`: Tests precision, recall, F1, false positive rate, confusion matrix, and ROC-AUC.
- `test_api.py`: Tests FastAPI REST endpoints (health, dataset metadata, analysis runs, triage status PATCH, notes, CSV export).
- `test_e2e_workflow.py`: End-to-end integration test verifying the full pipeline on both original and synthetic SQL datasets.
