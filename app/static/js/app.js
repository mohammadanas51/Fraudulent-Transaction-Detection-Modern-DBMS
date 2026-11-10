let currentDataset = "original";
let scoreDistChartInstance = null;
let severityChartInstance = null;
let offHoursChartInstance = null;
let currentAlertId = null;

document.addEventListener("DOMContentLoaded", () => {
  onDatasetChange();
});

function onDatasetChange() {
  currentDataset = document.getElementById("datasetSelect").value;
  updateDimensionTags();
  loadDashboardData();
}

function updateDimensionTags() {
  const isOriginal = currentDataset === "original";
  document.getElementById("dimSQL").classList.toggle("active", !isOriginal);
  document.getElementById("dimVolume").classList.toggle("active", !isOriginal);
  document.getElementById("sourceBadge").innerText = isOriginal
    ? "Source: original (access_logs.db)"
    : "Source: synthetic_sql (sql_audit_logs)";
}

async function loadDashboardData() {
  await Promise.all([
    fetchOverviewStats(),
    fetchEvaluationMetrics(),
    fetchAlerts()
  ]);
}

async function fetchOverviewStats() {
  try {
    const res = await fetch(`/api/stats/overview?source=${currentDataset}`);
    const data = await res.json();

    document.getElementById("statAlerts").innerText = data.total_alerts || 0;
    document.getElementById("statCritical").innerText = (data.critical_alerts + data.high_alerts) || 0;
    
    // Total users / profiles count based on dataset
    document.getElementById("statUsers").innerText = currentDataset === "original" ? "50" : "7";

    renderSeverityChart(data.severity_distribution || {});
    renderScoreDistChart(data.score_distribution || {});
  } catch (err) {
    console.error("Failed to load overview stats:", err);
  }
}

async function fetchEvaluationMetrics() {
  try {
    const res = await fetch("/api/evaluation/metrics");
    const data = await res.json();
    const metricsObj = currentDataset === "original" 
      ? data.original_dataset?.metrics 
      : data.synthetic_sql_dataset?.metrics;

    const container = document.getElementById("evalMetricsContent");
    if (!metricsObj || !metricsObj.has_ground_truth) {
      container.innerHTML = `<p class="text-muted">No evaluation metrics available yet. Execute analysis to train and evaluate.</p>`;
      document.getElementById("statRocAuc").innerText = "--";
      document.getElementById("statAnalyzed").innerText = "--";
      return;
    }

    document.getElementById("statAnalyzed").innerText = metricsObj.total_samples || "--";
    document.getElementById("statRocAuc").innerText = metricsObj.roc_auc ? metricsObj.roc_auc.toFixed(3) : "--";

    const cm = metricsObj.confusion_matrix || {};
    container.innerHTML = `
      <div class="eval-metric-row"><span>Evaluated Records:</span><span class="eval-val">${metricsObj.total_samples}</span></div>
      <div class="eval-metric-row"><span>Precision:</span><span class="eval-val">${(metricsObj.precision * 100).toFixed(1)}%</span></div>
      <div class="eval-metric-row"><span>Recall (Detection Rate):</span><span class="eval-val">${(metricsObj.recall * 100).toFixed(1)}%</span></div>
      <div class="eval-metric-row"><span>F1-Score:</span><span class="eval-val">${metricsObj.f1_score.toFixed(3)}</span></div>
      <div class="eval-metric-row"><span>False Positive Rate (FPR):</span><span class="eval-val">${(metricsObj.false_positive_rate * 100).toFixed(2)}%</span></div>
      <div class="eval-metric-row"><span>ROC-AUC Score:</span><span class="eval-val">${metricsObj.roc_auc ? metricsObj.roc_auc.toFixed(3) : 'N/A'}</span></div>
      <div class="eval-metric-row"><span>Confusion Matrix:</span><span class="eval-val">TP:${cm.true_positive || 0} | FP:${cm.false_positive || 0} | FN:${cm.false_negative || 0} | TN:${cm.true_negative || 0}</span></div>
    `;

    renderOffHoursComparison(metricsObj);
  } catch (err) {
    console.error("Failed to load evaluation metrics:", err);
  }
}

async function fetchAlerts() {
  try {
    const user = document.getElementById("filterUser").value.trim();
    const resource = document.getElementById("filterResource").value.trim();
    const severity = document.getElementById("filterSeverity").value;
    const status = document.getElementById("filterStatus").value;

    let url = `/api/alerts?source=${currentDataset}&limit=100`;
    if (user) url += `&user_identifier=${encodeURIComponent(user)}`;
    if (resource) url += `&resource=${encodeURIComponent(resource)}`;
    if (severity && severity !== "all") url += `&severity=${severity}`;
    if (status && status !== "all") url += `&status=${status}`;

    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById("alertTableBody");

    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted">No alerts matching filter criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.alerts.map(a => {
      const sevClass = `badge-${a.severity.toLowerCase()}`;
      return `
        <tr>
          <td>${a.timestamp}</td>
          <td><strong>${a.user_identifier}</strong> <span class="subtitle">(${a.user_role || 'User'})</span></td>
          <td>${a.resource_accessed || 'N/A'}</td>
          <td><code>${a.query_type || 'FILE'}</code></td>
          <td><span class="score-badge">${a.anomaly_score}</span></td>
          <td><span class="badge ${sevClass}">${a.severity}</span></td>
          <td style="max-width: 320px;" title="${escapeHtml(a.explanation)}">
            ${escapeHtml(a.explanation.length > 90 ? a.explanation.substring(0, 90) + '...' : a.explanation)}
          </td>
          <td><span class="badge badge-outline">${a.status}</span></td>
          <td>
            <button class="btn btn-outline" style="padding: 0.25rem 0.6rem; font-size: 0.8rem;" onclick="openAlertModal(${a.id})">🔍 Investigate</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to fetch alerts:", err);
  }
}

async function runAnalysis() {
  const btn = event?.target;
  if (btn) {
    btn.disabled = true;
    btn.innerText = "⏳ Running Anomaly Analysis...";
  }

  try {
    const res = await fetch("/api/analysis/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dataset_source: currentDataset,
        alert_threshold: 60.0,
        contamination: 0.03,
        n_estimators: 200
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Analysis run failed");
    }

    const data = await res.json();
    alert(`Detection Run Complete!\nAnalyzed: ${data.records_analyzed} records\nFlagged Anomalies: ${data.anomalies_detected}\nExecution: ${data.execution_time_seconds}s`);
    await loadDashboardData();
  } catch (err) {
    alert(`Error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = "⚡ Run Anomaly Detection";
    }
  }
}

async function openAlertModal(alertId) {
  try {
    currentAlertId = alertId;
    const res = await fetch(`/api/alerts/${alertId}`);
    if (!res.ok) throw new Error("Could not fetch alert detail");
    const data = await res.json();

    document.getElementById("modalEventId").innerText = `Alert ${data.event_id}`;
    const sevBadge = document.getElementById("modalSeverity");
    sevBadge.innerText = data.severity;
    sevBadge.className = `badge badge-${data.severity.toLowerCase()}`;

    document.getElementById("modalTimestamp").innerText = data.timestamp;
    document.getElementById("modalUser").innerText = data.user_identifier;
    document.getElementById("modalRole").innerText = `${data.user_role || 'User'} (${data.department || 'General'})`;
    document.getElementById("modalResource").innerText = data.resource_accessed || 'N/A';
    document.getElementById("modalQuery").innerText = data.query_type || 'N/A';
    document.getElementById("modalScore").innerText = `${data.anomaly_score} / 100`;
    document.getElementById("modalGroundTruth").innerText = data.ground_truth_type 
      ? `Anomaly (${data.ground_truth_type})` 
      : (data.ground_truth_label === 0 ? "Normal" : "Unknown");
    document.getElementById("modalSource").innerText = data.dataset_source;

    // Narrative
    document.getElementById("modalExplanation").innerText = data.explanation;

    // Contributing Factors
    const factorsList = document.getElementById("modalFactorsList");
    factorsList.innerHTML = (data.contributing_factors || []).map(f => `<li>⚡ ${escapeHtml(f)}</li>`).join("") 
      || `<li>No single dominant factor. Triggered by multi-dimensional joint feature sparsity.</li>`;

    // Baseline comparisons
    const bContent = document.getElementById("modalBaselineContent");
    const b = data.baseline_comparison || {};
    let bHtml = "";
    if (b.observed_events_count !== undefined) {
      bHtml += `<div>Observed Event Count: <strong>${b.observed_events_count}</strong> | User Historical Baseline Average: <strong>${b.user_historical_mean}</strong> | Volume Z-Score: <strong>${b.volume_zscore}σ</strong></div>`;
    }
    if (b.rows_returned !== undefined) {
      bHtml += `<div>Database Query Volume: <strong>${Number(b.rows_returned).toLocaleString()}</strong> rows returned</div>`;
    }
    bContent.innerHTML = bHtml || `<div>No historical baseline deviations recorded for this profile.</div>`;

    // Recommendations
    document.getElementById("modalActionText").innerText = data.recommended_action || "Verify user activity logs with system administrator.";

    // Triage status
    document.getElementById("modalStatusSelect").value = data.status || "open";

    // Notes
    renderNotesList(data.notes || []);

    document.getElementById("alertModal").style.display = "flex";
  } catch (err) {
    alert(`Failed to load alert: ${err.message}`);
  }
}

function renderNotesList(notes) {
  const container = document.getElementById("modalNotesList");
  if (!notes || notes.length === 0) {
    container.innerHTML = `<p class="text-muted" style="font-size: 0.8rem;">No analyst notes recorded yet.</p>`;
    return;
  }
  container.innerHTML = notes.map(n => `
    <div class="note-item">
      <div class="note-meta">${escapeHtml(n.author)} • ${n.created_at.replace("T", " ").substring(0, 19)}</div>
      <div>${escapeHtml(n.note_text)}</div>
    </div>
  `).join("");
}

async function saveStatusChange() {
  if (!currentAlertId) return;
  const newStatus = document.getElementById("modalStatusSelect").value;
  try {
    const res = await fetch(`/api/alerts/${currentAlertId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus })
    });
    if (!res.ok) throw new Error("Status update failed");
    alert(`Status updated to: ${newStatus}`);
    await fetchAlerts();
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

async function submitNote() {
  if (!currentAlertId) return;
  const textarea = document.getElementById("modalNewNote");
  const text = textarea.value.trim();
  if (!text) {
    alert("Please enter a note.");
    return;
  }

  try {
    const res = await fetch(`/api/alerts/${currentAlertId}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note_text: text, author: "Security Analyst" })
    });
    if (!res.ok) throw new Error("Could not save note");
    textarea.value = "";
    // Refresh modal
    await openAlertModal(currentAlertId);
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

function closeModal() {
  document.getElementById("alertModal").style.display = "none";
  currentAlertId = null;
}

function exportCSV() {
  window.location.href = `/api/alerts/export/csv?source=${currentDataset}`;
}

// Chart Rendering
function renderScoreDistChart(buckets) {
  const ctx = document.getElementById("scoreDistChart").getContext("2d");
  if (scoreDistChartInstance) scoreDistChartInstance.destroy();

  const labels = Object.keys(buckets);
  const values = Object.values(buckets);

  scoreDistChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Events Count",
        data: values,
        backgroundColor: [
          "#10b981", "#3b82f6", "#f59e0b", "#f97316", "#ef4444"
        ]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "#1f2937" }, ticks: { color: "#9ca3af" } },
        y: { grid: { color: "#1f2937" }, ticks: { color: "#9ca3af" } }
      }
    }
  });
}

function renderSeverityChart(severities) {
  const ctx = document.getElementById("severityChart").getContext("2d");
  if (severityChartInstance) severityChartInstance.destroy();

  severityChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [
          severities.CRITICAL || 0,
          severities.HIGH || 0,
          severities.MEDIUM || 0,
          severities.LOW || 0
        ],
        backgroundColor: ["#ef4444", "#f97316", "#f59e0b", "#10b981"]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#9ca3af" } }
      }
    }
  });
}

function renderOffHoursComparison(metrics) {
  const ctx = document.getElementById("offHoursChart").getContext("2d");
  if (offHoursChartInstance) offHoursChartInstance.destroy();

  const dist = metrics.score_distribution || {};
  const normalMean = dist.normal_mean || 28.0;
  const anomMean = dist.anomaly_mean || 78.5;

  offHoursChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Ground-Truth Normal Sessions", "Ground-Truth Anomalous Sessions"],
      datasets: [{
        label: "Mean Risk Score (0-100)",
        data: [normalMean, anomMean],
        backgroundColor: ["#3b82f6", "#ef4444"]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { min: 0, max: 100, grid: { color: "#1f2937" }, ticks: { color: "#9ca3af" } },
        x: { grid: { color: "#1f2937" }, ticks: { color: "#9ca3af" } }
      }
    }
  });
}

function escapeHtml(text) {
  if (!text) return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
