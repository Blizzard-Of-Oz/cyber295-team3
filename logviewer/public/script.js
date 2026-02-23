let allLogs = [];
let autoRefreshInterval = null;
let autoRefreshEnabled = false;
let healthInterval = null;
let sqlTables = [];
let kvPrefixes = ["mcp-action:", "mcp-policy:", "mcp-alert:"];

function getApiUrl(endpoint) {
  const url = new URL(`./api${endpoint}`, window.location.href);
  return url.toString();
}

function getSelectedSource() {
  const sourceSelect = document.getElementById("storage-source");
  return sourceSelect ? sourceSelect.value : "sql";
}

function getSelectedTarget() {
  const targetSelect = document.getElementById("storage-target");
  return targetSelect ? targetSelect.value : "mcp_actions";
}

function buildLogsUrl() {
  const source = getSelectedSource();
  const target = getSelectedTarget();
  const params = new URLSearchParams();
  
  if (source === "sql") {
    params.set("source", "sql");
    params.set("table", target);
  } else {
    params.set("source", "kv");
    params.set("prefix", target);
  }

  const baseUrl = getApiUrl("/logs");
  return `${baseUrl}?${params.toString()}`;
}

function updateStorageTargets() {
  const source = getSelectedSource();
  const targetSelect = document.getElementById("storage-target");
  if (!targetSelect) return;

  if (source === "sql") {
    targetSelect.innerHTML = sqlTables
      .map((table) => `<option value="${table}">${table}</option>`)
      .join("");
  } else {
    targetSelect.innerHTML = kvPrefixes
      .map((prefix) => `<option value="${prefix}">${prefix}</option>`)
      .join("");
  }

  fetchLogs();
}

async function fetchTables() {
  try {
    const response = await fetch(getApiUrl("/tables"));
    const data = await response.json();
    if (!response.ok || !data?.tables?.length) {
      return;
    }

    sqlTables = data.tables
      .map((table) => (table && typeof table === "object" ? table.name : table))
      .filter(Boolean);
    
    // Update the dropdown if we're in SQL mode
    if (getSelectedSource() === "sql") {
      updateStorageTargets();
    }
  } catch (error) {
    console.error("Failed to fetch tables:", error.message);
  }

}

async function fetchLogs() {
  try {
    updateStatus("Loading...", "loading");
    updateDbStatus("immuDB: checking...", "loading");
    const response = await fetch(buildLogsUrl());
    const data = await response.json();

    if (response.ok) {
      allLogs = data.logs || [];
      updateStatus("Connected", "connected");
      updateDbStatus("immuDB: connected", "connected");
      setUiEnabled(true);
      setLastUpdated(new Date());
      renderLogs(allLogs);
    } else {
      if (data?.error?.toLowerCase().includes("immudb not connected")) {
        updateStatus("Waiting for immuDB...", "reconnecting");
        updateDbStatus("immuDB: disconnected", "disconnected");
        setUiEnabled(false);
      } else {
        updateStatus("Error: " + data.error, "disconnected");
      }

      showError("Failed to fetch logs: " + data.error);
    }
  } catch (error) {
    updateStatus("Server unreachable", "disconnected");
    updateDbStatus("immuDB: unknown", "disconnected");
    showError("Connection error: " + error.message);
  }
}

function updateStatus(text, status) {
  const statusText = document.getElementById("status-text");
  const statusIndicator = document.getElementById("status-indicator");

  statusText.textContent = text;
  statusIndicator.classList.remove("connected", "disconnected", "loading", "reconnecting");
  statusIndicator.classList.add(status);
}

function updateDbStatus(text, status) {
  const dbStatus = document.getElementById("db-status");
  if (!dbStatus) return;
  dbStatus.textContent = text;
  dbStatus.classList.remove("connected", "disconnected", "loading", "reconnecting");
  dbStatus.classList.add(status);
}

function setUiEnabled(enabled) {
  const controls = document.querySelector(".controls");
  const tableWrapper = document.querySelector(".table-wrapper");
  const statusBar = document.querySelector(".status-bar");
  const banner = document.getElementById("db-banner");

  [controls, tableWrapper, statusBar].forEach((el) => {
    if (!el) return;
    el.classList.toggle("disabled", !enabled);
  });

  if (banner) {
    banner.classList.toggle("hidden", enabled);
  }
}

function setLastUpdated(date) {
  const lastUpdated = document.getElementById("last-updated");
  if (!lastUpdated) return;
  lastUpdated.textContent = `Last update: ${date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  })}`;
}

async function fetchHealth() {
  try {
    const response = await fetch(getApiUrl("/health"));
    const data = await response.json();

    if (response.ok) {
      const isConnected = data?.immudb === "connected";
      updateDbStatus(
        `immuDB: ${isConnected ? "connected" : "disconnected"}`,
        isConnected ? "connected" : "disconnected"
      );
      if (!isConnected) {
        updateStatus("Waiting for immuDB...", "reconnecting");
        setUiEnabled(false);
      } else {
        setUiEnabled(true);
      }
      return;
    }
  } catch (error) {
    updateDbStatus("immuDB: unknown", "disconnected");
    setUiEnabled(false);
  }
}

function showError(message) {
  const tbody = document.getElementById("logs-tbody");
  tbody.innerHTML = `<tr><td colspan="7" class="loading" style="color: #f44336;">${message}</td></tr>`;
}

function formatTimestamp(timestamp) {
  if (!timestamp) return "N/A";
  const date = new Date(timestamp);
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function renderLogs(logsToRender) {
  const tbody = document.getElementById("logs-tbody");

  if (logsToRender.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="loading">No audit logs found</td></tr>';
    document.getElementById("log-count").textContent = "Showing 0 entries";
    return;
  }

  tbody.innerHTML = logsToRender
    .map((log, idx) => {
      const rawAction = log.action || "unknown";
      const [baseAction, actionDetail] = rawAction.split(":");
      const actionLabel = actionDetail
        ? `${baseAction.toUpperCase()} (${actionDetail})`
        : baseAction.toUpperCase();
      const timestamp = formatTimestamp(log.timestamp || log.ts);
      const authenticatedUser = log.authenticatedUser || "unknown";
      const requesterIp = log.requesterIp || "unknown";
      const targetUserId = log.targetUserId || "unknown";
      const source = log.source || "unknown";
      const hasDetails =
        log.opaRequest ||
        log.opaResponse ||
        log.reason ||
        log.status ||
        log.durationMs !== null && log.durationMs !== undefined ||
        log.resultSummary ||
        log.errorCode ||
        log.errorMessage ||
        log.correlationId;
      const statusLabel = log.status ? ` (${log.status})` : "";

      const detailsBtn = hasDetails
        ? `<button class="details-btn" data-log-idx="${idx}">View</button>`
        : "-";

      return `
        <tr>
          <td class="timestamp">${timestamp}</td>
          <td><span class="action ${baseAction}">${actionLabel}${statusLabel}</span></td>
          <td>${targetUserId}</td>
          <td>${authenticatedUser}</td>
          <td>${requesterIp}</td>
          <td><span class="source ${source}">${source.toUpperCase()}</span></td>
          <td>${detailsBtn}</td>
        </tr>
      `;
    })
    .join("");

  document.getElementById("log-count").textContent = `Showing ${logsToRender.length} entries`;

  // Attach event listeners
  document.querySelectorAll(".details-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const idx = parseInt(e.target.dataset.logIdx, 10);
      showDetailsModal(logsToRender[idx]);
    });
  });
}

function showDetailsModal(log) {
  const modal = document.getElementById("details-modal");
  const detailsBody = document.getElementById("details-body");

  let html = "<div class='details-grid'>";

  if (log.reason) {
    html += `<div class="detail-row"><strong>Reason:</strong> <span>${escapeHtml(log.reason)}</span></div>`;
  }

  if (log.requestId) {
    html += `<div class="detail-row"><strong>Request ID:</strong> <span>${escapeHtml(log.requestId)}</span></div>`;
  }

  if (log.policyVersion) {
    html += `<div class="detail-row"><strong>Policy Version:</strong> <span>${escapeHtml(log.policyVersion)}</span></div>`;
  }

  if (log.risk) {
    html += `<div class="detail-row"><strong>Risk:</strong> <span>${escapeHtml(log.risk)}</span></div>`;
  }

  if (log.status) {
    html += `<div class="detail-row"><strong>Status:</strong> <span>${escapeHtml(log.status)}</span></div>`;
  }

  if (log.durationMs !== null && log.durationMs !== undefined) {
    html += `<div class="detail-row"><strong>Duration (ms):</strong> <span>${escapeHtml(String(log.durationMs))}</span></div>`;
  }

  if (log.resultSummary) {
    html += `<div class="detail-row"><strong>Result:</strong> <span>${escapeHtml(log.resultSummary)}</span></div>`;
  }

  if (log.errorCode) {
    html += `<div class="detail-row"><strong>Error Code:</strong> <span>${escapeHtml(log.errorCode)}</span></div>`;
  }

  if (log.errorMessage) {
    html += `<div class="detail-row"><strong>Error Message:</strong> <span>${escapeHtml(log.errorMessage)}</span></div>`;
  }

  if (log.correlationId) {
    html += `<div class="detail-row"><strong>Correlation ID:</strong> <span>${escapeHtml(log.correlationId)}</span></div>`;
  }

  if (log.opaRequest) {
    try {
      const opaReq = typeof log.opaRequest === "string" ? JSON.parse(log.opaRequest) : log.opaRequest;
      html += `<div class="detail-row"><strong>OPA Request:</strong></div>`;
      html += `<pre>${escapeHtml(JSON.stringify(opaReq, null, 2))}</pre>`;
    } catch (e) {
      html += `<div class="detail-row"><strong>OPA Request:</strong> <span>${escapeHtml(log.opaRequest)}</span></div>`;
    }
  }

  if (log.opaResponse) {
    try {
      const opaResp = typeof log.opaResponse === "string" ? JSON.parse(log.opaResponse) : log.opaResponse;
      html += `<div class="detail-row"><strong>OPA Response:</strong></div>`;
      html += `<pre>${escapeHtml(JSON.stringify(opaResp, null, 2))}</pre>`;
    } catch (e) {
      html += `<div class="detail-row"><strong>OPA Response:</strong> <span>${escapeHtml(log.opaResponse)}</span></div>`;
    }
  }

  html += "</div>";
  detailsBody.innerHTML = html;
  modal.classList.remove("hidden");
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function applyFilters() {
  const searchText = document.getElementById("search-box").value.toLowerCase();

  const filtered = allLogs.filter((log) => {
    const matchesSearch =
      !searchText ||
      (log.requesterIp || "").toLowerCase().includes(searchText) ||
      (log.targetUserId || "").toLowerCase().includes(searchText) ||
      (log.authenticatedUser || "").toLowerCase().includes(searchText) ||
      (log.action || "").toLowerCase().includes(searchText);

    return matchesSearch;
  });

  renderLogs(filtered);
}

function toggleAutoRefresh(enabled) {
  autoRefreshEnabled = enabled;
  const toggle = document.getElementById("auto-refresh-toggle");
  const label = document.querySelector(".auto-refresh-toggle span");

  if (autoRefreshEnabled) {
    autoRefreshInterval = setInterval(fetchLogs, 5000);
    label.textContent = "Auto-refresh (on)";
    toggle.checked = true;
  } else {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }

    label.textContent = "Auto-refresh (off)";
    toggle.checked = false;
  }
}

function startHealthPolling() {
  if (healthInterval) {
    clearInterval(healthInterval);
  }
  fetchHealth();
  healthInterval = setInterval(fetchHealth, 5000);
}

document.getElementById("refresh-btn").addEventListener("click", fetchLogs);
document.getElementById("search-box").addEventListener("input", applyFilters);
document.getElementById("storage-source").addEventListener("change", updateStorageTargets);
document.getElementById("storage-target").addEventListener("change", fetchLogs);
document.getElementById("auto-refresh-toggle").addEventListener("change", (e) =>
  toggleAutoRefresh(e.target.checked)
);

// Modal close handler
document.getElementById("details-modal").addEventListener("click", (e) => {
  if (e.target.id === "details-modal" || e.target.classList.contains("modal-close")) {
    document.getElementById("details-modal").classList.add("hidden");
  }
});

fetchTables();
fetchLogs();
startHealthPolling();
