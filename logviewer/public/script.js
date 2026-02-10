let allLogs = [];
let autoRefreshInterval = null;
let autoRefreshEnabled = false;
let healthInterval = null;

function getApiUrl(endpoint) {
  const url = new URL(`./api${endpoint}`, window.location.href);
  return url.toString();
}

function getSelectedSource() {
  const sourceSelect = document.getElementById("log-source");
  return sourceSelect ? sourceSelect.value : "both";
}

function getSelectedTable() {
  const tableSelect = document.getElementById("sql-table");
  return tableSelect ? tableSelect.value : "mcp_actions";
}

function getSelectedPrefix() {
  const prefixInput = document.getElementById("kv-prefix");
  return prefixInput ? prefixInput.value || "mcp-action:" : "mcp-action:";
}

function buildLogsUrl() {
  const params = new URLSearchParams();
  const source = getSelectedSource();
  params.set("source", source);

  if (source === "sql" || source === "both") {
    params.set("table", getSelectedTable());
  }

  if (source === "kv" || source === "both") {
    params.set("prefix", getSelectedPrefix());
  }

  const baseUrl = getApiUrl("/logs");
  return `${baseUrl}?${params.toString()}`;
}

function setSourceVisibility(source) {
  const tableSelect = document.getElementById("sql-table");
  const prefixInput = document.getElementById("kv-prefix");
  const sourceFilter = document.getElementById("filter-source");

  if (tableSelect) {
    tableSelect.classList.toggle("hidden", source === "kv");
  }

  if (prefixInput) {
    prefixInput.classList.toggle("hidden", source === "sql");
  }

  if (sourceFilter) {
    if (source === "both") {
      sourceFilter.disabled = false;
    } else {
      sourceFilter.value = source;
      sourceFilter.disabled = true;
    }
  }
}

async function fetchTables() {
  try {
    const response = await fetch(getApiUrl("/tables"));
    const data = await response.json();
    if (!response.ok || !data?.tables?.length) {
      return;
    }

    const tableSelect = document.getElementById("sql-table");
    if (!tableSelect) return;
    const currentValue = tableSelect.value;
    const tableNames = data.tables
      .map((table) => (table && typeof table === "object" ? table.name : table))
      .filter(Boolean);
    tableSelect.innerHTML = tableNames
      .map((table) => `<option value="${table}">${table}</option>`)
      .join("");

    if (currentValue && tableNames.includes(currentValue)) {
      tableSelect.value = currentValue;
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
  tbody.innerHTML = `<tr><td colspan="6" class="loading" style="color: #f44336;">${message}</td></tr>`;
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
      '<tr><td colspan="6" class="loading">No audit logs found</td></tr>';
    document.getElementById("log-count").textContent = "Showing 0 entries";
    return;
  }

  tbody.innerHTML = logsToRender
    .map((log) => {
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

      return `
        <tr>
          <td class="timestamp">${timestamp}</td>
          <td><span class="action ${baseAction}">${actionLabel}</span></td>
          <td>${targetUserId}</td>
          <td>${authenticatedUser}</td>
          <td>${requesterIp}</td>
          <td><span class="source ${source}">${source.toUpperCase()}</span></td>
        </tr>
      `;
    })
    .join("");

  document.getElementById("log-count").textContent = `Showing ${logsToRender.length} entries`;
}

function applyFilters() {
  const searchText = document.getElementById("search-box").value.toLowerCase();
  const actionFilter = document.getElementById("filter-action").value;
  const sourceFilter = document.getElementById("filter-source").value;

  const filtered = allLogs.filter((log) => {
    const matchesSearch =
      !searchText ||
      (log.requesterIp || "").toLowerCase().includes(searchText) ||
      (log.targetUserId || "").toLowerCase().includes(searchText) ||
      (log.authenticatedUser || "").toLowerCase().includes(searchText) ||
      (log.action || "").toLowerCase().includes(searchText);

    const logAction = (log.action || "").toLowerCase();
    const baseAction = logAction.split(":")[0];
    const matchesAction = !actionFilter || baseAction === actionFilter;

    const matchesSource =
      !sourceFilter || (log.source || "").toLowerCase() === sourceFilter;

    return matchesSearch && matchesAction && matchesSource;
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
document.getElementById("filter-action").addEventListener("change", applyFilters);
document.getElementById("filter-source").addEventListener("change", applyFilters);
document.getElementById("log-source").addEventListener("change", (e) => {
  setSourceVisibility(e.target.value);
  fetchLogs();
});
document.getElementById("sql-table").addEventListener("change", fetchLogs);
document.getElementById("kv-prefix").addEventListener("change", fetchLogs);
document.getElementById("auto-refresh-toggle").addEventListener("change", (e) =>
  toggleAutoRefresh(e.target.checked)
);

setSourceVisibility(getSelectedSource());
fetchTables();
fetchLogs();
startHealthPolling();
