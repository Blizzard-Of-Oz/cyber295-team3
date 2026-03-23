const runButton = document.getElementById("run");
const stopButton = document.getElementById("stop");
const requirementInput = document.getElementById("requirement");
const statusEl = document.getElementById("status");
const summaryEl = document.getElementById("summary");
const toolCallsEl = document.getElementById("toolCalls");
const toolOutputsEl = document.getElementById("toolOutputs");
const attachmentsInput = document.getElementById("attachments");
const attachmentListEl = document.getElementById("attachmentList");
const authPrompt = document.getElementById("authPrompt");
const signinBtn = document.getElementById("signinBtn");
const signoutBtn = document.getElementById("signoutBtn");
const userInfo = document.getElementById("userInfo");
const userName = document.getElementById("userName");
const userEmail = document.getElementById("userEmail");
const csrfBanner = document.getElementById("csrfBanner");
const csrfMessage = document.getElementById("csrfMessage");
const csrfRetry = document.getElementById("csrfRetry");

let isAuthenticated = false;
let csrfToken = "";
let cachedUser = null;
let selectedAttachments = [];
let activeAbortController = null;
let isRunning = false;
let activeRequestId = "";

function createRequestId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  return `req-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function syncActionButtons() {
  if (isRunning) {
    runButton.disabled = true;
    stopButton.disabled = false;
    return;
  }

  stopButton.disabled = true;
  runButton.disabled = !isAuthenticated;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderAttachmentList() {
  if (!selectedAttachments.length) {
    attachmentListEl.textContent = "No files selected";
    return;
  }

  const rows = selectedAttachments.map((entry, index) => {
    const escapedName = escapeHtml(entry.displayName);
    const escapedSize = escapeHtml(String(entry.displaySizeBytes));
    return `
      <div class="attachment-row" data-index="${index}">
        <div class="attachment-row-title">Attachment ${index + 1}</div>
        <label>filename</label>
        <input type="text" class="attachment-name" data-index="${index}" value="${escapedName}" />
        <label>size (bytes)</label>
        <input type="number" min="0" step="1" class="attachment-size" data-index="${index}" value="${escapedSize}" />
      </div>
    `;
  });
  attachmentListEl.innerHTML = rows.join("");
}

function setAttachmentsFromFiles(files) {
  selectedAttachments = Array.from(files || []).map((file) => ({
    file,
    displayName: file.name,
    displaySizeBytes: file.size,
    mimeType: file.type || "application/octet-stream"
  }));
  renderAttachmentList();
}

function clearAttachments() {
  selectedAttachments = [];
  if (attachmentsInput) {
    attachmentsInput.value = "";
  }
  renderAttachmentList();
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      const commaIndex = result.indexOf(",");
      resolve(commaIndex >= 0 ? result.slice(commaIndex + 1) : result);
    };
    reader.onerror = () => reject(reader.error || new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}

async function buildAttachmentPayload() {
  if (!selectedAttachments.length) return [];
  const payload = [];
  for (const entry of selectedAttachments) {
    const contentBase64 = await fileToBase64(entry.file);
    const parsedDisplaySize = Number(entry.displaySizeBytes);
    payload.push({
      name: entry.file.name,
      size: entry.file.size,
      mimeType: entry.mimeType,
      displayName: entry.displayName || entry.file.name,
      displaySizeBytes: Number.isFinite(parsedDisplaySize) && parsedDisplaySize >= 0
        ? parsedDisplaySize
        : entry.file.size,
      contentBase64
    });
  }
  return payload;
}

function showAuthPrompt() {
  isAuthenticated = false;
  csrfToken = "";
  csrfBanner.style.display = "none";
  authPrompt.style.display = "block";
  userInfo.style.display = "none";
  syncActionButtons();
  statusEl.textContent = "Sign in required";
}

function showApp(user) {
  isAuthenticated = true;
  authPrompt.style.display = "none";
  syncActionButtons();
  if (user) {
    userName.textContent = user.name || user.username || "Signed in";
    const emailValue =
      user.email || user.mail || user.preferred_username || user.username || "";
    userEmail.textContent = emailValue;
    userEmail.style.display = emailValue ? "block" : "none";
    userInfo.style.display = "flex";
  }
}

function showCsrfBanner(message) {
  csrfMessage.textContent = message || "Security token unavailable.";
  csrfBanner.style.display = "flex";
}

function hideCsrfBanner() {
  csrfBanner.style.display = "none";
}

async function loadCsrfToken() {
  try {
    const response = await fetch("/api/csrf");
    if (!response.ok) {
      csrfToken = "";
      if (isAuthenticated) {
        showCsrfBanner("Security token unavailable. Please retry.");
      }
      return;
    }
    const data = await response.json();
    csrfToken = data.token || "";
    if (csrfToken) {
      hideCsrfBanner();
    } else if (isAuthenticated) {
      showCsrfBanner("Security token unavailable. Please retry.");
    }
  } catch {
    csrfToken = "";
    if (isAuthenticated) {
      showCsrfBanner("Security token unavailable. Please retry.");
    }
  }
}

async function checkAuthentication() {
  try {
    const response = await fetch("/api/user", { cache: "no-store" });
    if (response.status === 304) {
      if (cachedUser) {
        showApp(cachedUser);
        await loadCsrfToken();
        return;
      }
      showAuthPrompt();
      return;
    }
    if (!response.ok) {
      showAuthPrompt();
      return;
    }
    const data = await response.json();
    cachedUser = data.user || null;
    showApp(cachedUser);
    await loadCsrfToken();
  } catch (error) {
    showAuthPrompt();
  }
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) {
      showAuthPrompt();
      return;
    }
    const data = await response.json();
    if (data.authenticated) {
      await checkAuthentication();
    } else {
      showAuthPrompt();
    }
  } catch (error) {
    showAuthPrompt();
  }
}

async function runAgent() {
  if (isRunning) {
    statusEl.textContent = "Agent is already running.";
    return;
  }

  const requirement = requirementInput.value.trim();
  if (!requirement) {
    statusEl.textContent = "Please enter a requirement.";
    return;
  }

  if (!isAuthenticated) {
    showAuthPrompt();
    return;
  }

  if (!csrfToken) {
    await loadCsrfToken();
  }
  if (!csrfToken) {
    showCsrfBanner("Security token unavailable. Please retry.");
    statusEl.textContent = "Unable to load CSRF token.";
    return;
  }

  isRunning = true;
  activeRequestId = createRequestId();
  activeAbortController = new AbortController();
  syncActionButtons();
  statusEl.textContent = "Running...";
  summaryEl.textContent = "";
  toolCallsEl.textContent = "";
  toolOutputsEl.textContent = "";

  let wasAborted = false;
  try {
    const attachments = await buildAttachmentPayload();
    const response = await fetch("/api/assist", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ requirement, attachments, requestId: activeRequestId }),
      signal: activeAbortController.signal
    });

    const data = await response.json();
    if (response.status === 401) {
      showAuthPrompt();
      return;
    }

    if (!response.ok) {
      throw new Error(data?.error || "Request failed");
    }

    summaryEl.textContent = data.summary || "(no summary)";
    toolCallsEl.textContent = JSON.stringify(data.toolCalls || [], null, 2);
    toolOutputsEl.textContent = JSON.stringify(data.toolOutputs || [], null, 2);
    if (Array.isArray(data.attachmentPathsUsed) && data.attachmentPathsUsed.length > 0) {
      statusEl.textContent = `Done (attachments: ${data.attachmentPathsUsed.length})`;
    } else {
      statusEl.textContent = "Done";
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      wasAborted = true;
      statusEl.textContent = "Stopped";
      summaryEl.textContent = "Request was stopped by user.";
      toolCallsEl.textContent = "Stopped by user";
      toolOutputsEl.textContent = "Stopped by user";
    } else {
      statusEl.textContent = error.message || "Error";
      summaryEl.textContent = "";
    }
  } finally {
    isRunning = false;
    activeAbortController = null;
    activeRequestId = "";
    syncActionButtons();
    if (!wasAborted) {
      clearAttachments();
    }
  }
}

attachmentsInput?.addEventListener("change", () => {
  setAttachmentsFromFiles(attachmentsInput.files);
});

attachmentListEl?.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const index = Number(target.dataset.index);
  if (!Number.isInteger(index) || index < 0 || index >= selectedAttachments.length) return;

  if (target.classList.contains("attachment-name")) {
    selectedAttachments[index].displayName = target.value;
  }
  if (target.classList.contains("attachment-size")) {
    selectedAttachments[index].displaySizeBytes = target.value;
  }
});

runButton.addEventListener("click", runAgent);

stopButton.addEventListener("click", async () => {
  if (!isRunning || !activeAbortController) {
    return;
  }
  statusEl.textContent = "Stopping...";

  const requestId = activeRequestId;
  if (requestId && csrfToken) {
    try {
      await fetch("/api/assist/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ requestId }),
        keepalive: true
      });
    } catch {
      // Ignore cancellation API failures and still abort local request.
    }
  }

  activeAbortController.abort();
});

signinBtn.addEventListener("click", () => {
  window.location.href = "/auth/signin";
});

signoutBtn.addEventListener("click", () => {
  if (!csrfToken) {
    loadCsrfToken().then(() => {
      if (csrfToken) {
        fetch("/auth/signout", {
          method: "POST",
          headers: { "X-CSRF-Token": csrfToken }
        }).then(() => {
          window.location.reload();
        });
      } else {
        showCsrfBanner("Security token unavailable. Please retry.");
        statusEl.textContent = "Unable to load CSRF token.";
      }
    });
    return;
  }
  fetch("/auth/signout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken }
  }).then(() => {
    window.location.reload();
  });
});

csrfRetry.addEventListener("click", async () => {
  await loadCsrfToken();
  if (!csrfToken) {
    showCsrfBanner("Security token unavailable. Please retry.");
  }
});

checkHealth();
setInterval(checkHealth, 5000);
setAttachmentsFromFiles(attachmentsInput?.files || []);
syncActionButtons();
