const runButton = document.getElementById("run");
const requirementInput = document.getElementById("requirement");
const statusEl = document.getElementById("status");
const summaryEl = document.getElementById("summary");
const toolCallsEl = document.getElementById("toolCalls");
const toolOutputsEl = document.getElementById("toolOutputs");
const authPrompt = document.getElementById("authPrompt");
const signinBtn = document.getElementById("signinBtn");
const signoutBtn = document.getElementById("signoutBtn");
const userInfo = document.getElementById("userInfo");
const userName = document.getElementById("userName");
const csrfBanner = document.getElementById("csrfBanner");
const csrfMessage = document.getElementById("csrfMessage");
const csrfRetry = document.getElementById("csrfRetry");

let isAuthenticated = false;
let csrfToken = "";

function showAuthPrompt() {
  isAuthenticated = false;
  csrfToken = "";
  csrfBanner.style.display = "none";
  authPrompt.style.display = "block";
  userInfo.style.display = "none";
  runButton.disabled = true;
  statusEl.textContent = "Sign in required";
}

function showApp(user) {
  isAuthenticated = true;
  authPrompt.style.display = "none";
  runButton.disabled = false;
  if (user) {
    userName.textContent = user.name || user.username || "Signed in";
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
    const response = await fetch("/api/user");
    if (!response.ok) {
      showAuthPrompt();
      return;
    }
    const data = await response.json();
    showApp(data.user);
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

  statusEl.textContent = "Running...";
  summaryEl.textContent = "";
  toolCallsEl.textContent = "";
  toolOutputsEl.textContent = "";

  try {
    const response = await fetch("/api/assist", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ requirement })
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
    statusEl.textContent = "Done";
  } catch (error) {
    statusEl.textContent = error.message || "Error";
    summaryEl.textContent = "";
  }
}

runButton.addEventListener("click", runAgent);

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
