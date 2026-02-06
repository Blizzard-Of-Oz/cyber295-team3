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

let isAuthenticated = false;

function showAuthPrompt() {
  isAuthenticated = false;
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

async function checkAuthentication() {
  try {
    const response = await fetch("/api/user");
    if (!response.ok) {
      showAuthPrompt();
      return;
    }
    const data = await response.json();
    showApp(data.user);
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

  statusEl.textContent = "Running...";
  summaryEl.textContent = "";
  toolCallsEl.textContent = "";
  toolOutputsEl.textContent = "";

  try {
    const response = await fetch("/api/assist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
  window.location.href = "/auth/signout";
});

checkHealth();
setInterval(checkHealth, 5000);
